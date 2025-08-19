import argparse
import hashlib
import json
import logging
import os
import re
import requests
import sys
import tempfile
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Union, BinaryIO, Any, Tuple
from requests.adapters import HTTPAdapter, Retry
from urllib.parse import urljoin


class LitterBoxError(Exception):
    """Base exception for LitterBox client errors"""
    pass


class LitterBoxAPIError(LitterBoxError):
    """Exception for API-related errors"""
    def __init__(self, message: str, status_code: Optional[int] = None, response: Optional[Dict] = None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response


class LitterBoxClient:
    """Optimized Python client for LitterBox malware analysis sandbox API."""
    
    def __init__(self, 
                 base_url: str = "http://127.0.0.1:1337",
                 timeout: int = 120,
                 max_retries: int = 3,
                 verify_ssl: bool = True,
                 logger: Optional[logging.Logger] = None,
                 proxy_config: Optional[Dict] = None,
                 headers: Optional[Dict] = None):
        """Initialize the LitterBox client."""
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.logger = logger or logging.getLogger(__name__)
        self.proxy_config = proxy_config
        self.headers = headers or {}
        
        # Cache for file lookups to improve performance
        self._file_cache = {}
        
        self.session = self._create_session(max_retries)

    def _create_session(self, max_retries: int) -> requests.Session:
        """Create and configure requests session with retries."""
        session = requests.Session()
        
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        if self.proxy_config:
            session.proxies.update(self.proxy_config)
        if not self.verify_ssl:
            session.verify = False
            # Suppress SSL warnings
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
        session.headers.update(self.headers)
        return session

    def _make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make HTTP request with enhanced error handling."""
        url = urljoin(self.base_url, endpoint)
        self.logger.debug(f"Making {method} request to {url}")
        
        try:
            kwargs.setdefault('timeout', self.timeout)
            response = self.session.request(method, url, **kwargs)
            
            # Log response details for debugging
            self.logger.debug(f"Response status: {response.status_code}")
            
            response.raise_for_status()
            return response
            
        except requests.exceptions.HTTPError as e:
            try:
                error_data = response.json()
            except (ValueError, AttributeError):
                error_data = {'error': response.text}
                
            error_msg = error_data.get('error', f'HTTP {response.status_code} error')
            raise LitterBoxAPIError(
                error_msg,
                status_code=response.status_code,
                response=error_data
            )
        except requests.exceptions.RequestException as e:
            raise LitterBoxError(f"Request failed: {str(e)}")

    def _validate_command_args(self, cmd_args: Optional[List[str]]) -> Dict:
        """Enhanced command line argument validation."""
        if cmd_args is None:
            return {}
            
        if not isinstance(cmd_args, list):
            raise ValueError("Arguments must be provided as a list")
            
        if not all(isinstance(arg, str) for arg in cmd_args):
            raise ValueError("All arguments must be strings")
            
        # Enhanced security validation
        dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '{', '}']
        for arg in cmd_args:
            if any(char in arg for char in dangerous_chars):
                raise ValueError(f"Dangerous character detected in argument: {arg}")
                
        return {'args': cmd_args}

    def _validate_analysis_type(self, analysis_type: str, valid_types: List[str]):
        """Validate analysis type with better error messages."""
        if analysis_type not in valid_types:
            raise ValueError(f"Invalid analysis_type '{analysis_type}'. Must be one of: {', '.join(valid_types)}")

    def _prepare_file_upload(self, file_path: Union[str, Path, BinaryIO], file_name: Optional[str] = None):
        """Prepare file for upload with better error handling."""
        if isinstance(file_path, (str, Path)):
            path = Path(file_path)
            if not path.exists():
                raise LitterBoxError(f"File not found: {path}")
            if not path.is_file():
                raise LitterBoxError(f"Path is not a file: {path}")
                
            return {'file': (file_name or path.name, open(path, 'rb'), 'application/octet-stream')}
        else:
            if not file_name:
                raise ValueError("file_name is required when uploading file-like objects")
            return {'file': (file_name, file_path, 'application/octet-stream')}

    # =============================================================================
    # CORE FILE OPERATIONS
    # =============================================================================

    def upload_file(self, file_path: Union[str, Path, BinaryIO], file_name: Optional[str] = None) -> Dict:
        """Upload a file for analysis."""
        files = self._prepare_file_upload(file_path, file_name)
        try:
            response = self._make_request('POST', '/upload', files=files)
            result = response.json()
            
            # Cache the file info for faster lookups
            if 'file_info' in result:
                file_hash = result['file_info'].get('md5')
                if file_hash:
                    self._file_cache[file_hash] = result['file_info']
                    
            return result
        finally:
            # Ensure file is closed
            if isinstance(file_path, (str, Path)):
                files['file'][1].close()

    def validate_process(self, pid: Union[str, int]) -> Dict:
        """Validate if a process ID exists and is accessible."""
        response = self._make_request('POST', f'/validate/{pid}')
        return response.json()

    def delete_file(self, file_hash: str) -> Dict:
        """Delete a file and its analysis results."""
        response = self._make_request('DELETE', f'/file/{file_hash}')
        
        # Remove from cache
        self._file_cache.pop(file_hash, None)
        
        return response.json()

    # =============================================================================
    # ANALYSIS OPERATIONS
    # =============================================================================

    def analyze_file(self, target: str, analysis_type: str, cmd_args: Optional[List[str]] = None,
                    wait_for_completion: bool = True, verify_file: bool = False) -> Dict:
        """Run analysis on a file or process with enhanced validation."""
        self._validate_analysis_type(analysis_type, ['static', 'dynamic'])
        
        # Enhanced PID validation for dynamic analysis
        if analysis_type == 'dynamic' and target.isdigit():
            try:
                self.validate_process(target)
            except LitterBoxAPIError as e:
                if e.status_code == 404:
                    raise LitterBoxError(f"Process with PID {target} not found or not accessible")
                raise
        elif analysis_type == 'static' and target.isdigit():
            raise ValueError("Cannot perform static analysis on PID")
        
        # For non-PID targets, verify the file exists if requested
        if not target.isdigit() and verify_file:
            try:
                self.get_file_info(target)
            except LitterBoxAPIError as e:
                if e.status_code == 404:
                    raise LitterBoxError(f"File {target} not found or not yet available")

        params = {'wait': '1' if wait_for_completion else '0'}
        data = self._validate_command_args(cmd_args)
        
        response = self._make_request('POST', f'/analyze/{analysis_type}/{target}', 
                                     params=params, json=data)
        
        result = response.json()
        
        # Enhanced result handling
        if result.get('status') == 'early_termination':
            self.logger.warning(f"Analysis terminated early: {result.get('error')}")
        elif result.get('status') == 'error':
            self.logger.error(f"Analysis failed: {result.get('error')}")
            
        return result

    def analyze_holygrail(self, file_hash: str, wait_for_completion: bool = True) -> Dict:
        """Run HolyGrail BYOVD analysis on a kernel driver."""
        params = {'hash': file_hash}
        if wait_for_completion:
            params['wait'] = '1'
            
        response = self._make_request('GET', '/holygrail', params=params)
        return response.json()

    def upload_and_analyze_driver(self, file_path: Union[str, Path, BinaryIO], 
                                 file_name: Optional[str] = None,
                                 run_holygrail: bool = True) -> Dict:
        """Upload a kernel driver and optionally run HolyGrail analysis."""
        # Upload the driver
        upload_result = self.upload_file(file_path, file_name)
        file_hash = upload_result['file_info']['md5']
        
        results = {
            'upload': upload_result,
            'holygrail': None
        }
        
        if run_holygrail:
            try:
                holygrail_result = self.analyze_holygrail(file_hash)
                results['holygrail'] = holygrail_result
            except Exception as e:
                self.logger.error(f"HolyGrail analysis failed: {e}")
                results['holygrail'] = {'error': str(e)}
                
        return results

    # =============================================================================
    # DOPPELGANGER OPERATIONS
    # =============================================================================

    def _validate_doppelganger_params(self, analysis_type: str, operation: str, 
                                     file_hash: Optional[str], folder_path: Optional[str]):
        """Enhanced doppelganger parameter validation."""
        if analysis_type not in ['blender', 'fuzzy']:
            raise ValueError("analysis_type must be either 'blender' or 'fuzzy'")

        if operation == 'scan' and analysis_type != 'blender':
            raise ValueError("scan operation is only available for blender analysis")
        
        if operation == 'create_db' and not folder_path:
            raise ValueError("folder_path is required for create_db operation")
        
        if operation == 'analyze' and not file_hash:
            raise ValueError("file_hash is required for analyze operation")

    def doppelganger_operation(self, analysis_type: str, operation: str,
                              file_hash: Optional[str] = None, folder_path: Optional[str] = None,
                              extensions: Optional[List[str]] = None, threshold: int = 1) -> Dict:
        """Unified doppelganger operations with enhanced error handling."""
        self._validate_doppelganger_params(analysis_type, operation, file_hash, folder_path)

        # For GET requests (comparisons)
        if file_hash and operation in ['compare', 'analyze']:
            params = {'type': analysis_type, 'hash': file_hash}
            if operation == 'analyze' and analysis_type == 'fuzzy':
                params['threshold'] = threshold
            response = self._make_request('GET', '/doppelganger', params=params)
            return response.json()

        # For POST requests
        data = {'type': analysis_type, 'operation': operation}

        if operation == 'create_db':
            data['folder_path'] = folder_path
            if extensions:
                data['extensions'] = extensions
        elif operation == 'analyze':
            data['hash'] = file_hash
            data['threshold'] = threshold

        response = self._make_request('POST', '/doppelganger', json=data)
        return response.json()

    def run_blender_scan(self) -> Dict:
        """Run a system-wide Blender scan."""
        return self.doppelganger_operation('blender', 'scan')

    def compare_with_blender(self, file_hash: str) -> Dict:
        """Compare a file with current system state using Blender."""
        return self.doppelganger_operation('blender', 'compare', file_hash=file_hash)

    def create_fuzzy_database(self, folder_path: str, extensions: Optional[List[str]] = None) -> Dict:
        """Create fuzzy hash database from folder."""
        return self.doppelganger_operation('fuzzy', 'create_db', 
                                         folder_path=folder_path, extensions=extensions)

    def analyze_with_fuzzy(self, file_hash: str, threshold: int = 1) -> Dict:
        """Analyze file using fuzzy hash comparison."""
        return self.doppelganger_operation('fuzzy', 'analyze', 
                                         file_hash=file_hash, threshold=threshold)

    # =============================================================================
    # RESULT RETRIEVAL
    # =============================================================================

    def get_results(self, target: str, analysis_type: str) -> Dict:
        """Get results for a specific analysis type."""
        self._validate_analysis_type(analysis_type, ['static', 'dynamic', 'info'])
        response = self._make_request('GET', f'/results/{target}/{analysis_type}')
        return response.json()

    def get_file_info(self, target: str) -> Dict:
        """Get file information via API endpoint."""
        response = self._make_request('GET', f'/api/results/{target}/info')
        return response.json()

    def get_static_results(self, target: str) -> Dict:
        """Get static analysis results via API endpoint."""
        response = self._make_request('GET', f'/api/results/{target}/static')
        return response.json()

    def get_dynamic_results(self, target: str) -> Dict:
        """Get dynamic analysis results via API endpoint."""
        response = self._make_request('GET', f'/api/results/{target}/dynamic')
        return response.json()

    def get_holygrail_results(self, target: str) -> Dict:
        """Get HolyGrail/BYOVD analysis results via API endpoint."""
        response = self._make_request('GET', f'/api/results/{target}/holygrail')
        return response.json()

    def get_files_summary(self) -> Dict:
        """Get summary of all analyzed files and processes."""
        response = self._make_request('GET', '/files')
        return response.json()

    def get_comprehensive_results(self, target: str) -> Dict:
        """Get all available results for a target in one call."""
        results = {'target': target}
        
        # Try to get each type of result
        for result_type, method in [
            ('file_info', self.get_file_info),
            ('static_results', self.get_static_results),
            ('dynamic_results', self.get_dynamic_results),
            ('holygrail_results', self.get_holygrail_results)
        ]:
            try:
                results[result_type] = method(target)
            except LitterBoxAPIError as e:
                if e.status_code == 404:
                    results[result_type] = None
                else:
                    results[result_type] = {'error': str(e)}
            except Exception as e:
                results[result_type] = {'error': str(e)}
                
        return results

    # =============================================================================
    # REPORT OPERATIONS
    # =============================================================================

    def get_report(self, target: str, download: bool = False) -> Union[str, bytes]:
        """Get analysis report for a file or process."""
        params = {'download': 'true' if download else 'false'}
        response = self._make_request('GET', f'/api/report/{target}', params=params)
        return response.content if download else response.text

    def download_report(self, target: str, output_path: Optional[str] = None) -> str:
        """Download analysis report and save it to disk."""
        response = self._make_request('GET', f'/api/report/{target}', 
                                     params={'download': 'true'}, stream=True)
        
        filename = self._extract_filename_from_response(response, target)
        
        # Determine final output path
        if output_path:
            if os.path.isdir(output_path):
                save_path = os.path.join(output_path, filename)
            else:
                save_path = output_path
        else:
            save_path = filename
        
        try:
            with open(save_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:  # filter out keep-alive chunks
                        f.write(chunk)
            self.logger.info(f"Report saved to {save_path}")
            return save_path
        except Exception as e:
            raise LitterBoxError(f"Failed to save report: {str(e)}")

    def _extract_filename_from_response(self, response: requests.Response, target: str) -> str:
        """Extract filename from Content-Disposition header or create default."""
        content_disposition = response.headers.get('Content-Disposition', '')
        
        if 'filename=' in content_disposition:
            match = re.search(r'filename="([^"]+)"', content_disposition)
            if match:
                return match.group(1)
        
        # Default filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return f"LitterBox_Report_{target[:8]}_{timestamp}.html"

    def open_report_in_browser(self, target: str) -> bool:
        """Generate a report and open it in the default web browser."""
        try:
            report_content = self.get_report(target, download=False)
            
            # Create temporary file
            fd, path = tempfile.mkstemp(suffix='.html', prefix='litterbox_report_')
            try:
                with os.fdopen(fd, 'w', encoding='utf-8') as tmp:
                    tmp.write(report_content)
                
                webbrowser.open('file://' + path)
                self.logger.info(f"Report opened in browser from {path}")
                return True
            except Exception as e:
                self.logger.error(f"Failed to open report in browser: {str(e)}")
                return False
        except Exception as e:
            self.logger.error(f"Failed to generate report: {str(e)}")
            return False

    # =============================================================================
    # SYSTEM OPERATIONS
    # =============================================================================

    def cleanup(self, include_uploads: bool = True, include_results: bool = True, 
               include_analysis: bool = True) -> Dict:
        """Clean up analysis artifacts and uploaded files."""
        data = {
            'cleanup_uploads': include_uploads,
            'cleanup_results': include_results,
            'cleanup_analysis': include_analysis
        }
        response = self._make_request('POST', '/cleanup', json=data)
        
        # Clear local cache
        self._file_cache.clear()
        
        return response.json()

    def check_health(self) -> Dict:
        """Check the health status of the LitterBox service."""
        # Use direct request without retries for health check
        url = urljoin(self.base_url, '/health')
        
        try:
            response = requests.get(url, timeout=self.timeout, verify=self.verify_ssl)
            if response.status_code in [200, 503]:  # Both OK and degraded are valid
                return response.json()
            else:
                response.raise_for_status()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Health check failed: {e}")
            return {
                "status": "error",
                "message": "Unable to connect to service", 
                "details": str(e)
            }

    def get_system_status(self) -> Dict:
        """Get comprehensive system status including health and file summary."""
        try:
            health = self.check_health()
            files_summary = self.get_files_summary()
            
            return {
                'health': health,
                'files_summary': files_summary,
                'status': 'healthy' if health.get('status') == 'ok' else 'degraded'
            }
        except Exception as e:
            return {
                'health': {'status': 'error', 'error': str(e)},
                'files_summary': None,
                'status': 'error'
            }

    # =============================================================================
    # CONTEXT MANAGERS AND CLEANUP
    # =============================================================================

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        """Close the session and cleanup resources."""
        if hasattr(self, 'session'):
            self.session.close()

    def __del__(self):
        """Ensure session is closed on garbage collection."""
        self.close()


# =============================================================================
# ENHANCED COMMAND LINE INTERFACE
# =============================================================================

def create_enhanced_parser():
    """Create enhanced argument parser with all available operations."""
    parser = argparse.ArgumentParser(
        description="Enhanced LitterBox Malware Analysis Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Upload and analyze a file
  %(prog)s upload malware.exe --analysis static dynamic

  # Upload and analyze a kernel driver
  %(prog)s upload-driver rootkit.sys --holygrail

  # Analyze a running process
  %(prog)s analyze-pid 1234 --wait

  # Get comprehensive results
  %(prog)s results abc123def --comprehensive

  # Run Doppelganger operations
  %(prog)s doppelganger-scan --type blender
  %(prog)s doppelganger-analyze abc123def --type fuzzy --threshold 85

  # System operations
  %(prog)s status --full
  %(prog)s cleanup --all

  # Report operations  
  %(prog)s report abc123def --browser
  %(prog)s report abc123def --download --output ./reports/
"""
    )
    
    # Global options
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--url', default='http://127.0.0.1:1337', help='LitterBox server URL')
    parser.add_argument('--timeout', type=int, default=120, help='Request timeout in seconds')
    parser.add_argument('--no-verify-ssl', action='store_true', help='Disable SSL verification')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://proxy:8080)')
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Upload command
    upload_parser = subparsers.add_parser('upload', help='Upload file for analysis')
    upload_parser.add_argument('file', help='File to upload')
    upload_parser.add_argument('--name', help='Custom name for the file')
    upload_parser.add_argument('--analysis', nargs='+', choices=['static', 'dynamic'],
                             help='Run analysis after upload')
    upload_parser.add_argument('--args', nargs='+', help='Command line arguments for dynamic analysis')
    
    # Upload driver command
    driver_parser = subparsers.add_parser('upload-driver', help='Upload kernel driver')
    driver_parser.add_argument('file', help='Driver file to upload')
    driver_parser.add_argument('--name', help='Custom name for the driver')
    driver_parser.add_argument('--holygrail', action='store_true', help='Run HolyGrail analysis')
    
    # Analyze PID command
    analyze_pid_parser = subparsers.add_parser('analyze-pid', help='Analyze running process')
    analyze_pid_parser.add_argument('pid', type=int, help='Process ID to analyze')
    analyze_pid_parser.add_argument('--wait', action='store_true', help='Wait for analysis completion')
    analyze_pid_parser.add_argument('--args', nargs='+', help='Command line arguments')
    
    # Results command
    results_parser = subparsers.add_parser('results', help='Get analysis results')
    results_parser.add_argument('target', help='File hash or PID')
    results_parser.add_argument('--type', choices=['static', 'dynamic', 'info', 'holygrail'],
                              help='Type of results to retrieve')
    results_parser.add_argument('--comprehensive', action='store_true', 
                              help='Get all available results')
    
    # Doppelganger scan command
    doppelganger_scan_parser = subparsers.add_parser('doppelganger-scan', help='Run doppelganger scan')
    doppelganger_scan_parser.add_argument('--type', choices=['blender'], default='blender',
                                        help='Type of scan to perform')
    
    # Doppelganger analyze command  
    doppelganger_analyze_parser = subparsers.add_parser('doppelganger-analyze', help='Doppelganger analysis')
    doppelganger_analyze_parser.add_argument('hash', help='File hash to analyze')
    doppelganger_analyze_parser.add_argument('--type', choices=['blender', 'fuzzy'], required=True,
                                           help='Type of analysis')
    doppelganger_analyze_parser.add_argument('--threshold', type=int, default=1,
                                           help='Similarity threshold for fuzzy analysis')
    
    # Doppelganger database command
    db_parser = subparsers.add_parser('doppelganger-db', help='Create doppelganger database')
    db_parser.add_argument('--folder', required=True, help='Folder path to process')
    db_parser.add_argument('--extensions', nargs='+', help='File extensions to include')
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate analysis report')
    report_parser.add_argument('target', help='File hash or process ID')
    report_parser.add_argument('--download', action='store_true', help='Download the report')
    report_parser.add_argument('--output', help='Output path for downloaded report')
    report_parser.add_argument('--browser', action='store_true', help='Open report in browser')
    
    # System commands
    subparsers.add_parser('status', help='Get system status').add_argument(
        '--full', action='store_true', help='Get comprehensive status')
    subparsers.add_parser('health', help='Check service health')
    subparsers.add_parser('files', help='Get summary of all analyzed files')
    
    # Cleanup command
    cleanup_parser = subparsers.add_parser('cleanup', help='Clean up analysis artifacts')
    cleanup_parser.add_argument('--all', action='store_true', help='Clean all artifacts')
    cleanup_parser.add_argument('--uploads', action='store_true', help='Clean upload directory')
    cleanup_parser.add_argument('--results', action='store_true', help='Clean results directory')
    cleanup_parser.add_argument('--analysis', action='store_true', help='Clean analysis artifacts')
    
    # Delete command
    delete_parser = subparsers.add_parser('delete', help='Delete file and its results')
    delete_parser.add_argument('hash', help='File hash to delete')
    
    return parser


def setup_enhanced_client(args) -> LitterBoxClient:
    """Create client instance from command line arguments."""
    client_kwargs = {
        'base_url': args.url,
        'timeout': args.timeout,
        'verify_ssl': not args.no_verify_ssl,
        'logger': logging.getLogger('litterbox'),
    }
    
    if args.proxy:
        client_kwargs['proxy_config'] = {'http': args.proxy, 'https': args.proxy}
    
    return LitterBoxClient(**client_kwargs)


def handle_enhanced_analysis_result(result: Dict, analysis_type: str):
    """Enhanced result handling with better formatting."""
    status = result.get('status', 'unknown')
    
    if status == 'early_termination':
        print("Process terminated early:")
        print(f"   Error: {result.get('error')}")
        details = result.get('details', {})
        if details:
            print("   Details:")
            for key, value in details.items():
                print(f"     {key}: {value}")
    elif status == 'error':
        print(f"Analysis failed: {result.get('error')}")
        if 'details' in result:
            print(f"   Details: {result['details']}")
    elif status == 'success':
        print("Analysis completed successfully")
        if 'results' in result:
            print(json.dumps(result['results'], indent=2))
        else:
            print(json.dumps(result, indent=2))
    else:
        print(json.dumps(result, indent=2))


def main():
    """Enhanced main function with comprehensive command handling."""
    parser = create_enhanced_parser()
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level, 
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        with setup_enhanced_client(args) as client:
            
            if args.command == 'upload':
                result = client.upload_file(args.file, file_name=args.name)
                file_hash = result['file_info']['md5']
                print(f"File uploaded successfully. Hash: {file_hash}")
                
                if args.analysis:
                    for analysis_type in args.analysis:
                        print(f"Running {analysis_type} analysis...")
                        analysis_args = args.args if analysis_type == 'dynamic' else None
                        result = client.analyze_file(file_hash, analysis_type, 
                                                   cmd_args=analysis_args, wait_for_completion=True)
                        handle_enhanced_analysis_result(result, analysis_type)
            
            elif args.command == 'upload-driver':
                result = client.upload_and_analyze_driver(args.file, file_name=args.name, 
                                                        run_holygrail=args.holygrail)
                file_hash = result['upload']['file_info']['md5']
                print(f"Driver uploaded successfully. Hash: {file_hash}")
                
                if args.holygrail and result['holygrail']:
                    if 'error' in result['holygrail']:
                        print(f"HolyGrail analysis failed: {result['holygrail']['error']}")
                    else:
                        print("HolyGrail analysis completed")
                        print(json.dumps(result['holygrail'], indent=2))
            
            elif args.command == 'analyze-pid':
                print(f"Analyzing process {args.pid}...")
                result = client.analyze_file(str(args.pid), 'dynamic', 
                                           cmd_args=args.args, wait_for_completion=args.wait)
                handle_enhanced_analysis_result(result, 'dynamic')
            
            elif args.command == 'results':
                if args.comprehensive:
                    result = client.get_comprehensive_results(args.target)
                    print("Comprehensive Results:")
                    print(json.dumps(result, indent=2))
                elif args.type:
                    if args.type == 'holygrail':
                        result = client.get_holygrail_results(args.target)
                    else:
                        result = client.get_results(args.target, args.type)
                    print(json.dumps(result, indent=2))
                else:
                    print("Please specify --type or use --comprehensive")
                    return
            
            elif args.command == 'doppelganger-scan':
                print(f"Running doppelganger scan with type: {args.type}")
                result = client.run_blender_scan()
                print(json.dumps(result, indent=2))
                
            elif args.command == 'doppelganger-analyze':
                print(f"Running doppelganger analysis with type: {args.type}")
                if args.type == 'blender':
                    result = client.compare_with_blender(args.hash)
                else:
                    result = client.analyze_with_fuzzy(args.hash, args.threshold)
                print(json.dumps(result, indent=2))
                
            elif args.command == 'doppelganger-db':
                print("Creating doppelganger fuzzy database...")
                result = client.create_fuzzy_database(args.folder, args.extensions)
                print(json.dumps(result, indent=2))

            elif args.command == 'report':
                if args.browser:
                    print(f"Opening report for {args.target} in browser...")
                    success = client.open_report_in_browser(args.target)
                    if not success:
                        print("Failed to open report in browser.")
                        sys.exit(1)
                elif args.download:
                    print(f"Downloading report for {args.target}...")
                    output_path = client.download_report(args.target, args.output)
                    print(f"Report saved to: {output_path}")
                else:
                    report = client.get_report(args.target)
                    print(report)
            
            elif args.command == 'status':
                if args.full:
                    result = client.get_system_status()
                    print("System Status:")
                else:
                    result = client.check_health()
                    print("Health Check:")
                print(json.dumps(result, indent=2))
            
            elif args.command == 'health':
                result = client.check_health()
                status = result.get('status', 'unknown')
                if status == 'ok':
                    print("Service is healthy")
                else:
                    print(f"Service status: {status}")
                print(json.dumps(result, indent=2))
            
            elif args.command == 'files':
                result = client.get_files_summary()
                print("Files Summary:")
                print(json.dumps(result, indent=2))

            elif args.command == 'cleanup':
                if args.all:
                    args.uploads = args.results = args.analysis = True
                result = client.cleanup(include_uploads=args.uploads, 
                                      include_results=args.results,
                                      include_analysis=args.analysis)
                print("Cleanup Results:")
                print(json.dumps(result, indent=2))
            
            elif args.command == 'delete':
                result = client.delete_file(args.hash)
                print("Deletion Results:")
                print(json.dumps(result, indent=2))
            
            else:
                parser.print_help()
    
    except LitterBoxAPIError as e:
        logging.error(f"API Error (Status {e.status_code}): {str(e)}")
        if args.debug and e.response:
            logging.debug(f"Response data: {e.response}")
        sys.exit(1)
    except LitterBoxError as e:
        logging.error(f"Client Error: {str(e)}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(130)
    except Exception as e:
        logging.error(f"Unexpected Error: {str(e)}")
        if args.debug:
            logging.exception("Detailed error information:")
        sys.exit(1)


if __name__ == "__main__":
    main()