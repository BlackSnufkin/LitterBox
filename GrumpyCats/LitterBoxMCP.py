import logging
import json
from typing import Optional, Dict, List, Any
from mcp.server.fastmcp import FastMCP

# Import the optimized LitterBox client
from optimized_litterbox_client import LitterBoxClient, LitterBoxError, LitterBoxAPIError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize MCP server with enhanced focus on OPSEC analysis
mcp = FastMCP(
    name="LitterBoxOpsecMCP",
    instructions=(
        "Elite payload OPSEC analysis framework specializing in detection evasion.\n"
        "Analyze YARA signatures, behavioral patterns, EDR triggers, and attribution risks.\n"
        "Provide actionable tradecraft improvements for bypassing modern security controls.\n"
        "Focus on signature evasion, behavioral stealth, attribution avoidance, and deployment readiness.\n"
        "Emphasize practical OPSEC improvements with specific remediation strategies.\n"
        "Support both payload analysis and kernel driver BYOVD assessment."
    ),
)

class LitterBoxMCPClient:
    """Enhanced MCP client wrapper with connection management"""
    
    def __init__(self, base_url: str = "http://127.0.0.1:1337", timeout: int = 120):
        self.base_url = base_url
        self.timeout = timeout
        self._client = None
        
    def get_client(self) -> LitterBoxClient:
        """Get or create client instance with connection pooling"""
        if self._client is None:
            self._client = LitterBoxClient(
                base_url=self.base_url,
                timeout=self.timeout,
                logger=logger
            )
        return self._client
    
    def close(self):
        """Close client connection"""
        if self._client:
            self._client.close()
            self._client = None

# Initialize enhanced client wrapper
mcp_client = LitterBoxMCPClient()

def handle_api_operation(operation_name: str, callable_fn, *args, **kwargs) -> Dict[str, Any]:
    """Enhanced error handling with operation context and detailed logging"""
    try:
        logger.debug(f"Executing operation: {operation_name}")
        result = callable_fn(*args, **kwargs)
        logger.debug(f"Operation {operation_name} completed successfully")
        
        return {
            "status": "success",
            "operation": operation_name,
            "data": result,
            "timestamp": None  # Could add timestamp if needed
        }
        
    except LitterBoxAPIError as e:
        error_msg = f"API error in {operation_name}: {str(e)}"
        logger.error(error_msg)
        return {
            "status": "api_error",
            "operation": operation_name,
            "message": str(e),
            "http_code": e.status_code,
            "response_data": e.response
        }
        
    except LitterBoxError as e:
        error_msg = f"Client error in {operation_name}: {str(e)}"
        logger.error(error_msg)
        return {
            "status": "client_error",
            "operation": operation_name,
            "message": str(e)
        }
        
    except Exception as e:
        error_msg = f"Unexpected error in {operation_name}: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return {
            "status": "error",
            "operation": operation_name,
            "message": str(e),
            "type": type(e).__name__
        }

# =============================================================================
# CORE PAYLOAD ANALYSIS TOOLS
# =============================================================================

@mcp.tool(name="upload_payload", description="Upload payload for comprehensive OPSEC analysis")
def upload_payload(path: str, name: Optional[str] = None) -> Dict[str, Any]:
    """Upload payload and prepare for analysis"""
    client = mcp_client.get_client()
    return handle_api_operation("upload_payload", client.upload_file, path, file_name=name)

@mcp.tool(name="upload_kernel_driver", description="Upload kernel driver for BYOVD analysis")
def upload_kernel_driver(path: str, name: Optional[str] = None, run_holygrail: bool = True) -> Dict[str, Any]:
    """Upload kernel driver and optionally run HolyGrail BYOVD analysis"""
    client = mcp_client.get_client()
    return handle_api_operation("upload_kernel_driver", 
                               client.upload_and_analyze_driver, path, 
                               file_name=name, run_holygrail=run_holygrail)

@mcp.tool(name="analyze_static", description="Run comprehensive static analysis - YARA signatures, PE structure, imports")
def analyze_static(file_hash: str, wait_completion: bool = True) -> Dict[str, Any]:
    """Execute static analysis to identify signature detections and file characteristics"""
    client = mcp_client.get_client()
    return handle_api_operation("analyze_static", 
                               client.analyze_file, file_hash, 'static', 
                               wait_for_completion=wait_completion)

@mcp.tool(name="analyze_dynamic", description="Run dynamic analysis - behavioral detection, runtime artifacts, process analysis")
def analyze_dynamic(target: str, cmd_args: Optional[List[str]] = None, wait_completion: bool = True) -> Dict[str, Any]:
    """Execute dynamic analysis to test behavioral evasion and runtime stealth"""
    client = mcp_client.get_client()
    return handle_api_operation("analyze_dynamic", 
                               client.analyze_file, target, 'dynamic', 
                               cmd_args=cmd_args, wait_for_completion=wait_completion)

@mcp.tool(name="analyze_holygrail", description="Run HolyGrail BYOVD analysis on kernel drivers")
def analyze_holygrail(file_hash: str, wait_completion: bool = True) -> Dict[str, Any]:
    """Execute HolyGrail analysis for kernel driver vulnerability assessment"""
    client = mcp_client.get_client()
    return handle_api_operation("analyze_holygrail", 
                               client.analyze_holygrail, file_hash, 
                               wait_for_completion=wait_completion)

# =============================================================================
# RESULT RETRIEVAL TOOLS
# =============================================================================

@mcp.tool(name="get_comprehensive_results", description="Get all available analysis results for target")
def get_comprehensive_results(target: str) -> Dict[str, Any]:
    """Retrieve all analysis results (static, dynamic, file info, HolyGrail)"""
    client = mcp_client.get_client()
    return handle_api_operation("get_comprehensive_results", 
                               client.get_comprehensive_results, target)

@mcp.tool(name="get_file_info", description="Get file metadata, entropy analysis, and PE structure")
def get_file_info(file_hash: str) -> Dict[str, Any]:
    """Retrieve detailed file information and characteristics"""
    client = mcp_client.get_client()
    return handle_api_operation("get_file_info", client.get_file_info, file_hash)

@mcp.tool(name="get_static_results", description="Get static analysis results - YARA matches, signatures, imports")
def get_static_results(file_hash: str) -> Dict[str, Any]:
    """Retrieve comprehensive static analysis results"""
    client = mcp_client.get_client()
    return handle_api_operation("get_static_results", client.get_static_results, file_hash)

@mcp.tool(name="get_dynamic_results", description="Get dynamic analysis results - behavioral detections, runtime artifacts")
def get_dynamic_results(target: str) -> Dict[str, Any]:
    """Retrieve comprehensive dynamic analysis results"""
    client = mcp_client.get_client()
    return handle_api_operation("get_dynamic_results", client.get_dynamic_results, target)

@mcp.tool(name="get_holygrail_results", description="Get HolyGrail BYOVD analysis results")
def get_holygrail_results(target: str) -> Dict[str, Any]:
    """Retrieve HolyGrail/BYOVD analysis results for kernel drivers"""
    client = mcp_client.get_client()
    return handle_api_operation("get_holygrail_results", client.get_holygrail_results, target)

# =============================================================================
# DOPPELGANGER COMPARISON TOOLS
# =============================================================================

@mcp.tool(name="run_blender_scan", description="Run system-wide Blender scan for baseline comparison")
def run_blender_scan() -> Dict[str, Any]:
    """Execute system-wide Blender scan to establish clean baseline"""
    client = mcp_client.get_client()
    return handle_api_operation("run_blender_scan", client.run_blender_scan)

@mcp.tool(name="compare_with_blender", description="Compare payload against system baseline with Blender")
def compare_with_blender(file_hash: str) -> Dict[str, Any]:
    """Compare payload execution against clean system baseline"""
    client = mcp_client.get_client()
    return handle_api_operation("compare_with_blender", client.compare_with_blender, file_hash)

@mcp.tool(name="create_fuzzy_database", description="Create fuzzy hash database for similarity analysis")
def create_fuzzy_database(folder_path: str, extensions: Optional[List[str]] = None) -> Dict[str, Any]:
    """Build fuzzy hash database from known payload collection"""
    client = mcp_client.get_client()
    return handle_api_operation("create_fuzzy_database", 
                               client.create_fuzzy_database, folder_path, extensions)

@mcp.tool(name="analyze_fuzzy_similarity", description="Analyze payload similarity using fuzzy hashing")
def analyze_fuzzy_similarity(file_hash: str, threshold: int = 85) -> Dict[str, Any]:
    """Compare payload against fuzzy hash database for attribution analysis"""
    client = mcp_client.get_client()
    return handle_api_operation("analyze_fuzzy_similarity", 
                               client.analyze_with_fuzzy, file_hash, threshold)

# =============================================================================
# PROCESS ANALYSIS TOOLS
# =============================================================================

@mcp.tool(name="validate_pid", description="Validate process ID before dynamic analysis")
def validate_pid(pid: int) -> Dict[str, Any]:
    """Verify process exists and is accessible for analysis"""
    client = mcp_client.get_client()
    return handle_api_operation("validate_pid", client.validate_process, pid)

@mcp.tool(name="analyze_running_process", description="Analyze currently running process for OPSEC assessment")
def analyze_running_process(pid: int, cmd_args: Optional[List[str]] = None) -> Dict[str, Any]:
    """Analyze live process for behavioral patterns and detection indicators"""
    client = mcp_client.get_client()
    return handle_api_operation("analyze_running_process", 
                               client.analyze_file, str(pid), 'dynamic', cmd_args=cmd_args)

# =============================================================================
# REPORT AND DOCUMENTATION TOOLS
# =============================================================================

@mcp.tool(name="generate_opsec_report", description="Generate comprehensive OPSEC analysis report")
def generate_opsec_report(target: str, download: bool = False) -> Dict[str, Any]:
    """Generate detailed OPSEC analysis report with findings and recommendations"""
    client = mcp_client.get_client()
    return handle_api_operation("generate_opsec_report", 
                               client.get_report, target, download=download)

@mcp.tool(name="download_analysis_report", description="Download analysis report to specified location")
def download_analysis_report(target: str, output_path: Optional[str] = None) -> Dict[str, Any]:
    """Download comprehensive analysis report for offline review"""
    client = mcp_client.get_client()
    return handle_api_operation("download_analysis_report", 
                               client.download_report, target, output_path)

# =============================================================================
# SYSTEM MANAGEMENT TOOLS
# =============================================================================

@mcp.tool(name="list_analyzed_payloads", description="List all analyzed payloads with OPSEC assessment summary")
def list_analyzed_payloads() -> Dict[str, Any]:
    """Retrieve summary of all tested payloads with risk assessments"""
    client = mcp_client.get_client()
    return handle_api_operation("list_analyzed_payloads", client.get_files_summary)

@mcp.tool(name="get_system_status", description="Get comprehensive system health and analysis status")
def get_system_status() -> Dict[str, Any]:
    """Check sandbox health, tool status, and analysis queue"""
    client = mcp_client.get_client()
    return handle_api_operation("get_system_status", client.get_system_status)

@mcp.tool(name="cleanup_analysis_artifacts", description="Clean up all testing artifacts and temporary files")
def cleanup_analysis_artifacts(include_uploads: bool = True, 
                             include_results: bool = True, 
                             include_analysis: bool = True) -> Dict[str, Any]:
    """Remove all testing artifacts from sandbox environment"""
    client = mcp_client.get_client()
    return handle_api_operation("cleanup_analysis_artifacts", 
                               client.cleanup, include_uploads, include_results, include_analysis)

@mcp.tool(name="delete_payload", description="Delete specific payload and all associated analysis results")
def delete_payload(file_hash: str) -> Dict[str, Any]:
    """Permanently remove payload and all analysis artifacts"""
    client = mcp_client.get_client()
    return handle_api_operation("delete_payload", client.delete_file, file_hash)

@mcp.tool(name="check_sandbox_health", description="Verify sandbox tools and analysis engines are operational")
def check_sandbox_health() -> Dict[str, Any]:
    """Comprehensive health check of all analysis components"""
    client = mcp_client.get_client()
    return handle_api_operation("check_sandbox_health", client.check_health)

# =============================================================================
# ENHANCED OPSEC-FOCUSED PROMPTS
# =============================================================================

@mcp.prompt()
def analyze_detection_patterns(file_hash: str = "") -> str:
    """Comprehensive detection pattern analysis with specific evasion recommendations"""
    return f"""Perform comprehensive detection pattern analysis for {f'payload {file_hash}' if file_hash else 'the target payload'}:

## YARA Signature Analysis
- Rule matches and triggered detection logic
- String patterns causing signature hits
- Behavioral rules triggered during execution
- Custom rule development for testing

## Static Analysis Detection Points
- PE structure anomalies flagged
- Import table suspicious patterns
- File entropy and packing indicators
- Metadata and compilation artifacts

## Dynamic Behavioral Detection
- Process manipulation techniques detected
- Memory artifacts flagged by Moneta/PE-Sieve
- API call patterns triggering alerts
- Network communication behaviors
- File system activity patterns

## EDR/AV Evasion Strategy
- Signature modification requirements
- Behavioral pattern adjustments needed
- Obfuscation and packing recommendations
- Alternative implementation approaches
- Anti-analysis technique improvements

## Attribution Risk Assessment
- Similarity to known offensive tools
- Framework-specific behavioral patterns
- Unique implementation fingerprints
- Metadata revealing tool origin

Provide specific, actionable remediation steps for each detection vector."""

@mcp.prompt()
def assess_evasion_effectiveness(file_hash: str = "") -> str:
    """Detailed evasion effectiveness assessment with improvement roadmap"""
    return f"""Evaluate comprehensive evasion effectiveness for {f'payload {file_hash}' if file_hash else 'the target payload'}:

## Signature Evasion Assessment
- **YARA Rule Bypass**: Success rate and failed patterns
- **AV Signature Avoidance**: Engine-specific detection rates
- **String Obfuscation**: Effectiveness of current techniques
- **Import Masking**: API hiding and resolution evasion

## Behavioral Evasion Assessment
- **EDR Behavioral Rules**: Triggered behaviors and bypass status
- **Process Manipulation**: Stealth level of injection techniques
- **Memory Artifacts**: Footprint visibility and cleanup effectiveness
- **API Hooking Detection**: Bypass success for monitoring evasion

## Runtime Stealth Evaluation
- **Execution Flow**: Natural vs suspicious behavior patterns
- **Resource Usage**: CPU, memory, and I/O pattern analysis
- **Timing Analysis**: Execution speed and delay patterns
- **Communication Stealth**: Network behavior obfuscation

## Improvement Priority Matrix
1. **CRITICAL**: Immediate signature bypass requirements
2. **HIGH**: Behavioral detection evasion improvements
3. **MEDIUM**: Attribution masking and fingerprint reduction
4. **LOW**: General stealth and efficiency optimizations

## Specific Enhancement Recommendations
- Code modification requirements for signature evasion
- Behavioral adjustment strategies for EDR bypass
- Obfuscation technique upgrades needed
- Alternative implementation methodologies

Provide concrete implementation steps with expected effectiveness improvements."""

@mcp.prompt()
def analyze_attribution_risks(file_hash: str = "") -> str:
    """In-depth attribution risk analysis with masking strategies"""
    return f"""Conduct thorough attribution risk analysis for {f'payload {file_hash}' if file_hash else 'the target payload'}:

## Framework Attribution Indicators
- **Metasploit/Cobalt Strike**: Known behavioral patterns and signatures
- **Custom Framework**: Unique implementation characteristics
- **Commercial Tools**: Licensed software patterns and artifacts
- **Open Source**: GitHub/public repository code similarities

## Code Attribution Vectors
- **Compilation Artifacts**: Compiler version, build environment indicators
- **Code Style**: Programming patterns and implementation choices
- **Library Usage**: Specific dependency patterns and versions
- **Error Handling**: Unique error message patterns and responses

## Behavioral Attribution Patterns
- **Technique Selection**: Preferred attack methods and sequences
- **Configuration**: Default settings and parameter choices
- **Communication**: Protocol preferences and data formats
- **Persistence**: Installation and survival method preferences

## Infrastructure Attribution Risks
- **C2 Communication**: Protocol patterns and encryption methods
- **Domain Generation**: Algorithm patterns and naming conventions
- **Certificate Usage**: SSL/TLS certificate patterns and authorities
- **Network Behavior**: Traffic patterns and timing characteristics

## Fuzzy Hash Similarity Analysis
- Similarity scores against known tool databases
- Clustering analysis with existing payload families
- Evolutionary relationship mapping to known tools
- Variation analysis from base tool implementations

## Attribution Masking Strategy
- **Code Diversification**: Implementation variation recommendations
- **Behavioral Modification**: Pattern disruption techniques
- **Metadata Sanitization**: Compilation and build artifact removal
- **Similarity Reduction**: Fuzzy hash distance optimization

## Risk Mitigation Priorities
1. Eliminate high-confidence attribution vectors
2. Reduce fuzzy hash similarity scores below threshold
3. Diversify behavioral implementation patterns
4. Sanitize compilation and development artifacts

Provide specific masking techniques with attribution risk reduction estimates."""

@mcp.prompt()
def generate_opsec_improvement_plan(file_hash: str = "") -> str:
    """Create comprehensive, prioritized OPSEC improvement plan"""
    return f"""Generate detailed OPSEC improvement plan for {f'payload {file_hash}' if file_hash else 'the target payload'}:

## Current OPSEC Assessment
### Detection Status
- **Static Detections**: YARA hits, signature matches, file characteristics
- **Dynamic Detections**: Behavioral alerts, runtime artifacts, process analysis
- **Attribution Risks**: Tool similarity, framework patterns, code fingerprints

### Risk Categorization
```
Risk Level | Detection Type | Count | Severity | Impact
-----------|----------------|-------|----------|--------
CRITICAL   | Signatures     | X     | HIGH     | Deployment Blocker
HIGH       | Behavioral     | X     | MED      | EDR Detection Risk
MEDIUM     | Attribution    | X     | LOW      | Investigation Risk
LOW        | Metadata       | X     | MIN      | Forensic Analysis
```

## Improvement Implementation Plan

### Phase 1: Critical Detection Elimination (Week 1)
- **Signature Evasion**:
  * Modify detected strings and patterns
  * Implement advanced obfuscation
  * Test against signature databases
- **Immediate Blockers**:
  * Fix compilation artifacts
  * Remove obvious tool indicators
  * Sanitize metadata fields

### Phase 2: Behavioral Stealth Enhancement (Week 2-3)
- **Process Behavior**:
  * Implement natural execution flows
  * Add timing variations and delays
  * Minimize suspicious API usage patterns
- **Memory Management**:
  * Improve artifact cleanup
  * Reduce detectable footprints
  * Enhance anti-analysis resistance

### Phase 3: Attribution Risk Mitigation (Week 4)
- **Code Diversification**:
  * Implement alternative techniques
  * Vary implementation patterns
  * Reduce fuzzy hash similarities
- **Fingerprint Elimination**:
  * Remove framework-specific patterns
  * Customize error handling and responses
  * Modify communication protocols

### Phase 4: Validation and Testing (Week 5)
- **Comprehensive Re-testing**:
  * Full static and dynamic analysis
  * Multi-engine signature testing
  * Behavioral pattern verification
- **Deployment Readiness**:
  * Final OPSEC assessment
  * Risk acceptance evaluation
  * Monitoring requirement definition

## Success Metrics and KPIs
- **Signature Detection Rate**: Target <5%
- **Behavioral Alert Count**: Target 0 critical alerts
- **Attribution Confidence**: Target <30% similarity
- **Overall Stealth Score**: Target >85%

## Resource Requirements
- Development time: X person-hours
- Testing infrastructure: Multi-engine analysis setup
- Validation tools: Updated signature databases
- Quality assurance: Independent OPSEC review

## Risk Assessment Post-Implementation
- Residual detection probability
- Attribution risk evaluation
- Operational security impact
- Incident response considerations

Provide specific, time-bound implementation steps with measurable success criteria."""

@mcp.prompt()
def evaluate_deployment_readiness(file_hash: str = "") -> str:
    """Comprehensive deployment readiness assessment with go/no-go decision framework"""
    return f"""Evaluate operational deployment readiness for {f'payload {file_hash}' if file_hash else 'the target payload'}:

## Deployment Readiness Criteria

### Technical Assessment Matrix
```
Category              | Status | Score | Weight | Weighted Score | Blocker
---------------------|--------|-------|--------|----------------|--------
Signature Evasion    | P/F    | 0-100 | 30%    | XX/30         | Y/N
Behavioral Stealth   | P/F    | 0-100 | 25%    | XX/25         | Y/N
Attribution Masking  | P/F    | 0-100 | 20%    | XX/20         | Y/N
Technical Function   | P/F    | 0-100 | 15%    | XX/15         | Y/N
Anti-Analysis        | P/F    | 0-100 | 10%    | XX/10         | Y/N
---------------------|--------|-------|--------|----------------|--------
TOTAL READINESS      |        |       | 100%   | XX/100        |
```

### Detailed Assessment Criteria

#### Signature Evasion (30% Weight)
- **YARA Rules**: Zero matches required for deployment
- **AV Engines**: <5% detection rate across major vendors
- **Static Analysis**: Clean file characteristics and entropy
- **String Analysis**: No obvious payload indicators

#### Behavioral Stealth (25% Weight)
- **EDR Bypass**: No behavioral rule triggers
- **Process Analysis**: Natural execution patterns
- **Memory Artifacts**: Minimal detectable footprint
- **API Usage**: Legitimate application behavior

#### Attribution Masking (20% Weight)
- **Tool Similarity**: <30% fuzzy hash similarity to known tools
- **Framework Patterns**: No obvious Metasploit/CS/custom indicators
- **Code Fingerprints**: Unique implementation characteristics
- **Compilation Artifacts**: Sanitized build environment traces

#### Technical Functionality (15% Weight)
- **Core Features**: All primary functions operational
- **Error Handling**: Graceful failure and recovery
- **Compatibility**: Target environment compatibility verified
- **Performance**: Acceptable resource usage and speed

#### Anti-Analysis Resistance (10% Weight)
- **Sandbox Evasion**: Bypass common analysis environments
- **Debugging Protection**: Anti-debug and anti-VM features
- **Reverse Engineering**: Code obfuscation and protection
- **Dynamic Analysis**: Runtime analysis resistance

## Risk Assessment Framework

### Detection Probability Matrix
```
Environment Type     | Detection Risk | Confidence | Mitigation
--------------------|----------------|------------|------------
Corporate SOC       | HIGH/MED/LOW   | XX%        | [Strategy]
Advanced EDR        | HIGH/MED/LOW   | XX%        | [Strategy]
Incident Response   | HIGH/MED/LOW   | XX%        | [Strategy]
Forensic Analysis   | HIGH/MED/LOW   | XX%        | [Strategy]
```

### Operational Risk Factors
- **Mission Impact**: Payload detection consequences
- **Attribution Risk**: Operator/infrastructure exposure probability
- **Incident Escalation**: Response team engagement likelihood
- **Recovery Complexity**: Remediation and re-engagement difficulty

## Deployment Decision Framework

### GO Decision Criteria (All Must Be Met)
- ✓ Total readiness score ≥85%
- ✓ Zero deployment blockers identified
- ✓ All critical and high-priority issues resolved
- ✓ Acceptable risk level for mission requirements
- ✓ Operational security review completed and approved

### NO-GO Decision Criteria (Any Present)
- ✗ Signature detection above threshold
- ✗ Critical behavioral detections present
- ✗ High-confidence attribution vectors identified
- ✗ Core functionality failures
- ✗ Unacceptable operational risk level

### CONDITIONAL GO Criteria
- Medium-priority issues with acceptable risk levels
- Non-critical attribution indicators below threshold
- Minor functionality limitations with workarounds
- Manageable operational risks with enhanced monitoring

## Final Recommendation

### Decision: **[GO / NO-GO / CONDITIONAL GO]**

### Supporting Rationale:
- Technical assessment summary
- Risk evaluation conclusion
- Mission requirement alignment
- Operational security considerations

### Required Actions Before Deployment:
1. [Specific technical fixes required]
2. [Additional testing requirements]
3. [Operational security measures]
4. [Monitoring and response preparations]

### Post-Deployment Requirements:
- Enhanced monitoring for XX period
- Incident response team notification
- Attribution monitoring and assessment
- Performance and effectiveness tracking

### Risk Acceptance Statement:
- Residual risks acknowledged and accepted
- Mitigation strategies implemented where possible
- Operational security measures in place
- Mission leadership approval obtained

Provide clear, actionable deployment recommendation with detailed supporting analysis."""

# =============================================================================
# SERVER INITIALIZATION AND CLEANUP
# =============================================================================

@mcp.tool(name="shutdown_client", description="Properly close MCP client connections")
def shutdown_client() -> Dict[str, Any]:
    """Clean shutdown of MCP client and connections"""
    try:
        mcp_client.close()
        return {"status": "success", "message": "Client connections closed successfully"}
    except Exception as e:
        return {"status": "error", "message": f"Error during shutdown: {str(e)}"}

def cleanup_on_exit():
    """Cleanup function called on server shutdown"""
    logger.info("Shutting down LitterBox MCP server...")
    mcp_client.close()
    logger.info("Cleanup completed")

if __name__ == "__main__":
    try:
        logger.info("Starting LitterBox OPSEC MCP Server...")
        mcp.serve(host="0.0.0.0", port=50051)
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    finally:
        cleanup_on_exit()