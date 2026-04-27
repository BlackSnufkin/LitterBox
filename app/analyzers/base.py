# app/analyzers/base.py
import os
import subprocess
from abc import ABC, abstractmethod


class BaseAnalyzer(ABC):
    def __init__(self, config):
        self.config = config
        self.results = {}

    @abstractmethod
    def analyze(self, target):
        """
        Perform the analysis
        :param target: Could be a file path or PID depending on analysis type
        """
        pass

    @abstractmethod
    def cleanup(self):
        """Cleanup after analysis"""
        pass

    def get_results(self):
        return self.results


class BaseSubprocessAnalyzer(BaseAnalyzer):
    """
    Template-method base for analyzers that wrap an external CLI tool.

    Subclass contract:
      - Set class-level `tool_section` ('static' or 'dynamic') and `tool_name'.
      - Implement `_parse_output(stdout)` to convert tool output to a dict / list.
      - Optionally override `_build_envelope`, `_preprocess_stdout`,
        `_postprocess_findings`, `_get_cwd`, or `_on_timeout` for tool-specific
        behavior.
    """

    tool_section = None          # 'static' | 'dynamic' — required
    tool_name = None             # e.g. 'pe_sieve' — required
    target_kwarg = 'pid'         # name passed to command.format(): 'pid' | 'file_path' | 'directory'
    extra_format_kwargs = ()     # additional config keys to forward to command.format()
    abspath_targets = False      # apply os.path.abspath to tool_path and (string) target before formatting
    use_tool_path_as_cwd = False # run subprocess with cwd=dirname(tool_path)
    use_timeout = True           # set False for tools that should run without a timeout

    def analyze(self, target):
        cfg = None
        # Expose the target on the instance under its semantic name
        # (self.pid / self.file_path / self.directory) so _parse_output
        # and other hooks can reference it without re-plumbing.
        setattr(self, self.target_kwarg, target)
        try:
            cfg = self._get_tool_config()
            command = self._build_command(cfg, target)
            stdout, stderr, returncode = self._run_subprocess(
                command,
                timeout=cfg.get('timeout') if self.use_timeout else None,
                cwd=self._get_cwd(cfg),
            )
            stdout = self._preprocess_stdout(stdout)
            findings = self._parse_output(stdout)
            findings = self._postprocess_findings(findings)
            self.results = self._build_envelope(findings, returncode, stderr, stdout, target)
        except subprocess.TimeoutExpired:
            self.results = self._on_timeout(cfg)
        except Exception as e:
            self.results = self._on_error(e)

    def _get_tool_config(self):
        return self.config['analysis'][self.tool_section][self.tool_name]

    def _build_command(self, cfg, target):
        tool_path = cfg['tool_path']
        target_value = target
        if self.abspath_targets:
            tool_path = os.path.abspath(tool_path)
            if isinstance(target_value, str):
                target_value = os.path.abspath(target_value)
        kwargs = {'tool_path': tool_path, self.target_kwarg: target_value}
        for key in self.extra_format_kwargs:
            kwargs[key] = cfg[key]
        return cfg['command'].format(**kwargs)

    def _run_subprocess(self, command, timeout=None, cwd=None):
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            cwd=cwd,
        )
        stdout, stderr = process.communicate(timeout=timeout)
        return stdout, stderr, process.returncode

    def _get_cwd(self, cfg):
        if self.use_tool_path_as_cwd:
            return os.path.dirname(os.path.abspath(cfg['tool_path']))
        return None

    def _preprocess_stdout(self, stdout):
        return stdout

    def _postprocess_findings(self, findings):
        return findings

    def _build_envelope(self, findings, returncode, stderr, stdout, target):
        return {
            'status': 'completed' if returncode == 0 else 'failed',
            'findings': findings,
            'errors': stderr if stderr else None,
        }

    def _on_timeout(self, cfg):
        timeout_val = cfg.get('timeout', 'unknown') if cfg else 'unknown'
        return {'status': 'timeout', 'error': f'Analysis timed out after {timeout_val} seconds'}

    def _on_error(self, exc):
        return {'status': 'error', 'error': str(exc)}

    @abstractmethod
    def _parse_output(self, stdout):
        pass

    def cleanup(self):
        pass
