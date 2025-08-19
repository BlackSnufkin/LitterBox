# GrumpyCats

![GrumpyCats Banner](https://github.com/user-attachments/assets/9d4018f7-79e8-4835-82af-49cf6c12b9e9)

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-GPL%20v3-green.svg)]()
[![MCP Supported](https://img.shields.io/badge/MCP-Supported-blueviolet.svg)]()
[![AI Powered](https://img.shields.io/badge/AI-Powered-brightgreen.svg)]()

## What This Is

GrumpyCats is a Python client for talking to LitterBox malware analysis sandbox. It comes in two flavors:

1. **grumpycat.py** - Python client that works as both a command-line tool and a library you can import
2. **LitterBoxMCP.py** - MCP server that lets Claude and other AI models analyze malware for you

---

## Table of Contents
- [Command Line Tool](#command-line-tool)
- [Using It](#using-it)
- [AI Integration](#ai-integration)
- [Installation](#installation)
- [API Functions](#api-functions)
---

## Command Line Tool

The Python client talks to your LitterBox server and handles all the boring stuff like connection management and error handling for you.

### What You Need

```bash
pip install requests
```

If you're using this with Claude Desktop, install it globally.

### How to Use It

```bash
python grumpycat.py [options] <command> [command-options]
```

### Commands

| Command | What It Does |
|---------|-------------|
| `upload` | Upload a file for analysis |
| `upload-driver` | Upload a kernel driver for BYOVD analysis |
| `analyze-pid` | Analyze a running process |
| `results` | Get your analysis results |
| `report` | Generate HTML reports |
| `files` | See all your analyzed files |
| `doppelganger-scan` | Run system baseline scan |
| `doppelganger-analyze` | Compare files for similarity |
| `doppelganger-db` | Build fuzzy hash database |
| `status` | Check if everything's working |
| `cleanup` | Delete all your junk |
| `health` | Health check |
| `delete` | Delete specific files |

### Options

| Option | What It Does |
|--------|-------------|
| `--debug` | Show debug info |
| `--url URL` | Your LitterBox server URL |
| `--timeout TIMEOUT` | How long to wait for responses |
| `--no-verify-ssl` | Skip SSL verification |
| `--proxy PROXY` | Use a proxy |

## Using It

### Basic Stuff

```bash
# Upload and analyze a file
grumpycat.py upload malware.exe --analysis static dynamic

# Upload a kernel driver for BYOVD analysis
grumpycat.py upload-driver rootkit.sys --holygrail

# Analyze a running process
grumpycat.py analyze-pid 1234 --wait

# Get all results at once
grumpycat.py results abc123def --comprehensive

# Get specific results
grumpycat.py results abc123def --type static
```

### Driver Analysis

```bash
# Upload and analyze a driver
grumpycat.py upload-driver driver.sys --holygrail

# Get the BYOVD results
grumpycat.py results abc123def --type holygrail
```

### Similarity Analysis

```bash
# Scan your system for baseline
grumpycat.py doppelganger-scan --type blender

# Check if your malware looks like known stuff
grumpycat.py doppelganger-analyze abc123def --type fuzzy --threshold 85

# Build a database of known samples
grumpycat.py doppelganger-db --folder /path/to/files --extensions .exe .dll
```

### Reports

```bash
# View report in terminal
grumpycat.py report abc123def

# Download it
grumpycat.py report abc123def --download

# Save to specific folder
grumpycat.py report abc123def --download --output /path/to/reports/

# Open in your browser
grumpycat.py report abc123def --browser
```

### Maintenance

```bash
# Check if everything's working
grumpycat.py status --full

# Clean up your mess
grumpycat.py cleanup --all

# Delete specific stuff
grumpycat.py delete abc123def
```

### Using It as a Library

```python
from grumpycat import LitterBoxClient

# Use it in your code
with LitterBoxClient(base_url="http://127.0.0.1:1337") as client:
    
    # Upload and analyze
    result = client.upload_file("malware.exe")
    file_hash = result['file_info']['md5']
    
    # Run analysis
    static_result = client.analyze_file(file_hash, 'static')
    dynamic_result = client.analyze_file(file_hash, 'dynamic')
    
    # Get everything at once
    all_results = client.get_comprehensive_results(file_hash)
    
    # Driver analysis
    driver_result = client.upload_and_analyze_driver("driver.sys", run_holygrail=True)
    
    # Similarity stuff
    blender_scan = client.run_blender_scan()
    comparison = client.compare_with_blender(file_hash)
    
    # Check system status
    status = client.get_system_status()
```

---

## AI Integration

The MCP server lets Claude analyze malware and give you OPSEC advice. It's basically like having a red team consultant that never sleeps.

### What You Need

| Thing | How to Get It |
|-------------|--------------|
| **Claude Desktop** | [Download it](https://claude.ai/desktop) |
| **fastmcp** | `pip install fastmcp` |
| **mcp-server** | `pip install mcp-server` |
| **requests** | `pip install requests` |
| **uv** | `powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 \| iex"` |
| **grumpycat.py** | Put it in the same folder |

### Setup

```bash
mcp install .\LitterBoxMCP.py
```

You should see:
```
[05/16/25 02:47:13] INFO     Added server 'LitterBoxMCP' to Claude config                                  claude.py:143
                    INFO     Successfully installed LitterBoxMCP in Claude app  
```

## Installation

1. Download the files
2. Install requests (`pip install requests`)
3. For AI stuff, install the MCP requirements
4. Install the MCP server in Claude if you want AI analysis

## API Functions

When you're using the MCP server with Claude, these functions are available:

### Analysis Functions

| Function | What It Does |
|----------|-------------|
| `upload_payload(path, name=None)` | Upload a file for analysis |
| `upload_kernel_driver(path, name=None, run_holygrail=True)` | Upload a driver for BYOVD analysis |
| `analyze_static(file_hash)` | Run static analysis |
| `analyze_dynamic(target, cmd_args=None)` | Run dynamic analysis |
| `analyze_holygrail(file_hash)` | Run BYOVD analysis on drivers |
| `get_comprehensive_results(target)` | Get all results at once |
| `get_file_info(file_hash)` | Get file details |
| `get_static_results(file_hash)` | Get static analysis results |
| `get_dynamic_results(target)` | Get dynamic analysis results |
| `get_holygrail_results(target)` | Get BYOVD results |

### Similarity Analysis

| Function | What It Does |
|----------|-------------|
| `run_blender_scan()` | Scan system for baseline |
| `compare_with_blender(file_hash)` | Compare against baseline |
| `create_fuzzy_database(folder_path, extensions=None)` | Build similarity database |
| `analyze_fuzzy_similarity(file_hash, threshold=85)` | Check similarity to known samples |

### System Stuff

| Function | What It Does |
|----------|-------------|
| `list_analyzed_payloads()` | See all your analyzed files |
| `get_system_status()` | Check system health |
| `cleanup_analysis_artifacts()` | Clean up files |
| `check_sandbox_health()` | Verify tools are working |
| `delete_payload(file_hash)` | Delete specific files |

### OPSEC Analysis Prompts

These are the AI prompts that help with red team analysis:

| Prompt | What It Does |
|--------|---------|
| `analyze_detection_patterns(file_hash="")` | Figure out what's getting detected and why |
| `assess_evasion_effectiveness(file_hash="")` | Check how well your evasion is working |
| `analyze_attribution_risks(file_hash="")` | Look for things that could link back to you |
| `generate_opsec_improvement_plan(file_hash="")` | Get a plan to make your stuff harder to detect |
| `evaluate_deployment_readiness(file_hash="")` | Decide if your payload is ready for real use |

### Claude Integration

https://github.com/user-attachments/assets/bd5e0653-c4c3-4d89-8651-215b8ee9cea2

