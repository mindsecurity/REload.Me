# REload.Me

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)](https://github.com/yourusername/REload.Me)
[![Build](https://img.shields.io/badge/Build-Stable-brightgreen.svg)](https://github.com/yourusername/REload.Me)

Static binary analysis framework with integrated Control Flow Graph visualization and AI-assisted reverse engineering guidance.

## Overview

REload.Me provides comprehensive static analysis capabilities for PE and ELF binaries, featuring real-time CFG generation, security assessment, and intelligent analysis recommendations. Built for security researchers, malware analysts, and reverse engineers.

## Features

**Static Analysis Engine**
- Multi-format binary parsing (PE/ELF)
- Security mitigation detection (ASLR, DEP, PIE, Canary)
- Function discovery and analysis
- Import/export enumeration
- String extraction and analysis

**Control Flow Analysis**
- Real-time CFG generation via angr
- Function-level flow visualization
- Basic block analysis with metrics
- Connection mapping and statistics
- ASCII terminal rendering

**Intelligence Layer**
- AI-powered analysis recommendations
- Dynamic analysis planning
- Tool integration guidance
- Educational context provision

## Installation

```bash
git clone https://github.com/marcostolosa/REload.Me.git
cd REload.Me
pip install -e .
```

## Usage

```bash
# Basic analysis
reloadme analyze target.exe

# Include CFG analysis
reloadme analyze target.exe --cfg

# Function-specific CFG
reloadme analyze target.exe --cfg-function main
```

## Command Reference

| Option | Description |
|--------|-------------|
| `analyze <file>` | Perform static analysis |
| `--cfg` | Include full binary CFG |
| `--cfg-function <name>` | Analyze specific function CFG |

## Analysis Output

**Binary Information**
- Architecture and platform details
- Compilation metadata
- Entry point identification

**Security Assessment**
```
┌─────────────── Security Features ───────────────┐
│ Canary     │ Enabled                           │
│ NX (DEP)   │ Enabled                           │
│ PIE        │ Enabled                           │
│ ASLR       │ Enabled                           │
└───────────────────────────────────────────────┘
```

**Function Analysis**
- Complete function enumeration
- Entry point detection
- Call convention analysis
- Size and complexity metrics

**CFG Visualization**
```
+- 0x401000 (size: 7, instr: 1)
  +-> 0x401007
  |
+- 0x401007 (size: 17, instr: 4)
  +-> 0x401018
  |
+- 0x401018 (size: 4, instr: 1)
  +-> 0x40101d
  +-> 0x40101c
```

## Architecture

```
reloadme/
├── analysis/
│   ├── static_analyzer.py    # Core analysis engine
│   └── cfg_analyzer.py       # CFG generation
├── presentation/
│   ├── display.py           # Output formatting
│   └── cfg_display.py       # CFG visualization
├── mentorship/
│   └── ai_mentor.py         # Intelligence layer
└── main.py                  # CLI interface
```

## Dependencies

**Core Requirements**
- Python 3.9+
- radare2/r2pipe
- rich (terminal UI)
- typer (CLI framework)

**CFG Analysis**
- angr (binary analysis)
- graphviz (visualization)

**AI Features**
- OpenAI API (optional)

## Configuration

Set OpenAI API key for intelligence features:
```bash
export OPENAI_API_KEY="your-key-here"
```

## License

MIT License - see [LICENSE](LICENSE) file.

## Technical Notes

- CFG generation requires angr framework
- Large binaries may require extended analysis time
- Terminal output optimized for dark themes
- Cross-platform compatibility verified

---

**REload.Me** - Professional binary analysis framework