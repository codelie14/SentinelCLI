# 🚀 SentinelCLI - Quick Start Guide

## ✓ Installation Completed

Your SentinelCLI project has been successfully set up with all required components:

### Project Structure
```
SentinelCLI/
├── sentinel.py              # Main interactive CLI application
├── demo.py                  # Demo script showing all features
├── test_modules.py          # Module testing script
├── requirements.txt         # Python dependencies
├── README.md                # Full documentation
│
├── engine/                  # Core monitoring engines
│   ├── system_monitor.py   # System information & monitoring
│   ├── network_monitor.py  # Network analysis
│   └── threat_engine.py    # Threat detection & scoring
│
├── modules/                 # Application features
│   ├── scanner.py          # Network scanning
│   ├── process_analyzer.py # Process analysis
│   └── report_generator.py # Report generation
│
├── logs/                   # Command history
├── reports/                # Generated reports
└── docs/                   # Documentation
```

---

## 📦 Running SentinelCLI

### Option 1: Interactive CLI Mode (Recommended)

```bash
python sentinel.py
```

This starts the interactive shell where you can run commands:

```
[sentinel]> help              # Show all commands
[sentinel]> sysinfo           # System information
[sentinel]> threats           # Analyze threats
[sentinel]> export            # Generate report
[sentinel]> exit              # Quit
```

### Option 2: Demo Mode

```bash
python demo.py
```

Runs a complete demonstration showing:
- System information
- Network analysis
- Process analysis
- Security scoring
- Report generation

### Option 3: Module Testing

```bash
python test_modules.py
```

Verifies all modules are working correctly.

---

## 🎯 Essential Commands

### System Monitoring
| Command | Function |
|---------|----------|
| `sysinfo` | Full system overview (OS, CPU, RAM, Disk) |
| `users` | Connected users |
| `startup` | Top resource-consuming processes |

### Network Analysis
| Command | Function |
|---------|----------|
| `scan` | Scan local network for active hosts |
| `ports` | List open ports and services |
| `connections` | Show active connections |

### Security
| Command | Function |
|---------|----------|
| `threats` | Analyze threats & calculate score |
| `watch` | Real-time monitoring |
| `processes` | Detect suspicious processes |
| `score` | Display security score with recommendations |

### Reporting
| Command | Function |
|---------|----------|
| `export` | Generate Markdown security report |

---

## 🔍 Example Workflow

```bash
# 1. Start the CLI
python sentinel.py

# 2. Get system overview
[sentinel]> sysinfo

# 3. Check network security
[sentinel]> ports
[sentinel]> connections

# 4. Analyze threats
[sentinel]> threats

# 5. View recommendations
[sentinel]> score

# 6. Generate a report
[sentinel]> export

# 7. Exit
[sentinel]> exit
```

---

## 📊 Understanding the Security Score

**Score Range: 0-100**

- **75-100** (🟢 LOW): Your system is secure
- **50-74** (🟡 MEDIUM): Some attention needed
- **25-49** (🟠 HIGH): Multiple threats detected
- **0-24** (🔴 CRITICAL): Immediate action required

**Score is based on:**
- Dangerous open ports (SSH, RDP, SMB)
- Suspicious network connections
- High memory/CPU usage
- Suspicious processes

---

## 📝 Generated Reports

Reports are saved in the `reports/` folder as Markdown files with the format:
```
SentinelCLI_Report_YYYYMMDD_HHMMSS.md
```

Each report includes:
- Executive summary
- System information
- Hardware resources
- Network status
- Detected threats
- Security recommendations

---

## 📋 Command History

All commands are logged to `logs/command_history.txt` for audit trails.

---

## 🔧 Troubleshooting

### Permission Issues
Some commands need elevated privileges:

**Windows:**
```bash
# Run Command Prompt as Administrator
python sentinel.py
```

**Linux:**
```bash
sudo python3 sentinel.py
```

### Module Import Errors
Reinstall dependencies:
```bash
pip install --upgrade -r requirements.txt
```

---

## 📚 More Information

- Full documentation: See [README.md](README.md)
- Project specifications: See [docs/Cahier_des_Charges.md](docs/Cahier_des_Charges.md)
- Example report: Check `reports/` folder

---

## 🎓 What You Can Do With SentinelCLI

✓ Monitor your system security in real-time  
✓ Detect open ports and suspicious connections  
✓ Analyze running processes  
✓ Generate security reports  
✓ Get actionable recommendations  
✓ Maintain command history  
✓ Learn about cybersecurity  

---

**Happy monitoring! 🛡️**

For issues or questions, check the command help:
```bash
[sentinel]> help
```
