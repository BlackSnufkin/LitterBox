# Docker

Windows 10 in a container. LitterBox gets installed automatically.

## Files

### docker-compose.yml
Windows container with 8GB RAM, 4 cores, 75GB disk. Uses KVM for speed.

Change stuff by editing the environment variables:
- `VERSION`: Windows version ("10", "11", "ltsc", etc.)
- `RAM_SIZE`: Memory allocation ("4G", "16G")  
- `CPU_CORES`: CPU cores ("2", "8")
- `DISK_SIZE`: Storage ("50G", "100G")
- `USERNAME/PASSWORD`: Login credentials

### setup.sh
Installs Docker, checks if KVM works, starts everything.

### File Layout
```
Docker/
├── docker-compose.yml    # Container settings
├── setup.sh             # Setup script  
├── install.ps1          # Windows installer
├── oem/                 # Auto-run stuff
└── share/               # Shared files
```

## How it works
1. `setup.sh` installs Docker and starts container
2. Windows boots, runs `install.ps1` automatically  
3. Script installs LitterBox and dependencies
4. Done

## Credit / Troubleshooting
For container issues, networking problems, or Windows boot failures, refer to [Windows inside a Docker container](https://github.com/dockur/windows)