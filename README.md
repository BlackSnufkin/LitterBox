# LitterBox

![LitterBox Logo](Screenshots/lb-logo.png)

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=plastic&logo=python&logoColor=white)]()
[![Windows](https://img.shields.io/badge/Windows-Supported-0078D6?style=plastic&logo=onlyfans&logoColor=black)]()
[![Linux](https://img.shields.io/badge/Linux-Supported-FCC624?style=plastic&logo=linux&logoColor=black)]()
[![Docker](https://img.shields.io/badge/Docker-Enabled-2496ED?style=plastic&logo=docker&logoColor=white)]()
[![MCP](https://img.shields.io/badge/MCP-Enabled-412991?style=plastic&logo=openai&logoColor=black)]()
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/BlackSnufkin/LitterBox)
[![GitHub Stars](https://img.shields.io/github/stars/BlackSnufkin/LitterBox)](https://github.com/BlackSnufkin/LitterBox/stargazers)

A self-hosted payload-analysis sandbox for red teams. Upload a sample, run static / dynamic / EDR analysis against it, get a Detection Score and a triggering-indicators breakdown — decide whether the payload is field-ready before it leaves the lab.

LitterBox can also dispatch payloads to a separate EDR-instrumented Windows VM (Elastic Defend or Fibratus) and pull the correlated detection alerts back into the results page.

> While designed primarily for red teams, LitterBox is equally useful for blue teams running the same tools in their malware-analysis workflows.

## Documentation

Operator and developer documentation lives in the **[LitterBox Wiki](../../wiki)**.

| Topic | Wiki page |
|---|---|
| How everything fits together | [Application Architecture](../../wiki/Application-Architecture) |
| Run static + every reachable EDR in parallel | [All in One Pipeline](../../wiki/All-in-One-Pipeline) |
| Dispatch payloads to a real EDR VM | [EDR Integration](../../wiki/EDR-Integration) → [Elastic Defend](../../wiki/Elastic-Defend-Setup) / [Fibratus](../../wiki/Fibratus-Setup) |
| Whiskers agent (install, endpoints, build) | [Whiskers Agent](../../wiki/Whiskers-Agent) |
| Every HTTP endpoint | [HTTP API Reference](../../wiki/HTTP-API-Reference) |
| CLI / Python lib / MCP for LLMs | [GrumpyCats CLI](../../wiki/GrumpyCats-CLI) · [GrumpyCats Library](../../wiki/GrumpyCats-Library) · [LitterBoxMCP](../../wiki/LitterBoxMCP) |
| What feeds the Detection Score | [Detection Score Explained](../../wiki/Detection-Score-Explained) |
| Configure scanners / paths / timeouts | [Configuration Reference](../../wiki/Configuration-Reference) |
| Add custom YARA rules / scanners | [YARA Rules Management](../../wiki/YARA-Rules-Management) · [New Scanner](../../wiki/New-Scanner) |

## Installation

### Windows

```bash
git clone https://github.com/BlackSnufkin/LitterBox.git
cd LitterBox
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python litterbox.py            # add --debug for verbose logging
```

Open `http://127.0.0.1:1337`. Requires Python 3.11+ and an admin shell.

### Linux (Docker)

```bash
git clone https://github.com/BlackSnufkin/LitterBox.git
cd LitterBox/Docker
chmod +x setup.sh
./setup.sh
```

The setup script provisions a Windows 10 container with KVM and runs LitterBox inside. Initial build takes ~1 hour.

- **Install monitor**: `http://localhost:8006`
- **RDP**: `localhost:3389` (creds in the docker compose file)
- **LitterBox UI**: `http://127.0.0.1:1337` once setup completes

### EDR setup (optional)

Drop one or more profile YAMLs under `Config/edr_profiles/` and the upload page picks them up at boot. Full walkthroughs in the wiki: [Whiskers Agent](../../wiki/Whiskers-Agent) → [Elastic Defend Setup](../../wiki/Elastic-Defend-Setup) or [Fibratus Setup](../../wiki/Fibratus-Setup).

## Scanners

Bundled binaries under `Scanners/`. Versions and last-update dates tracked here so operators can tell at a glance whether a scanner is current.

| Scanner | Version | Last updated | Source |
|---|---|---|---|
| [PE-Sieve](https://github.com/hasherezade/pe-sieve) | 0.4.1.2 (`f1dc39d`) | 2026-05-02 | hasherezade/pe-sieve |
| [Hollows-Hunter](https://github.com/hasherezade/hollows_hunter) | 0.4.1.2 (`e271f7e`) | 2026-04-18 | hasherezade/hollows_hunter |
| [Moneta](https://github.com/forrest-orr/moneta) | `5b65395` | 2024-03-16 | forrest-orr/moneta |
| [Patriot](https://github.com/joe-desimone/patriot) | — | 2024-12-29 | joe-desimone/patriot |
| [Hunt-Sleeping-Beacons](https://github.com/thefLink/Hunt-Sleeping-Beacons) | `84dd3a9` | 2026-01-25 | thefLink/Hunt-Sleeping-Beacons |
| [RedEdr](https://github.com/dobin/RedEdr) | 0.9 (release) | 2026-04-12 | dobin/RedEdr |
| [YARA](https://github.com/VirusTotal/yara/releases) (engine `yara64.exe`) | — | 2024-12-29 | VirusTotal/yara |
| Elastic YARA rules (`Scanners/Yara/rules/elastic-yara/`) | `d131ea8` | 2026-04-30 | elastic/protections-artifacts |
| YARA-Forge Extended (`Scanners/Yara/rules/YARAForge/`) | 0.9.1 (release `20260503`) | 2026-05-03 | YARAHQ/yara-forge |
| [CheckPlz](https://github.com/BlackSnufkin/CheckPlz) | — | 2024-12-29 | BlackSnufkin/CheckPlz |
| [Stringnalyzer](https://github.com/BlackSnufkin/Rusty-Playground/tree/main/Stringnalyzer) | — | 2025-01-27 | BlackSnufkin/Rusty-Playground |
| [HolyGrail](https://github.com/BlackSnufkin/HolyGrail) | — | 2025-08-18 | BlackSnufkin/HolyGrail |

Version format: `<release-version>` or `<release-version> (release)` when the binary is pulled from an upstream release; `<release-version> (\`<commit>\`)` or just `\`<commit>\`` when built from source. Last-updated date is the upstream commit / release date, not the local build date.

When you refresh a scanner: replace the binary under its `Scanners/<Name>/` directory and update the row above (version + date).

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Work in feature branches on personal forks.

## Support 🍺

<a href="https://www.buymeacoffee.com/blacksnufkin"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" width="200" height="60"></a>

[![Stars](https://starchart.cc/blacksnufkin/litterbox.svg?variant=adaptive)](https://starchart.cc/blacksnufkin/litterbox)

## Security Advisory

- **Development use only.** This platform is designed for testing environments. Production deployment presents significant security risks.
- **Isolation required.** Run only in isolated VMs or dedicated testing environments.
- **No warranty.** Provided without guarantees; use at your own risk.
- **Legal compliance.** Users are responsible for ensuring usage complies with applicable laws.

## Acknowledgments

LitterBox stands on the work of these projects and their authors:

| Tool | Author |
|---|---|
| [YARA rules](https://github.com/elastic/protections-artifacts/tree/main/yara) · [Elastic Defend](https://www.elastic.co/security/endpoint-security) | [Elastic Security](https://github.com/elastic) |
| [PE-Sieve](https://github.com/hasherezade/pe-sieve) · [Hollows-Hunter](https://github.com/hasherezade/hollows_hunter) | [hasherezade](https://github.com/hasherezade) |
| [Moneta](https://github.com/forrest-orr/moneta) | [Forrest Orr](https://github.com/forrest-orr) |
| [Patriot](https://github.com/joe-desimone/patriot) | [joe-desimone](https://github.com/joe-desimone) |
| [Hunt-Sleeping-Beacons](https://github.com/thefLink/Hunt-Sleeping-Beacons) | [thefLink](https://github.com/thefLink) |
| [RedEdr](https://github.com/dobin/RedEdr) | [dobin](https://github.com/dobin) |
| [Fibratus](https://github.com/rabbitstack/fibratus) | [rabbitstack](https://github.com/rabbitstack) |
| [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) (basis for CheckPlz) | [rasta-mouse](https://github.com/rasta-mouse) |
| [MalAPI](https://malapi.io/) reference DB | [mr.d0x](https://github.com/mrd0x) |

## Interface

![LitterBox Demo](Screenshots/lb-demo.gif)
