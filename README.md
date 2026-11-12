<p align="center"><img src="src/fsa/assets/fsa.svg" width="72" height="72" alt="FSA chip logo"></p>

# Firmware Security Analyzer

Inspect a firmware image on your own machine. Open a component marker at its byte offset, review the evidence behind a security indicator, and save a report you can share.

[![Test matrix](https://github.com/Mustafaiq1998x/Firmware-Security-Analyzer/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/Mustafaiq1998x/Firmware-Security-Analyzer/actions/workflows/tests.yml?query=branch%3Amain)
[![Python](https://img.shields.io/badge/Python-3.10%2B-235751)](pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-235751)](LICENSE)

**[Walk through a sample report](docs/SAMPLE_REPORT.md)** · [Firmware test results](docs/FIRMWARE_VALIDATION.md) · [دليل البدء بالعربية](docs/START_AR.md) · [Release downloads](https://github.com/Mustafaiq1998x/Firmware-Security-Analyzer/releases)

![Local dashboard inspecting an OpenWrt firmware image](docs/dashboard.png)

## Run your first inspection

Clone the project and enter its directory.

```sh
git clone https://github.com/Mustafaiq1998x/Firmware-Security-Analyzer.git
cd Firmware-Security-Analyzer
```

| Linux or Kali | Windows PowerShell |
|---|---|
| `python3 -m venv .venv` | `py -3 -m venv .venv` |
| `.venv/bin/python -m pip install ".[web]"` | `.\.venv\Scripts\python.exe -m pip install ".[web]"` |
| `.venv/bin/fsa-gui` | `.\.venv\Scripts\fsa-gui.exe` |

Use **View sample report** to explore the bundled example, or choose your image and select **Run analysis**. The GUI opens on loopback and accepts images up to 128 MiB. Use the language control for Arabic. [Dashboard controls](docs/GUI.md)

## What the report tells you

| Question | Evidence |
|---|---|
| Which file did I inspect? | Filename, byte count and SHA-256. |
| Where are the component markers? | Searchable signatures with offsets and magic bytes. A marker is a lead for a format-specific parser. |
| What triggered a finding? | A rule, confidence and sampled evidence from printable strings. |
| What is inside this ZIP or TAR? | Optional bounded extraction returns paths, byte counts and per-file hashes. [Extraction limits](docs/EXTRACTION.md) |
| What can I share? | Full JSON, a printable dashboard and a standalone HTML report from the CLI. Review firmware-derived text for sensitive data before sharing. |

## Command line

With the virtual environment active:

```sh
fsa scan samples/demo_firmware.bin --out report.json --html report.html
fsa extract firmware.tar --outdir extracted --report manifest.json
fsa info samples/demo_firmware.bin
```

Core CLI installation uses `python -m pip install .`. The CLI scan defaults to 512 MiB. The extraction command supports ZIP and TAR. SquashFS and UBIFS appear as preliminary markers. Optional kernel advisory matching uses a local feed and requires vendor-specific review. [CLI and offline feed reference](docs/CLI.md)

## Verify a download

Look for the exact asset name and SHA-256 in its [GitHub release notes](https://github.com/Mustafaiq1998x/Firmware-Security-Analyzer/releases). When the VirusTotal workflow has completed, that row links to the dated multi-engine report. An absent row means verification has not been published for that file. Firmware submitted through the dashboard stays local.

## Project guide

[Methodology](docs/METHODOLOGY.md) · [Testing](docs/TESTING.md) · [Roadmap](docs/ROADMAP.md) · [Changelog](CHANGELOG.md) · [Reference tools](docs/REFERENCE_TOOLS.md)

Browse related GitHub topics: [firmware-analysis](https://github.com/topics/firmware-analysis) · [embedded-linux](https://github.com/topics/embedded-linux) · [static-analysis](https://github.com/topics/static-analysis) · [iot-security](https://github.com/topics/iot-security)
