# ios-cti-scanner

CTI-driven spyware detection for unmodified iOS devices. MSc Cyber Security dissertation, Aston University, 2026.

Code for *A CTI-Driven Workflow for Detecting Spyware on iOS Devices*.

## Scripts

- `ioc_scanner.py` - single-source version, used for the August 2026 evaluation. Run with `--auto` to ingest indicators automatically from the MVT manifest.
- `ioc_scanner_multisource.py` - multi-source version, used for the September 2026 run. Fetches MVT, Echap and Citizen Lab separately and reports which source each match came from. Run with `--sources-only` to compare the sources without a phone.

## Requirements

macOS, Python 3 (standard library only), libimobiledevice, Wireshark and Xcode. The iPhone must have encrypted backups switched off.

    brew install libimobiledevice wireshark
    python3 ioc_scanner_multisource.py

## Known limitation

Process-name indicators are matched as substrings across all files, including binary ones, which produces the false positives described in Section 4.10 of the dissertation.
