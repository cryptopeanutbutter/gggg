# WHOIS Watching

WHOIS Watching is a defensive-first Windows security workstation for monitoring processes, correlating downloads, and enriching IP/WHOIS context on demand. The project focuses on transparency, local-first storage, and safe optional lab experimentation.

## Ethical and Operational Statement

WHOIS Watching is for defensive operations only. Lab Mode is disabled by default and requires multi-step authorization, including a passphrase and explicit allowed target list. Offensive activities outside of an isolated lab, any unauthorized probing, or use against production systems is strictly prohibited. Distribute compiled binaries responsibly, apply code-signing before release, and comply with all local laws and policies.

## Project Layout

```
main.py               # Application entry point
assets/               # Logo, textures, and gradient styling
compiled/             # Build artifacts (placeholder only in repo)
data/mock_processes.json
lab_mode/             # Gated lab utilities (disabled by default)
scanner/              # Process, download, and context modules
heuristics/engine.py  # Confidence scoring engine
utils/                # Secure storage, hashing, reporting, manifest helpers
tests/                # Unit tests executed by install script
scripts/              # Build scripts, installer, PyInstaller spec
```

### Visual Design

The UI uses a deep purple → indigo → near-black gradient (`gui/theme.py`) with smooth button ripple hooks, animated refresh timers, and respect for reduced motion toggles persisted to encrypted settings storage.

## Requirements

* Windows 10+ (primary target) with Python 3.11+
* PyQt5, psutil, cryptography, requests, PyInstaller, pytest, PySocks, stem (pinned in `requirements.txt`)
* PowerShell 5+ for installer automation

## Quick Start (Developers)

```powershell
# Clone and explore
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
pytest
python main.py --lab-mode  # Only if you are in an isolated lab and know the passphrase
```

## Building and Installing

Run the guided installer from an elevated PowerShell or Command Prompt:

```powershell
scripts\install.bat
```

The script logs to `scripts\install.log`, prompts for confirmation, prepares `venv/`, installs dependencies, and executes `pytest`. If tests fail, the build stops unless `--force` is supplied.

### Optional flags

* `--force` – continue the build even if tests fail (not recommended).
* `--elevate` – allows the script to emit a system-wide installation PowerShell script (you must run the generated script manually with elevation).

### Build Outputs

* `compiled/WHOIS_Watching-<version>-win64-<build-id>/onedir/` – PyInstaller onedir bundle based on `scripts/whois_watching.spec`.
* `compiled/WHOIS_Watching-<version>-win64-<build-id>/onefile/WHOIS_Watching.exe` – self-contained onefile executable.
* `compiled/.../build_manifest.json` – generated manifest with version, dependencies, and SHA256 entries (template at `compiled/build_manifest.template.json`).
* `scripts/install.log` – detailed action log.

The installer can optionally compress the build via `scripts/create_portable_zip.bat` and perform a user-level install (`%LOCALAPPDATA%\Programs\WHOIS_Watching\`) with a Start Menu shortcut. System-wide installs require generating an elevated PowerShell script (no auto-elevation).

### Signing and Verification

Before distributing binaries, sign the EXE:

```powershell
signtool sign /fd SHA256 /a /tr http://timestamp.digicert.com /td SHA256 compiled\WHOIS_Watching-1.0.0-win64-20240101000000\onefile\WHOIS_Watching.exe
```

Verify signatures with `signtool verify /pa`. Share SHA256 checksums alongside signed builds. Consider publishing binaries via release artifacts (e.g., GitHub Releases) rather than committing them into source control to maintain repo hygiene.

## Secure Storage

* Logs and settings are encrypted with `cryptography.Fernet` and stored under `%LOCALAPPDATA%\WHOIS_Watching\`.
* API keys are only stored after the user opts in and supplies them in the settings panel.
* No telemetry is sent unless the user explicitly enables it.

## WHOIS and IP Enrichment

Lookups are opt-in, rate-limited, and cached (`scanner/context.py`). Users can paste IP addresses to retrieve RDAP/WHOIS summaries. All responses are sanitized before display and stored locally only when reports are exported.

## Educational Multi Dehasher

The dashboard includes a purple-themed *Educational Multi Dehasher* panel designed to demystify common hash algorithms in training scenarios. Paste hashes, select supported algorithms (MD5, SHA1, SHA256), and compare against sanctioned wordlists (`data/dehash_samples.txt` or custom lists you load). Results are clearly labeled with their source to reinforce provenance. Use this tool only for defensive analysis workshops—do not attempt to crack unauthorized data.

## Encryption Toolkit

The **Encryption Toolkit** tab lets responders generate high-entropy shared passphrases, encrypt investigative notes, and protect attachments in place. Text payloads are sealed with PBKDF2-derived keys and local Fernet encryption; file helpers create `.enc` packages that can be restored after providing the same passphrase. Nothing leaves the workstation, and errors are surfaced directly in the UI.

## Secure Tor Chat

WHOIS Watching now includes an opt-in **Secure Tor Chat** workspace for peer-to-peer coordination with other analysts running the app. Highlights:

* Host mode can publish an ephemeral Tor hidden service (requires a local Tor daemon with control port access) or simply listen on localhost for testing.
* Join mode routes connections through the Tor SOCKS proxy by default. Supply the host’s onion address and shared session passphrase to authenticate the channel.
* Messages remain within the encrypted tunnel and are logged locally. File offers always require manual acceptance before anything is saved to the Downloads directory.
* Use `scripts\install.bat` to package the full application into an EXE for teammates—both peers must run the compiled WHOIS Watching build to participate in the secure chat.
* The secure chat workspace depends on the optional `PySocks` package. If it is missing, the tab stays disabled until you install it (`pip install PySocks` or rerun `scripts\install.bat`).

Refer to the Tor Project documentation for enabling the control port and configuring authentication. Never expose the chat service to production networks; keep it restricted to vetted peers inside a defensive lab environment.

## Reports

Export encrypted and plaintext reports through the UI (`utils/reporting.py`). Each report includes:

* `report_<tag>.json` – human-readable summary.
* `report_<tag>.html` – printable HTML overview with theme styling.
* `report_<tag>.enc` – encrypted archive with matching `.key` and `.sha256` files.

## Lab Mode

Lab Mode lives under `lab_mode/` and is **never** imported unless:

1. The application is launched with `--lab-mode` (sets `WHOIS_WATCHING_LAB=1`).
2. The operator provides the correct passphrase and explicitly enumerates allowed targets.
3. All targets are verified as private (RFC1918) unless the user confirms intentional public testing.

Available probes (`lab_mode/probes.py`) are limited to:

* TCP connect-and-close checks
* Lightweight banner grabbing (first 128 bytes)
* Explicit service inventory loops

All Lab Mode actions append encrypted audit logs to `%LOCALAPPDATA%\WHOIS_Watching\lab_audit.enc`. Never run Lab Mode outside an air-gapped or tightly controlled lab. Suggested setup:

* Dedicated VLAN or isolated Hyper-V/VMware/KVM network
* Snapshot-controlled targets with no production data
* No route to the public internet or sensitive internal subnets

When deploying in production environments, keep Lab Mode code in a private fork and remove the `lab_mode/` package entirely.

## Testing

Unit tests cover hashing, heuristics, and download correlation logic. Run `pytest` directly or via `scripts\install.bat`. Add new tests for additional heuristics or utilities.

## Reduced Motion and Accessibility

The settings toggle inside the app persists a “reduced motion” flag (stored encrypted). Animations respect this setting by shortening or disabling ripple effects. Continue to iterate on color contrast and keyboard navigation for accessibility.

## Contributing

* Keep the project defensive-focused.
* Document new heuristics and scoring adjustments.
* Ensure Lab Mode remains strictly gated and auditable.
* Update `requirements.txt` with pinned versions when adding dependencies.

## Support

Open defensive-use questions as issues. For sensitive disclosures, use responsible channels and do **not** upload live forensic evidence or secrets into the repository.
