# BootAttestor

Minimal tool for **boot attestation and system integrity**. It reads TPM/EFI artifacts (PCRs, TCG Event Log, EFI variables), builds a report, and compares it against a trusted **baseline**. Useful for IR, hardening, and CI/CD image checks.

## Features

* 📦 Artifact collection: **PCR 0–7/11**, **TCG Event Log**, EFI vars (`SecureBoot`, `db`, `dbx`, `BootOrder`, etc.).
* 🔎 Baseline diff: PCR/event comparison with clear highlights.
* 🧾 Reports: JSON + human-readable summary (exit code reflects status).
* 🖥️ Platforms: Windows / Linux (TPM 2.0, UEFI).
* 🪪 Hash algorithms: SHA-1 / SHA-256.

## Why use it

* Verify your boot chain (Boot Manager, services, drivers, boot options) hasn’t drifted.
* Catch unwanted changes (new driver, modified `dbx`, sneaky `BootOrder` entry).
* Validate golden images and track configuration drift.

## Install

```bash
# from source
git clone https://github.com/Wythwool/bootattestor.git
cd bootattestor
pip install -r requirements.txt
```

**Requirements**

* Windows: Administrator privileges to read EFI vars/logs.
* Linux: access to `/sys/firmware/efi/efivars` and `tpm0`.

## Quick start

```bash
# Collect and report without a baseline
python -m bootattestor run --out report.json

# Create a baseline from a known-good machine
python -m bootattestor baseline make --out baseline.json

# Verify current state against the baseline
python -m bootattestor verify --baseline baseline.json --out verify.json
```

## Report format (short)

```json
{
  "host": "DESKTOP-123",
  "tpmspec": "2.0",
  "pcr": { "0": "sha256:…", "1": "sha256:…" },
  "tcg_log": [
    { "idx": 0, "algo": "sha256", "desc": "EFI_BOOT_SERVICES_DRIVER", "hash": "…" }
  ],
  "efi": { "SecureBoot": true, "dbx_size": 123456 },
  "diff": {
    "pcr": [{ "index": 7, "expected": "…", "actual": "…" }],
    "events": [ … ]
  },
  "status": "ok|drift|fail"
}
```

## Exit codes

* `0` — OK (matches baseline / no critical issues)
* `1` — Drift (differences found)
* `2` — Runtime error / data unavailable

## Ops tips

* Version your baselines (git tags per image/release).
* Refresh the baseline after legitimate firmware/boot updates.
* Run `verify` in CI before shipping images.

## Roadmap

* [ ] Signed baselines/reports (Sigstore/PGP)
* [ ] Prometheus metrics export
* [ ] Deeper TCG event parsing (measured-boot apps)
* [ ] Solid cross-platform EFI var access

## Limitations

* Requires TPM 2.0 and UEFI.
* OS must expose PCRs and the event log.
* On Windows, EFI var access may require elevated rights.

## License

MIT
