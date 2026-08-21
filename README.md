# ESP-IDF secure firmware workflow

`secure_firmware.py` builds, signs, encrypts, packages, validates, and optionally flashes an existing ESP-IDF Secure Boot V2 application. It is independent of any one project: run it from an activated ESP-IDF environment and point it at a completed build directory.

The currently guaranteed target is ESP32-C5 with Secure Boot V2 and AES-XTS flash encryption. The tool never reads or changes eFuses, never enables security features, and never flashes during packaging.

## Private files

By default, the tool selects keys next to itself:

- RSA build: `secure_boot_signing_key_rsa.pem`
- ECDSA-V2 build: `secure_boot_signing_key_ecdsa.pem`
- Flash encryption: `my_flash_encryption_key.bin`

These and other `*.pem`, `*.bin`, and `*.hex` files are ignored by the supplied `.gitignore`. Override the directory with `--key-dir` or `SECURITY_WORKFLOW_DIR`, or override individual files with `--signing-key` / `SECURE_BOOT_SIGNING_KEY` and `--encryption-key` / `FLASH_ENCRYPTION_KEY`. Command-line paths take precedence over environment variables.

## Build and package

The project defaults to the current directory and the build directory defaults to `build`:

```bash
python ~/esp/projects/security-workflow/secure_firmware.py build-package
```

For the generic 20 MiB configuration:

```bash
python ~/esp/projects/security-workflow/secure_firmware.py \
    build-package \
    --build-dir build-20mb \
    --idf-define SDKCONFIG=build-20mb/sdkconfig \
    --idf-define 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.20mb' \
    --partition-image flash_test=flash_test_payload.bin \
    --label no-softdis
```

`--idf-define NAME=VALUE` is repeatable and is passed to `idf.py -D`. By default the script located on `PATH` is run with the Python interpreter used to launch this tool, so invoke the tool with the active ESP-IDF Python environment. Use `--idf-py` to override the `idf.py` executable.

To package an already completed build without rebuilding:

```bash
python ~/esp/projects/security-workflow/secure_firmware.py \
    package --build-dir build-20mb \
    --partition-image flash_test=flash_test_payload.bin \
    --label no-softdis
```

Custom artifacts are never guessed. Each one must be associated with a generated partition-table label using `--partition-image LABEL=PATH`; a relative path is resolved inside the build directory. Offsets, region sizes, encryption flags, the application filename, target, signing scheme, flash settings, and build Python are read from ESP-IDF’s generated metadata and binary partition table.

Packaging signs the bootloader and application, verifies both signatures, encrypts each required image at its physical flash address, and decrypts each encrypted result temporarily for a byte-for-byte round-trip check. It rejects overlaps and secured images that exceed their reserved regions.

All published files are replaced atomically under `<build-dir>/secured`. The directory contains signed intermediates, encrypted flash parts, the merged image, and `manifest.json`. If the merged image crosses 16 MiB, it also contains an exact 16 MiB `part1` and a `part2` whose first byte corresponds to flash offset `0x1000000`. Packaging streams the merge and split operations rather than retaining a large payload in RAM.

Use `--dry-run` to inspect the build or packaging commands without producing artifacts.

## Flash

Flashing first validates the manifest and hashes of all inputs, the ELF, and all published outputs. A rebuilt, deleted, or modified artifact is rejected. Unless `--yes` is supplied, execution requires the exact case-sensitive token `FLASH`.

With esptool, a port is mandatory and baud is optional:

```bash
python ~/esp/projects/security-workflow/secure_firmware.py \
    flash --build-dir build-20mb \
    --interface esptool --port /dev/cu.usbserial-1130

python ~/esp/projects/security-workflow/secure_firmware.py \
    flash --build-dir build-20mb \
    --interface esptool --port /dev/cu.usbserial-1130 --baud 921600
```

The encrypted flash parts are passed in one low-to-high-address `write_flash` invocation. The tool uses the Python recorded by the build and invokes `python -m esptool`.

With built-in USB-JTAG and OpenOCD:

```bash
# Neither verification nor transfer compression is enabled by default.
python ~/esp/projects/security-workflow/secure_firmware.py \
    flash --build-dir build-20mb --interface openocd

# Either option can be enabled independently, or both can be used.
python ~/esp/projects/security-workflow/secure_firmware.py \
    flash --build-dir build-20mb --interface openocd --verify --compress
```

The default configuration is `board/esp32c5-builtin.cfg`. Override it with `--openocd-config` and the executable with `--openocd`. A normal package is programmed as one merged image. A package crossing 16 MiB is programmed as its generated split files in low-to-high order. `verify` is added only with `--verify`, and `compress` only with `--compress`.

Add `--dry-run` to any flash command to validate all artifacts and print the exact command without prompting or touching hardware.

## Test

The unit suite uses temporary files and mocked subprocesses; it does not flash hardware:

```bash
cd ~/esp/projects/security-workflow
python -m unittest -v test_secure_firmware.py
```

For safety, keep private keys backed up outside the project, review `manifest.json` before provisioning, and use a stable power supply. Secure packaging does not itself prove that the running device matches the package; compare the firmware ELF SHA reported by the application with the packaged image metadata as part of device verification.
