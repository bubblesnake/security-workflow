# ESP-IDF secure firmware workflow

`secure_firmware.py` builds, signs, encrypts, packages, validates, and optionally flashes an existing ESP-IDF Secure Boot V2 application. It is independent of any one project: run it from an activated ESP-IDF environment and point it at a completed build directory.

The currently guaranteed target is ESP32-C5 with Secure Boot V2 and AES-XTS flash encryption. The tool never reads or changes eFuses, never enables security features, and never flashes during packaging.

## Private files

By default, the tool selects keys next to itself:

- RSA build: `secure_boot_signing_key_rsa.pem`
- ECDSA-V2 build: `secure_boot_signing_key_ecdsa.pem`
- Flash encryption: `my_flash_encryption_key.bin`

These and other `*.pem`, `*.bin`, and `*.hex` files are ignored by the supplied `.gitignore`. Override the directory with `--key-dir` or `SECURITY_WORKFLOW_DIR`, or override individual files with `--signing-key` / `SECURE_BOOT_SIGNING_KEY` and `--encryption-key` / `FLASH_ENCRYPTION_KEY`. Command-line paths take precedence over environment variables.

### Generate keys and provision an ESP32-C5

Run these commands in an activated ESP-IDF environment. From this repository, generate **new** files only for a device that has not already been provisioned; keep the original keys for any chip that has already received them. Choose the signing scheme configured in the firmware (`CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME` or `CONFIG_SECURE_SIGNED_APPS_ECDSA_V2_SCHEME`):

```bash
cd ~/esp/projects/security-workflow
umask 077

# RSA-3072 Secure Boot V2 build:
python -m espsecure generate_signing_key --version 2 --scheme rsa3072 secure_boot_signing_key_rsa.pem
python -m espsecure digest_sbv2_public_key --keyfile secure_boot_signing_key_rsa.pem --output digest_rsa.bin

# OR, for an ECDSA-P256 Secure Boot V2 build:
python -m espsecure generate_signing_key --version 2 --scheme ecdsa256 secure_boot_signing_key_ecdsa.pem
python -m espsecure digest_sbv2_public_key --keyfile secure_boot_signing_key_ecdsa.pem --output digest_ecdsa.bin

# ESP32-C5 AES-XTS-128 uses a 256-bit (32-byte) flash encryption key:
python -m espsecure generate_flash_encryption_key my_flash_encryption_key.bin
```

The `.pem` file stays on the host for signing; burn its **public-key digest**, not the private signing key. The flash encryption key is burned to the chip and must match the file used by `secure_firmware.py` to encrypt images. Back up both keys securely before provisioning. The digest and flash key must occupy different unused eFuse key blocks. Check the chip first and adjust the example block numbers if they are already in use:

```bash
PORT=/dev/cu.usbserial-1130  # Replace with your device's serial port.
python -m espefuse --chip esp32c5 --port "$PORT" summary

# Example allocation: BLOCK_KEY0 = Secure Boot digest, BLOCK_KEY1 = flash key.
# Use digest_ecdsa.bin instead for an ECDSA build.
python -m espefuse --chip esp32c5 --port "$PORT" burn_key BLOCK_KEY0 digest_rsa.bin SECURE_BOOT_DIGEST0
python -m espefuse --chip esp32c5 --port "$PORT" burn_key BLOCK_KEY1 my_flash_encryption_key.bin XTS_AES_128_KEY
python -m espefuse --chip esp32c5 --port "$PORT" summary
```

eFuse burns are irreversible. For externally encrypted images, enable the matching security features **after** the signed, encrypted bootloader, partition table, and application have been flashed with the commands in [Flash](#flash). On a fresh ESP32-C5, the following sets one `SPI_BOOT_CRYPT_CNT` bit (development mode, with flash encryption enabled) and enables Secure Boot V2:

```bash
python -m espefuse --chip esp32c5 --port "$PORT" burn_efuse SPI_BOOT_CRYPT_CNT 0x1
python -m espefuse --chip esp32c5 --port "$PORT" burn_efuse SECURE_BOOT_EN
python -m espefuse --chip esp32c5 --port "$PORT" summary
```

Confirm the chip's existing eFuse state and the firmware configuration before burning these bits. For release mode, ESP-IDF documents burning `SPI_BOOT_CRYPT_CNT` to `0x7` instead of `0x1`. Production provisioning may also require additional security eFuses and write protection according to the ESP-IDF security configuration.

#### Optional JTAG provisioning: choose one path

- **Allow later JTAG access with an HMAC key.** Burn a unique 32-byte key into an unused block with purpose `HMAC_DOWN_JTAG`, then set `SOFT_DIS_JTAG`. `burn_key` read and write protects the HMAC key by default; do this **before** write protecting `RD_DIS`. Setting all three `SOFT_DIS_JTAG` bits leaves an odd number set (JTAG disabled) and prevents a later eFuse bit from toggling it back on. JTAG can then be re-enabled from firmware with `esp_hmac_jtag_enable()` and the HMAC-SHA256 token derived from the saved key and 32 zero bytes. Keep the key backed up. Do not burn `DIS_PAD_JTAG` for this path.

  ```bash
  # Use a new, unused file and key block; BLOCK_KEY2 is only an example.
  openssl rand -out hmac_jtag_key.bin 32
  python -m espefuse --chip esp32c5 --port "$PORT" burn_key BLOCK_KEY2 hmac_jtag_key.bin HMAC_DOWN_JTAG
  python -m espefuse --chip esp32c5 --port "$PORT" summary
  python -m espefuse --chip esp32c5 --port "$PORT" burn_efuse SOFT_DIS_JTAG 0x7
  ```

  Check the firmware's JTAG security configuration before first boot: ESP-IDF's default secure boot and flash encryption paths burn `DIS_PAD_JTAG` and `DIS_USB_JTAG`, defeating HMAC re-enablement. `CONFIG_SECURE_BOOT_ALLOW_JTAG` prevents those bootloader burns where that option is available; the soft-disable eFuse above still controls JTAG access. See the [ESP32-C5 HMAC JTAG guide](https://docs.espressif.com/projects/esp-idf/en/latest/esp32c5/api-reference/peripherals/hmac.html).

- **Disable JTAG permanently.** Burn both the pad and USB JTAG disable bits. HMAC cannot restore JTAG after `DIS_PAD_JTAG` is set; `DIS_USB_JTAG` also cuts off the built-in USB JTAG connection.

  ```bash
  python -m espefuse --chip esp32c5 --port "$PORT" burn_efuse DIS_PAD_JTAG 0x1
  python -m espefuse --chip esp32c5 --port "$PORT" burn_efuse DIS_USB_JTAG 0x1
  python -m espefuse --chip esp32c5 --port "$PORT" summary
  ```

Finally, after all keys that need read protection have been burned and protected, write protect `RD_DIS` to keep the Secure Boot public-key digest readable. **Do this only after confirming that the flash encryption key is read protected:** once `RD_DIS` is write protected, no additional eFuse key can be made unreadable. Check the eFuse summary before and after the irreversible burn:

```bash
python -m espefuse --chip esp32c5 --port "$PORT" summary
python -m espefuse --chip esp32c5 --port "$PORT" write_protect_efuse RD_DIS
python -m espefuse --chip esp32c5 --port "$PORT" summary
```

See the [ESP-IDF ESP32-C5 security enablement workflow](https://docs.espressif.com/projects/esp-idf/en/latest/esp32c5/security/security-features-enablement-workflows.html) for the full eFuse provisioning sequence.

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

The default configuration is `board/esp32c5-builtin.cfg`. Override it with `--openocd-config` and the executable with `--openocd`. A normal package is programmed as one merged image. For a package crossing 16 MiB, OpenOCD programs the upper split at `0x1000000` first and the lower 16 MiB split at `0x0` second. `verify` is added only with `--verify`, and `compress` only with `--compress`.

Add `--dry-run` to any flash command to validate all artifacts and print the exact command without prompting or touching hardware.

## Test

The unit suite uses temporary files and mocked subprocesses; it does not flash hardware:

```bash
cd ~/esp/projects/security-workflow
python -m unittest -v test_secure_firmware.py
```

For safety, keep private keys backed up outside the project, review `manifest.json` before provisioning, and use a stable power supply. Secure packaging does not itself prove that the running device matches the package; compare the firmware ELF SHA reported by the application with the packaged image metadata as part of device verification.
