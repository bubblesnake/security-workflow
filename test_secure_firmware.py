#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for secure_firmware.py. These tests never access hardware."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import secure_firmware as sf


def write_file(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def partition_entry(
    label: str,
    offset: int,
    size: int,
    *,
    ptype: int = 1,
    subtype: int = 0,
    flags: int = 0,
) -> bytes:
    raw_label = label.encode().ljust(16, b"\0")
    return struct.pack("<2sBBLL16sL", sf.PARTITION_MAGIC, ptype, subtype, offset, size, raw_label, flags)


def record(path: Path) -> dict:
    return {
        "path": path.name,
        "size": path.stat().st_size,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


class SecureFirmwareTests(unittest.TestCase):
    def test_load_build_context_preserves_recorded_virtualenv_python(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary).resolve()
            build = project / "build"
            python_target = write_file(project / "base-python", b"#!")
            python_link = project / "venv-python"
            python_link.symlink_to(python_target)
            write_file(
                build / "partition_table/partition-table.bin",
                partition_entry("factory", 0x20000, 0x100000, ptype=0) + b"\xff" * 32,
            )
            write_file(build / "app.elf", b"elf")
            (build / "config").mkdir(exist_ok=True)
            (build / "project_description.json").write_text(
                json.dumps(
                    {
                        "build_dir": str(build),
                        "project_path": str(project),
                        "project_name": "sample",
                        "project_version": "1.2.3",
                        "target": "esp32c5",
                        "app_elf": "app.elf",
                    }
                )
            )
            (build / "config/sdkconfig.json").write_text(
                json.dumps(
                    {
                        "SECURE_BOOT_V2_ENABLED": True,
                        "SECURE_FLASH_ENC_ENABLED": True,
                    }
                )
            )
            (build / "flasher_args.json").write_text("{}")
            (build / "CMakeCache.txt").write_text(f"PYTHON:FILEPATH={python_link}\n")
            context = sf.load_build_context(project, Path("build"))
            self.assertEqual(context.python, python_link)
            self.assertNotEqual(context.python, python_target)
            self.assertEqual(context.partitions[0].offset, 0x20000)

    def test_parse_partition_table_and_flags(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "partitions.bin"
            path.write_bytes(
                partition_entry("factory", 0x20000, 0x400000, ptype=0, flags=0)
                + partition_entry("flash_test", 0x420000, 0xFE0000, flags=3)
                + b"\xff" * 32
            )
            factory, flash_test = sf.parse_partition_table(path)
            self.assertEqual((factory.label, factory.offset, factory.size), ("factory", 0x20000, 0x400000))
            self.assertFalse(factory.encrypted)
            self.assertTrue(flash_test.encrypted)
            self.assertTrue(flash_test.readonly)

    def test_signing_scheme(self) -> None:
        self.assertEqual(sf.signing_scheme({"SECURE_SIGNED_APPS_RSA_SCHEME": True}), "rsa")
        self.assertEqual(
            sf.signing_scheme({"SECURE_SIGNED_APPS_ECDSA_V2_SCHEME": True}), "ecdsa-v2"
        )
        with self.assertRaisesRegex(sf.WorkflowError, "exactly one"):
            sf.signing_scheme({})
        with self.assertRaisesRegex(sf.WorkflowError, "exactly one"):
            sf.signing_scheme(
                {
                    "SECURE_SIGNED_APPS_RSA_SCHEME": True,
                    "SECURE_SIGNED_APPS_ECDSA_V2_SCHEME": True,
                }
            )

    def test_partition_image_paths_and_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            result = sf.parse_partition_images(["data=payload.bin"], base)
            self.assertEqual(result["data"], (base / "payload.bin").resolve())
            with self.assertRaisesRegex(sf.WorkflowError, "Duplicate"):
                sf.parse_partition_images(["data=a.bin", "data=b.bin"], base)

    def test_validate_label(self) -> None:
        self.assertEqual(sf.validate_label("release_20MiB-1.0"), "release_20MiB-1.0")
        with self.assertRaises(sf.WorkflowError):
            sf.validate_label("not safe/path")

    def test_image_plans_use_partition_offsets_and_flags(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary)
            boot = write_file(build / "bootloader/bootloader.bin", b"boot")
            table = write_file(build / "partition_table/partition-table.bin", b"table")
            app = write_file(build / "app.bin", b"app")
            custom = write_file(build / "payload.bin", b"payload")
            python = write_file(build / "python", b"#!")
            elf = write_file(build / "app.elf", b"elf")
            context = sf.BuildContext(
                project_dir=build,
                build_dir=build,
                project_name="sample",
                project_version="1.0",
                target="esp32c5",
                python=python,
                app_elf=elf,
                config={"BOOTLOADER_OFFSET_IN_FLASH": 0x2000, "PARTITION_TABLE_OFFSET": 0x12000},
                flasher_args={
                    "app": {"offset": "0x20000", "file": app.name},
                    "partition-table": {"offset": "0x12000", "file": "partition_table/partition-table.bin"},
                },
                partitions=(
                    sf.Partition("factory", 0, 0, 0x20000, 0x400000, False, False),
                    sf.Partition("data", 1, 0, 0x420000, 0x100000, True, False),
                ),
            )
            plans = sf.make_image_plans(context, {"data": custom})
            self.assertEqual([plan.offset for plan in plans], [0x2000, 0x12000, 0x20000, 0x420000])
            self.assertEqual(plans[-1].encrypt, True)
            self.assertEqual(plans[-1].sign, False)
            self.assertEqual(plans[0].source, boot.resolve())
            self.assertEqual(plans[1].source, table.resolve())

    def test_image_larger_than_partition_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary)
            write_file(build / "bootloader/bootloader.bin", b"boot")
            write_file(build / "partition_table/partition-table.bin", b"table")
            write_file(build / "app.bin", b"x" * 17)
            context = sf.BuildContext(
                build,
                build,
                "sample",
                "1",
                "esp32c5",
                build / "python",
                build / "app.elf",
                {"BOOTLOADER_OFFSET_IN_FLASH": 0x2000, "PARTITION_TABLE_OFFSET": 0x12000},
                {"app": {"offset": 0x20000, "file": "app.bin"}},
                (sf.Partition("factory", 0, 0, 0x20000, 16, False, False),),
            )
            with self.assertRaisesRegex(sf.WorkflowError, "larger"):
                sf.make_image_plans(context, {})

    def test_stream_merge_and_exact_split_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            low = write_file(base / "low.bin", b"low")
            high = write_file(base / "high.bin", b"high")
            merged = base / "merged.bin"
            size = sf.merge_images([(0, low), (sf.SPLIT_BOUNDARY + 4, high)], merged)
            self.assertEqual(size, sf.SPLIT_BOUNDARY + 8)
            part1, part2 = base / "part1.bin", base / "part2.bin"
            sf.split_merged_image(merged, part1, part2)
            self.assertEqual(part1.stat().st_size, sf.SPLIT_BOUNDARY)
            self.assertEqual(part2.read_bytes(), b"\xff\xff\xff\xffhigh")

    def test_merge_rejects_overlap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            first = write_file(base / "first.bin", b"1234")
            second = write_file(base / "second.bin", b"x")
            with self.assertRaisesRegex(sf.WorkflowError, "overlaps"):
                sf.merge_images([(0, first), (3, second)], base / "merged.bin")

    def test_openocd_verify_and_compress_are_independent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            secured = Path(temporary)
            merged = write_file(secured / "merged.bin", b"image")
            manifest = {"merged": record(merged), "split": []}
            for verify in (False, True):
                for compress in (False, True):
                    args = argparse.Namespace(
                        openocd="openocd",
                        openocd_config="board/esp32c5-builtin.cfg",
                        verify=verify,
                        compress=compress,
                    )
                    command = sf.make_openocd_flash_command(args, manifest, secured)
                    program = command[-1]
                    self.assertEqual(" verify" in program, verify)
                    self.assertEqual(" compress" in program, compress)
                    self.assertTrue(program.endswith("reset exit"))

    def test_openocd_split_order_is_upper_then_lower(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            secured = Path(temporary)
            high = write_file(secured / "part2.bin", b"2")
            low = write_file(secured / "part1.bin", b"1")
            manifest = {
                "split": [
                    {"offset": sf.SPLIT_BOUNDARY, **record(high)},
                    {"offset": 0, **record(low)},
                ]
            }
            args = argparse.Namespace(
                openocd="openocd",
                openocd_config="board/esp32c5-builtin.cfg",
                verify=False,
                compress=False,
            )
            command = sf.make_openocd_flash_command(args, manifest, secured)
            self.assertIn("part2.bin", command[4])
            self.assertIn("0x1000000", command[4])
            self.assertNotIn("reset", command[4])
            self.assertIn("part1.bin", command[6])
            self.assertIn("0x0", command[6])
            self.assertIn("reset exit", command[6])

    def test_esptool_requires_port_and_orders_parts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            secured = Path(temporary)
            python = write_file(secured / "python", b"#!")
            manifest = {
                "build_python": str(python),
                "target": "esp32c5",
                "extra_esptool_args": {"stub": False},
                "flash_settings": {"flash_mode": "dio", "flash_size": "32MB"},
                "flash_parts": [
                    {"offset": 0x20000, "file": "app.bin"},
                    {"offset": 0x2000, "file": "boot.bin"},
                ],
            }
            missing = argparse.Namespace(port=None, baud=None)
            with self.assertRaisesRegex(sf.WorkflowError, "--port"):
                sf.make_esptool_flash_command(missing, manifest, secured)
            args = argparse.Namespace(port="/dev/test", baud=921600)
            command = sf.make_esptool_flash_command(args, manifest, secured)
            self.assertLess(command.index("0x2000"), command.index("0x20000"))
            self.assertIn("--no-stub", command)

    def test_manifest_detects_modified_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            build = project / "build"
            secured = build / "secured"
            input_file = write_file(build / "input.bin", b"input")
            elf = write_file(build / "app.elf", b"elf")
            output = write_file(secured / "output.bin", b"output")
            manifest = {
                "schema_version": sf.SCHEMA_VERSION,
                "build_dir": str(build),
                "inputs": [record(input_file)],
                "app_elf": record(elf),
                "outputs": [record(output)],
            }
            (secured / "manifest.json").write_text(json.dumps(manifest))
            sf.load_and_validate_manifest(project, Path("build"))
            output.write_bytes(b"tampered")
            with self.assertRaisesRegex(sf.WorkflowError, "stale or modified"):
                sf.load_and_validate_manifest(project, Path("build"))

    def test_confirmation_requires_exact_flash(self) -> None:
        with mock.patch("builtins.input", return_value="FLASH"):
            sf.confirm_flash(False)
        with mock.patch("builtins.input", return_value="flash"):
            with self.assertRaisesRegex(sf.WorkflowError, "cancelled"):
                sf.confirm_flash(False)
        with mock.patch("builtins.input") as prompt:
            sf.confirm_flash(True)
            prompt.assert_not_called()

    def test_build_command_forwards_definitions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            args = argparse.Namespace(
                project_dir=str(project),
                build_dir="build-20mb",
                idf_py="idf.py",
                idf_define=["SDKCONFIG=x", "SDKCONFIG_DEFAULTS=a;b"],
                dry_run=False,
            )
            with mock.patch.object(sf, "run_command") as run:
                sf.build_project(args)
            command, cwd, dry_run = run.call_args.args
            self.assertEqual(cwd, project.resolve())
            self.assertFalse(dry_run)
            self.assertEqual(
                command,
                [
                    "idf.py",
                    "-B",
                    str((project / "build-20mb").resolve()),
                    "-D",
                    "SDKCONFIG=x",
                    "-D",
                    "SDKCONFIG_DEFAULTS=a;b",
                    "build",
                ],
            )

    def test_default_idf_py_uses_active_python(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            args = argparse.Namespace(
                project_dir=str(project),
                build_dir="build",
                idf_py=None,
                idf_define=[],
                dry_run=False,
            )
            with mock.patch.object(sf.shutil, "which", return_value="/tools/idf.py"), mock.patch.object(
                sf, "run_command"
            ) as run:
                sf.build_project(args)
            command = run.call_args.args[0]
            self.assertEqual(command[:2], [sf.sys.executable, "/tools/idf.py"])


if __name__ == "__main__":
    unittest.main()
