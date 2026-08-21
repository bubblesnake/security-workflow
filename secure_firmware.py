#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

"""Build, securely package, and flash ESP-IDF firmware artifacts."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shlex
import shutil
import struct
import subprocess
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


SCHEMA_VERSION = 1
PARTITION_ENTRY_SIZE = 32
PARTITION_MAGIC = b"\xaa\x50"
PARTITION_MD5_MAGIC = b"\xeb\xeb"
APP_PARTITION_TYPE = 0x00
SPLIT_BOUNDARY = 16 * 1024 * 1024
COPY_CHUNK_SIZE = 1024 * 1024
LABEL_RE = re.compile(r"^[A-Za-z0-9._-]+$")


class WorkflowError(RuntimeError):
    """Expected workflow or input failure."""


@dataclass(frozen=True)
class Partition:
    label: str
    type: int
    subtype: int
    offset: int
    size: int
    encrypted: bool
    readonly: bool


@dataclass(frozen=True)
class ImagePlan:
    role: str
    label: str
    source: Path
    offset: int
    max_size: int
    sign: bool
    encrypt: bool
    stem: str


@dataclass(frozen=True)
class BuildContext:
    project_dir: Path
    build_dir: Path
    project_name: str
    project_version: str
    target: str
    python: Path
    app_elf: Path
    config: dict
    flasher_args: dict
    partitions: tuple[Partition, ...]


def parse_number(value: object, name: str) -> int:
    if isinstance(value, int):
        result = value
    elif isinstance(value, str):
        try:
            result = int(value, 0)
        except ValueError as error:
            raise WorkflowError(f"Invalid {name}: {value!r}") from error
    else:
        raise WorkflowError(f"Invalid {name}: {value!r}")
    if result < 0 or result > 0xFFFFFFFF:
        raise WorkflowError(f"{name} does not fit in an unsigned 32-bit value")
    return result


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(COPY_CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def same_file_content(first: Path, second: Path) -> bool:
    return first.stat().st_size == second.stat().st_size and sha256_file(first) == sha256_file(second)


def load_json(path: Path) -> dict:
    try:
        with path.open(encoding="utf-8") as stream:
            value = json.load(stream)
    except (OSError, json.JSONDecodeError) as error:
        raise WorkflowError(f"Unable to read {path}: {error}") from error
    if not isinstance(value, dict):
        raise WorkflowError(f"Expected a JSON object in {path}")
    return value


def parse_cmake_cache(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise WorkflowError(f"Unable to read {path}: {error}") from error
    for line in lines:
        if not line or line.startswith(("#", "//")) or "=" not in line:
            continue
        key_and_type, value = line.split("=", 1)
        key = key_and_type.split(":", 1)[0]
        values[key] = value
    return values


def parse_partition_table(path: Path) -> tuple[Partition, ...]:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise WorkflowError(f"Unable to read partition table {path}: {error}") from error
    partitions: list[Partition] = []
    for position in range(0, len(data) - PARTITION_ENTRY_SIZE + 1, PARTITION_ENTRY_SIZE):
        entry = data[position : position + PARTITION_ENTRY_SIZE]
        magic = entry[:2]
        if magic == b"\xff\xff" or magic == PARTITION_MD5_MAGIC:
            break
        if magic != PARTITION_MAGIC:
            raise WorkflowError(
                f"Invalid partition-table magic {magic.hex()} at file offset 0x{position:x}"
            )
        _, ptype, subtype, offset, size, raw_label, flags = struct.unpack("<2sBBLL16sL", entry)
        try:
            label = raw_label.split(b"\0", 1)[0].decode("utf-8")
        except UnicodeDecodeError as error:
            raise WorkflowError(f"Invalid partition label at file offset 0x{position:x}") from error
        if not label:
            raise WorkflowError(f"Empty partition label at file offset 0x{position:x}")
        partitions.append(
            Partition(
                label=label,
                type=ptype,
                subtype=subtype,
                offset=offset,
                size=size,
                encrypted=bool(flags & 1),
                readonly=bool(flags & 2),
            )
        )
    if not partitions:
        raise WorkflowError(f"No partitions found in {path}")
    return tuple(partitions)


def resolve_build_dir(project_dir: Path, build_dir: Path) -> Path:
    project_dir = project_dir.expanduser().resolve()
    build_dir = build_dir.expanduser()
    if not build_dir.is_absolute():
        build_dir = project_dir / build_dir
    return build_dir.resolve()


def load_build_context(project_dir: Path, build_dir: Path) -> BuildContext:
    project_dir = project_dir.expanduser().resolve()
    build_dir = resolve_build_dir(project_dir, build_dir)
    description = load_json(build_dir / "project_description.json")
    config = load_json(build_dir / "config" / "sdkconfig.json")
    flasher_args = load_json(build_dir / "flasher_args.json")
    cache = parse_cmake_cache(build_dir / "CMakeCache.txt")
    partitions = parse_partition_table(build_dir / "partition_table" / "partition-table.bin")

    recorded_build = Path(description.get("build_dir", "")).expanduser().resolve()
    if recorded_build != build_dir:
        raise WorkflowError(
            f"Build metadata belongs to {recorded_build}, not requested directory {build_dir}"
        )
    recorded_project = Path(description.get("project_path", "")).expanduser().resolve()
    if recorded_project != project_dir:
        raise WorkflowError(
            f"Build metadata belongs to project {recorded_project}, not {project_dir}"
        )
    target = description.get("target")
    if target != "esp32c5":
        raise WorkflowError(f"Unsupported target {target!r}; this tool currently guarantees ESP32-C5")
    if not config.get("SECURE_BOOT_V2_ENABLED"):
        raise WorkflowError("The build does not enable Secure Boot V2")
    if not config.get("SECURE_FLASH_ENC_ENABLED"):
        raise WorkflowError("The build does not enable flash encryption")

    python_text = cache.get("PYTHON")
    if not python_text:
        raise WorkflowError(f"PYTHON is missing from {build_dir / 'CMakeCache.txt'}")
    # Preserve the exact virtual-environment path recorded by ESP-IDF. Calling
    # Path.resolve() here can follow it to the base interpreter and thereby lose
    # the environment which provides espsecure and esptool.
    python = Path(python_text).expanduser()
    if not python.is_absolute():
        python = (build_dir / python).absolute()
    if not python.is_file():
        raise WorkflowError(f"Build-recorded Python does not exist: {python}")

    app_elf_value = description.get("app_elf")
    if not isinstance(app_elf_value, str) or not app_elf_value:
        raise WorkflowError("Application ELF is missing from project_description.json")
    app_elf = Path(app_elf_value)
    if not app_elf.is_absolute():
        app_elf = build_dir / app_elf

    return BuildContext(
        project_dir=project_dir,
        build_dir=build_dir,
        project_name=str(description.get("project_name", "application")),
        project_version=str(description.get("project_version", "")),
        target=target,
        python=python,
        app_elf=app_elf.resolve(),
        config=config,
        flasher_args=flasher_args,
        partitions=partitions,
    )


def signing_scheme(config: dict) -> str:
    rsa = bool(config.get("SECURE_SIGNED_APPS_RSA_SCHEME"))
    ecdsa = bool(config.get("SECURE_SIGNED_APPS_ECDSA_V2_SCHEME"))
    if rsa == ecdsa:
        raise WorkflowError("Expected exactly one Secure Boot V2 signing scheme")
    return "rsa" if rsa else "ecdsa-v2"


def resolve_keys(
    config: dict,
    key_dir_arg: str | None,
    signing_key_arg: str | None,
    encryption_key_arg: str | None,
) -> tuple[str, Path, Path]:
    scheme = signing_scheme(config)
    script_dir = Path(__file__).resolve().parent
    key_dir = Path(
        key_dir_arg or os.environ.get("SECURITY_WORKFLOW_DIR", str(script_dir))
    ).expanduser().resolve()
    default_signing_name = (
        "secure_boot_signing_key_rsa.pem"
        if scheme == "rsa"
        else "secure_boot_signing_key_ecdsa.pem"
    )
    signing_key = Path(
        signing_key_arg
        or os.environ.get("SECURE_BOOT_SIGNING_KEY", str(key_dir / default_signing_name))
    ).expanduser().resolve()
    encryption_key = Path(
        encryption_key_arg
        or os.environ.get("FLASH_ENCRYPTION_KEY", str(key_dir / "my_flash_encryption_key.bin"))
    ).expanduser().resolve()
    for description, path in (
        ("secure-boot signing key", signing_key),
        ("flash-encryption key", encryption_key),
    ):
        if not path.is_file():
            raise WorkflowError(f"Missing {description}: {path}")
    if encryption_key.stat().st_size not in (32, 64):
        raise WorkflowError(
            f"Unexpected AES-XTS key length {encryption_key.stat().st_size} in {encryption_key}"
        )
    return scheme, signing_key, encryption_key


def partition_by_label(partitions: Sequence[Partition], label: str) -> Partition:
    matches = [partition for partition in partitions if partition.label == label]
    if len(matches) != 1:
        raise WorkflowError(f"Partition label {label!r} resolved to {len(matches)} entries")
    return matches[0]


def partition_at(partitions: Sequence[Partition], offset: int, ptype: int | None = None) -> Partition:
    matches = [
        partition
        for partition in partitions
        if partition.offset == offset and (ptype is None or partition.type == ptype)
    ]
    if len(matches) != 1:
        raise WorkflowError(f"Flash offset 0x{offset:x} resolved to {len(matches)} partitions")
    return matches[0]


def parse_partition_images(values: Sequence[str], build_dir: Path) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        if "=" not in value:
            raise WorkflowError(
                f"Invalid --partition-image {value!r}; expected PARTITION_LABEL=FILE"
            )
        label, filename = value.split("=", 1)
        if not label or not filename:
            raise WorkflowError(
                f"Invalid --partition-image {value!r}; expected PARTITION_LABEL=FILE"
            )
        if label in result:
            raise WorkflowError(f"Duplicate --partition-image mapping for {label!r}")
        path = Path(filename).expanduser()
        if not path.is_absolute():
            path = build_dir / path
        result[label] = path.resolve()
    return result


def make_image_plans(context: BuildContext, custom_images: dict[str, Path]) -> list[ImagePlan]:
    config = context.config
    build_dir = context.build_dir
    boot_offset = parse_number(config.get("BOOTLOADER_OFFSET_IN_FLASH"), "bootloader offset")
    table_offset = parse_number(config.get("PARTITION_TABLE_OFFSET"), "partition-table offset")
    first_partition_offset = min(partition.offset for partition in context.partitions)
    if not boot_offset < table_offset < first_partition_offset:
        raise WorkflowError("Generated bootloader/partition-table layout is inconsistent")

    app_info = context.flasher_args.get("app")
    if not isinstance(app_info, dict):
        raise WorkflowError("Application entry is missing from flasher_args.json")
    app_offset = parse_number(app_info.get("offset"), "application offset")
    app_file = app_info.get("file")
    if not isinstance(app_file, str) or not app_file:
        raise WorkflowError("Application file is missing from flasher_args.json")
    app_partition = partition_at(context.partitions, app_offset, APP_PARTITION_TYPE)

    table_info = context.flasher_args.get("partition-table")
    table_file = (
        table_info.get("file")
        if isinstance(table_info, dict)
        else "partition_table/partition-table.bin"
    )
    if not isinstance(table_file, str) or not table_file:
        raise WorkflowError("Partition-table file is missing from flasher_args.json")

    plans = [
        ImagePlan(
            role="bootloader",
            label="bootloader",
            source=(build_dir / "bootloader" / "bootloader.bin").resolve(),
            offset=boot_offset,
            max_size=table_offset - boot_offset,
            sign=True,
            encrypt=True,
            stem="bootloader",
        ),
        ImagePlan(
            role="partition-table",
            label="partition-table",
            source=(build_dir / table_file).resolve(),
            offset=table_offset,
            max_size=first_partition_offset - table_offset,
            sign=False,
            encrypt=True,
            stem="partition-table",
        ),
        ImagePlan(
            role="application",
            label=app_partition.label,
            source=(build_dir / app_file).resolve(),
            offset=app_offset,
            max_size=app_partition.size,
            sign=True,
            encrypt=True,
            stem=context.project_name,
        ),
    ]

    automatic_labels = {plan.label for plan in plans}
    for label, source in custom_images.items():
        if label in automatic_labels:
            raise WorkflowError(f"Partition {label!r} is already handled automatically")
        partition = partition_by_label(context.partitions, label)
        plans.append(
            ImagePlan(
                role="custom-partition",
                label=label,
                source=source,
                offset=partition.offset,
                max_size=partition.size,
                sign=partition.type == APP_PARTITION_TYPE,
                encrypt=partition.type == APP_PARTITION_TYPE or partition.encrypted,
                stem=label,
            )
        )

    plans.sort(key=lambda plan: plan.offset)
    seen_offsets: set[int] = set()
    for plan in plans:
        if plan.offset in seen_offsets:
            raise WorkflowError(f"Multiple images start at flash offset 0x{plan.offset:x}")
        seen_offsets.add(plan.offset)
        if not plan.source.is_file():
            raise WorkflowError(f"Missing input image for {plan.label}: {plan.source}")
        if plan.source.stat().st_size == 0:
            raise WorkflowError(f"Input image is empty: {plan.source}")
        if plan.source.stat().st_size > plan.max_size:
            raise WorkflowError(
                f"{plan.source} is larger than the 0x{plan.max_size:x}-byte region for {plan.label}"
            )
    return plans


def shell_command(command: Sequence[object]) -> str:
    return shlex.join(str(value) for value in command)


def run_command(command: Sequence[object], cwd: Path, dry_run: bool = False) -> None:
    rendered = shell_command(command)
    print(f"+ {rendered}")
    if dry_run:
        return
    try:
        subprocess.run([str(value) for value in command], cwd=cwd, check=True)
    except FileNotFoundError as error:
        raise WorkflowError(f"Command not found: {command[0]}") from error
    except subprocess.CalledProcessError as error:
        raise WorkflowError(f"Command failed with exit code {error.returncode}: {rendered}") from error


def fill_bytes(stream, count: int, value: int = 0xFF) -> None:
    block = bytes([value]) * min(COPY_CHUNK_SIZE, max(count, 1))
    while count:
        size = min(count, len(block))
        stream.write(block[:size])
        count -= size


def merge_images(parts: Sequence[tuple[int, Path]], output: Path) -> int:
    position = 0
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as destination:
        for offset, source in sorted(parts):
            if offset < position:
                raise WorkflowError(
                    f"Image {source} at 0x{offset:x} overlaps the preceding secured image"
                )
            fill_bytes(destination, offset - position)
            with source.open("rb") as input_stream:
                shutil.copyfileobj(input_stream, destination, COPY_CHUNK_SIZE)
            position = offset + source.stat().st_size
    output.chmod(0o600)
    return position


def split_merged_image(merged: Path, first: Path, second: Path) -> None:
    if merged.stat().st_size <= SPLIT_BOUNDARY:
        raise WorkflowError("Split requested for an image which does not cross 16 MiB")
    with merged.open("rb") as source, first.open("wb") as first_stream:
        remaining = SPLIT_BOUNDARY
        while remaining:
            chunk = source.read(min(COPY_CHUNK_SIZE, remaining))
            if not chunk:
                raise WorkflowError("Merged image ended before the 16 MiB split boundary")
            first_stream.write(chunk)
            remaining -= len(chunk)
        with second.open("wb") as second_stream:
            shutil.copyfileobj(source, second_stream, COPY_CHUNK_SIZE)
    first.chmod(0o600)
    second.chmod(0o600)
    if first.stat().st_size != SPLIT_BOUNDARY or second.stat().st_size == 0:
        raise WorkflowError("Generated split files have invalid sizes")


def record_path(path: Path, base: Path) -> str:
    try:
        return str(path.resolve().relative_to(base.resolve()))
    except ValueError:
        return str(path.resolve())


def file_record(path: Path, base: Path) -> dict:
    return {
        "path": record_path(path, base),
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def validate_label(label: str | None) -> str | None:
    if label is not None and not LABEL_RE.fullmatch(label):
        raise WorkflowError("--label may contain only letters, digits, '.', '_', and '-'")
    return label


def publish_staging(staging: Path, destination: Path) -> None:
    backup = destination.parent / f".{destination.name}.backup-{uuid.uuid4().hex}"
    had_destination = destination.exists()
    try:
        if had_destination:
            os.replace(destination, backup)
        os.replace(staging, destination)
    except Exception:
        if had_destination and backup.exists() and not destination.exists():
            os.replace(backup, destination)
        raise
    else:
        if backup.exists():
            shutil.rmtree(backup)


def package_build(args: argparse.Namespace) -> Path:
    project_dir = Path(args.project_dir)
    build_dir = resolve_build_dir(project_dir, Path(args.build_dir))
    context = load_build_context(project_dir, build_dir)
    custom_images = parse_partition_images(args.partition_image, context.build_dir)
    plans = make_image_plans(context, custom_images)
    scheme, signing_key, encryption_key = resolve_keys(
        context.config, args.key_dir, args.signing_key, args.encryption_key
    )
    label = validate_label(args.label)

    print(f"Project: {context.project_name} {context.project_version}")
    print(f"Build directory: {context.build_dir}")
    print(f"Target/signing: {context.target}/{scheme}")
    for plan in plans:
        operations = "+".join(
            operation
            for operation, enabled in (("sign", plan.sign), ("encrypt", plan.encrypt))
            if enabled
        ) or "copy"
        print(
            f"  0x{plan.offset:08x} {plan.source.name} ({operations}, max 0x{plan.max_size:x})"
        )
    if args.dry_run:
        preview_dir = context.build_dir / "secured"
        for plan in plans:
            current = plan.source
            if plan.sign:
                signed = preview_dir / f"{plan.stem}-signed.bin"
                print(
                    "+ "
                    + shell_command(
                        [
                            context.python,
                            "-m",
                            "espsecure",
                            "sign_data",
                            "--version",
                            "2",
                            "--keyfile",
                            signing_key,
                            "--output",
                            signed,
                            current,
                        ]
                    )
                )
                print(
                    "+ "
                    + shell_command(
                        [
                            context.python,
                            "-m",
                            "espsecure",
                            "verify_signature",
                            "--version",
                            "2",
                            "--keyfile",
                            signing_key,
                            signed,
                        ]
                    )
                )
                current = signed
            if plan.encrypt:
                encrypted = preview_dir / f"{plan.stem}-encrypted.bin"
                check = preview_dir / f".{plan.stem}-decrypted-check.bin"
                for action, input_path, output_path in (
                    ("encrypt_flash_data", current, encrypted),
                    ("decrypt_flash_data", encrypted, check),
                ):
                    print(
                        "+ "
                        + shell_command(
                            [
                                context.python,
                                "-m",
                                "espsecure",
                                action,
                                "--aes_xts",
                                "--keyfile",
                                encryption_key,
                                "--address",
                                hex(plan.offset),
                                "--output",
                                output_path,
                                input_path,
                            ]
                        )
                    )
        print("Dry run: no secured artifacts were written.")
        return context.build_dir / "secured" / "manifest.json"

    staging = context.build_dir / f".secured-staging-{uuid.uuid4().hex}"
    destination = context.build_dir / "secured"
    staging.mkdir(mode=0o700)
    output_records: list[dict] = []
    flash_parts: list[dict] = []
    try:
        for plan in plans:
            current = plan.source
            transformations: list[str] = []
            if plan.sign:
                signed = staging / f"{plan.stem}-signed.bin"
                run_command(
                    [
                        context.python,
                        "-m",
                        "espsecure",
                        "sign_data",
                        "--version",
                        "2",
                        "--keyfile",
                        signing_key,
                        "--output",
                        signed,
                        current,
                    ],
                    context.project_dir,
                )
                run_command(
                    [
                        context.python,
                        "-m",
                        "espsecure",
                        "verify_signature",
                        "--version",
                        "2",
                        "--keyfile",
                        signing_key,
                        signed,
                    ],
                    context.project_dir,
                )
                signed.chmod(0o600)
                current = signed
                transformations.append("secure-boot-v2-sign")
                output_records.append({"kind": "signed", **file_record(signed, staging)})

            if plan.encrypt:
                encrypted = staging / f"{plan.stem}-encrypted.bin"
                decrypted_check = staging / f".{plan.stem}-decrypted-check.bin"
                run_command(
                    [
                        context.python,
                        "-m",
                        "espsecure",
                        "encrypt_flash_data",
                        "--aes_xts",
                        "--keyfile",
                        encryption_key,
                        "--address",
                        hex(plan.offset),
                        "--output",
                        encrypted,
                        current,
                    ],
                    context.project_dir,
                )
                run_command(
                    [
                        context.python,
                        "-m",
                        "espsecure",
                        "decrypt_flash_data",
                        "--aes_xts",
                        "--keyfile",
                        encryption_key,
                        "--address",
                        hex(plan.offset),
                        "--output",
                        decrypted_check,
                        encrypted,
                    ],
                    context.project_dir,
                )
                if not same_file_content(current, decrypted_check):
                    raise WorkflowError(f"Encryption round-trip failed for {plan.label}")
                decrypted_check.unlink()
                encrypted.chmod(0o600)
                current = encrypted
                transformations.append("aes-xts-encrypt")
                output_records.append({"kind": "encrypted", **file_record(encrypted, staging)})
            elif current == plan.source:
                copied = staging / f"{plan.stem}.bin"
                shutil.copyfile(current, copied)
                copied.chmod(0o600)
                current = copied
                transformations.append("copy")
                output_records.append({"kind": "copied", **file_record(copied, staging)})

            if current.stat().st_size > plan.max_size:
                raise WorkflowError(
                    f"Secured {plan.label} image is 0x{current.stat().st_size:x} bytes, "
                    f"larger than its 0x{plan.max_size:x}-byte region"
                )
            flash_parts.append(
                {
                    "role": plan.role,
                    "label": plan.label,
                    "offset": plan.offset,
                    "max_size": plan.max_size,
                    "file": current.name,
                    "size": current.stat().st_size,
                    "sha256": sha256_file(current),
                    "transformations": transformations,
                }
            )

        merged_size_hint = max(part["offset"] + part["size"] for part in flash_parts)
        merged_name = f"{context.project_name}-merged-secured"
        if merged_size_hint == 20 * 1024 * 1024:
            merged_name += "-20MiB"
        if label:
            merged_name += f"-{label}"
        merged = staging / f"{merged_name}.bin"
        merged_size = merge_images(
            [(part["offset"], staging / part["file"]) for part in flash_parts], merged
        )
        if merged_size != merged_size_hint:
            raise WorkflowError("Merged image size does not match its planned extent")
        output_records.append({"kind": "merged", **file_record(merged, staging)})

        split_records: list[dict] = []
        if merged_size > SPLIT_BOUNDARY:
            part1 = staging / f"{merged_name}.part1.bin"
            part2 = staging / f"{merged_name}.part2.bin"
            split_merged_image(merged, part1, part2)
            split_records = [
                {"offset": 0, **file_record(part1, staging)},
                {"offset": SPLIT_BOUNDARY, **file_record(part2, staging)},
            ]
            output_records.extend(
                [
                    {"kind": "split", **file_record(part1, staging)},
                    {"kind": "split", **file_record(part2, staging)},
                ]
            )

        inputs = [
            {
                "role": plan.role,
                "label": plan.label,
                **file_record(plan.source, context.build_dir),
            }
            for plan in plans
        ]
        flash_settings = context.flasher_args.get("flash_settings", {})
        extra_esptool = context.flasher_args.get("extra_esptool_args", {})
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "project_dir": str(context.project_dir),
            "build_dir": str(context.build_dir),
            "project_name": context.project_name,
            "project_version": context.project_version,
            "target": context.target,
            "signing_scheme": scheme,
            "build_python": str(context.python),
            "app_elf": file_record(context.app_elf, context.build_dir),
            "keys": {
                "signing": {"name": signing_key.name, "sha256": sha256_file(signing_key)},
                "encryption": {
                    "name": encryption_key.name,
                    "sha256": sha256_file(encryption_key),
                },
            },
            "inputs": inputs,
            "outputs": output_records,
            "flash_parts": flash_parts,
            "merged": file_record(merged, staging),
            "split": split_records,
            "flash_settings": flash_settings,
            "extra_esptool_args": extra_esptool,
        }
        manifest_path = staging / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        manifest_path.chmod(0o600)
        publish_staging(staging, destination)
    except Exception:
        if staging.exists():
            shutil.rmtree(staging)
        raise

    manifest_path = destination / "manifest.json"
    print(f"Secured package: {destination}")
    print(f"Manifest: {manifest_path}")
    return manifest_path


def resolve_record_path(value: str, base: Path) -> Path:
    path = Path(value).expanduser()
    return path.resolve() if path.is_absolute() else (base / path).resolve()


def validate_record(record: dict, base: Path, description: str) -> Path:
    try:
        path = resolve_record_path(record["path"], base)
        expected_size = int(record["size"])
        expected_sha = str(record["sha256"])
    except (KeyError, TypeError, ValueError) as error:
        raise WorkflowError(f"Malformed {description} record in manifest") from error
    if not path.is_file():
        raise WorkflowError(f"Missing {description}: {path}")
    if path.stat().st_size != expected_size or sha256_file(path) != expected_sha:
        raise WorkflowError(f"{description} is stale or modified: {path}")
    return path


def load_and_validate_manifest(project_dir: Path, build_dir: Path) -> tuple[dict, Path]:
    build_dir = resolve_build_dir(project_dir, build_dir)
    secured_dir = build_dir / "secured"
    manifest = load_json(secured_dir / "manifest.json")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise WorkflowError(f"Unsupported manifest schema {manifest.get('schema_version')!r}")
    if Path(str(manifest.get("build_dir", ""))).resolve() != build_dir:
        raise WorkflowError("Manifest belongs to a different build directory")
    for index, record in enumerate(manifest.get("inputs", [])):
        validate_record(record, build_dir, f"input #{index + 1}")
    validate_record(manifest.get("app_elf", {}), build_dir, "application ELF")
    for index, record in enumerate(manifest.get("outputs", [])):
        validate_record(record, secured_dir, f"secured output #{index + 1}")
    return manifest, secured_dir


def tcl_path(path: Path) -> str:
    text = str(path.resolve()).replace("\\", "/")
    return "{" + text.replace("}", "\\}") + "}"


def openocd_program_command(
    path: Path,
    offset: int,
    verify: bool,
    compress: bool,
    final: bool,
) -> str:
    values = ["program_esp", tcl_path(path), hex(offset)]
    if verify:
        values.append("verify")
    if compress:
        values.append("compress")
    if final:
        values.extend(("reset", "exit"))
    return " ".join(values)


def make_esptool_flash_command(args: argparse.Namespace, manifest: dict, secured_dir: Path) -> list[str]:
    if not args.port:
        raise WorkflowError("--port is required for the esptool interface")
    python = Path(str(manifest.get("build_python", ""))).expanduser()
    if not python.is_file():
        raise WorkflowError(f"Build-recorded Python does not exist: {python}")
    command = [str(python), "-m", "esptool", "--chip", str(manifest["target"]), "--port", args.port]
    if args.baud is not None:
        command.extend(("--baud", str(args.baud)))
    extra = manifest.get("extra_esptool_args", {})
    before = extra.get("before")
    after = extra.get("after")
    if before:
        command.extend(("--before", str(before)))
    if after:
        command.extend(("--after", str(after)))
    if extra.get("stub") is False:
        command.append("--no-stub")
    command.extend(("write_flash", "--force"))
    settings = manifest.get("flash_settings", {})
    for option, key in (
        ("--flash_mode", "flash_mode"),
        ("--flash_size", "flash_size"),
        ("--flash_freq", "flash_freq"),
    ):
        if settings.get(key):
            command.extend((option, str(settings[key])))
    for part in sorted(manifest["flash_parts"], key=lambda item: int(item["offset"])):
        path = secured_dir / str(part["file"])
        command.extend((hex(int(part["offset"])), str(path)))
    return command


def make_openocd_flash_command(args: argparse.Namespace, manifest: dict, secured_dir: Path) -> list[str]:
    command = [args.openocd, "-f", args.openocd_config]
    split = manifest.get("split", [])
    if split:
        records = sorted(split, key=lambda item: int(item["offset"]))
    else:
        merged = manifest.get("merged")
        if not isinstance(merged, dict):
            raise WorkflowError("Merged image is missing from manifest")
        records = [{"offset": 0, **merged}]
    for index, record in enumerate(records):
        path = validate_record(record, secured_dir, f"OpenOCD image #{index + 1}")
        command.extend(
            (
                "-c",
                openocd_program_command(
                    path,
                    int(record["offset"]),
                    args.verify,
                    args.compress,
                    index == len(records) - 1,
                ),
            )
        )
    return command


def confirm_flash(skip: bool) -> None:
    if skip:
        return
    try:
        token = input("This writes flash. Type FLASH to continue: ")
    except (EOFError, KeyboardInterrupt):
        print()
        raise WorkflowError("Flashing cancelled")
    if token != "FLASH":
        raise WorkflowError("Flashing cancelled")


def flash_package(args: argparse.Namespace) -> None:
    project_dir = Path(args.project_dir).expanduser().resolve()
    manifest, secured_dir = load_and_validate_manifest(
        project_dir, Path(args.build_dir)
    )
    if args.interface == "esptool":
        command = make_esptool_flash_command(args, manifest, secured_dir)
    else:
        if args.port:
            raise WorkflowError("--port is valid only for the esptool interface")
        command = make_openocd_flash_command(args, manifest, secured_dir)
    print("Flash command:")
    print(f"  {shell_command(command)}")
    if args.dry_run:
        print("Dry run: flash was not modified.")
        return
    confirm_flash(args.yes)
    run_command(command, project_dir)


def build_project(args: argparse.Namespace) -> None:
    project_dir = Path(args.project_dir).expanduser().resolve()
    build_dir = resolve_build_dir(project_dir, Path(args.build_dir))
    if args.idf_py:
        command: list[str] = [args.idf_py]
    else:
        idf_py = shutil.which("idf.py")
        if not idf_py:
            raise WorkflowError("idf.py is not on PATH; activate ESP-IDF or use --idf-py")
        # The tool is normally launched with `python` from the activated IDF
        # environment. Use that interpreter explicitly so an idf.py shebang
        # cannot accidentally select a system Python outside the environment.
        command = [sys.executable, idf_py]
    command.extend(("-B", str(build_dir)))
    for definition in args.idf_define:
        if "=" not in definition:
            raise WorkflowError(f"Invalid --idf-define {definition!r}; expected NAME=VALUE")
        command.extend(("-D", definition))
    command.append("build")
    run_command(command, project_dir, args.dry_run)


def add_project_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--project-dir", default=".", help="ESP-IDF project directory (default: current directory)")
    parser.add_argument("--build-dir", default="build", help="build directory, relative to project directory")


def add_package_options(parser: argparse.ArgumentParser) -> None:
    add_project_options(parser)
    parser.add_argument(
        "--partition-image",
        action="append",
        default=[],
        metavar="LABEL=FILE",
        help="map a custom partition label to an image; relative files are inside the build directory",
    )
    parser.add_argument("--label", help="optional filename-safe merged-image label")
    parser.add_argument("--key-dir", help="directory containing default key filenames")
    parser.add_argument("--signing-key", help="override secure-boot signing key")
    parser.add_argument("--encryption-key", help="override AES-XTS flash-encryption key")
    parser.add_argument("--dry-run", action="store_true", help="show actions without producing artifacts")


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    package_parser = subparsers.add_parser("package", help="securely package an existing ESP-IDF build")
    add_package_options(package_parser)

    build_parser = subparsers.add_parser("build-package", help="run idf.py build, then securely package it")
    add_package_options(build_parser)
    build_parser.add_argument(
        "--idf-define",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="repeatable CMake cache definition passed to idf.py",
    )
    build_parser.add_argument(
        "--idf-py",
        help="override the idf.py executable (default: idf.py from PATH using the active Python)",
    )

    flash_parser = subparsers.add_parser("flash", help="flash a validated secured package")
    add_project_options(flash_parser)
    flash_parser.add_argument("--interface", choices=("esptool", "openocd"), required=True)
    flash_parser.add_argument("--port", help="serial port; required for esptool")
    flash_parser.add_argument("--baud", type=int, help="optional esptool baud rate")
    flash_parser.add_argument("--openocd", default="openocd", help="OpenOCD executable")
    flash_parser.add_argument(
        "--openocd-config",
        default="board/esp32c5-builtin.cfg",
        help="OpenOCD configuration (default: board/esp32c5-builtin.cfg)",
    )
    flash_parser.add_argument("--verify", action="store_true", help="add OpenOCD post-write verification")
    flash_parser.add_argument("--compress", action="store_true", help="add OpenOCD transfer compression")
    flash_parser.add_argument("--yes", action="store_true", help="skip the FLASH confirmation")
    flash_parser.add_argument("--dry-run", action="store_true", help="validate and print without flashing")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "build-package":
            build_project(args)
            if args.dry_run:
                project_dir = Path(args.project_dir)
                build_dir = resolve_build_dir(project_dir, Path(args.build_dir))
                if not (build_dir / "project_description.json").is_file():
                    print("Dry run: packaging plan is unavailable until the build metadata exists.")
                    return 0
            package_build(args)
        elif args.command == "package":
            package_build(args)
        else:
            flash_package(args)
    except WorkflowError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
