from typing import Any, cast

Import("env")  # type: ignore[name-defined]
env = cast(Any, globals()["env"])

import os
from pathlib import Path
import io
import shutil
import subprocess
import tarfile
import serial.tools.list_ports


PROJECT_DIR = Path(env["PROJECT_DIR"])
PROJECT_REPO = PROJECT_DIR
PIOENV = env["PIOENV"]
LIB_SOURCE_REPO = Path("/home/ubuntu/src/pn532/Adafruit-PN532-NTAG424")
LIB_NAME = "Adafruit PN532 NTAG424"
PINNED_LIB_DIR = PROJECT_DIR / ".pio" / "libdeps" / PIOENV / LIB_NAME
PINNED_LIB_BUILD_DIR = PROJECT_DIR / ".pio" / "build" / PIOENV / "libeac" / LIB_NAME
BUILD_METADATA = PROJECT_DIR / "include" / "build_metadata.h"

EXPECTED_PORTS = {
    "m5stack-atom-mfrc522": {
        "path": "/dev/serial/by-id/usb-M5STACK_Inc._M5_Serial_Converter_9D529068B4-if00-port0",
        "vid": 0x0403,
        "pid": 0x6001,
        "serial_number": "9D529068B4",
        "description_substring": "M5 Serial Converter",
    },
}


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def require_clean_project_repo() -> None:
    if os.environ.get("BOLTY_ALLOW_DIRTY_BUILD") == "1":
        print("Warning: allowing dirty Bolty build for local validation")
        return
    status = git(PROJECT_REPO, "status", "--porcelain", "--untracked-files=no")
    if status:
        raise RuntimeError(
            "Bolty build is pinned to committed code only. Commit tracked changes before building.\n"
            + status
        )


def require_expected_upload_device() -> None:
    expected = EXPECTED_PORTS.get(PIOENV)
    if expected is None:
        return
    if os.environ.get("BOLTY_SKIP_DEVICE_CHECK") == "1":
        print("Warning: skipping Bolty upload device verification")
        return

    expected_path = expected["path"]
    if not Path(expected_path).exists():
        raise RuntimeError(
            f"Expected upload device not found for {PIOENV}: {expected_path}"
        )

    matching_port = None
    for port in serial.tools.list_ports.comports():
        if port.device == expected_path or port.device == os.path.realpath(expected_path):
            matching_port = port
            break

    if matching_port is None:
        raise RuntimeError(
            f"Expected upload device {expected_path} is present but was not enumerated by pyserial"
        )

    if matching_port.vid != expected["vid"] or matching_port.pid != expected["pid"]:
        raise RuntimeError(
            f"Unexpected USB VID:PID for {expected_path}: "
            f"got {matching_port.vid:04x}:{matching_port.pid:04x}, "
            f"expected {expected['vid']:04x}:{expected['pid']:04x}"
        )

    if matching_port.serial_number != expected["serial_number"]:
        raise RuntimeError(
            f"Unexpected USB serial for {expected_path}: "
            f"got {matching_port.serial_number}, expected {expected['serial_number']}"
        )

    description = matching_port.description or ""
    if expected["description_substring"] not in description:
        raise RuntimeError(
            f"Unexpected upload device description for {expected_path}: {description}"
        )

    print(
        "Verified upload device:",
        matching_port.device,
        f"({description}, {matching_port.hwid})",
    )


def export_git_head(repo: Path, destination: Path) -> str:
    commit = git(repo, "rev-parse", "HEAD")
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True, exist_ok=True)

    archive = subprocess.run(
        ["git", "archive", "--format=tar", "HEAD"],
        cwd=repo,
        check=True,
        capture_output=True,
    ).stdout

    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        tar.extractall(destination)

    return commit


def export_worktree(repo: Path, destination: Path) -> str:
    commit = git(repo, "rev-parse", "HEAD")
    dirty = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    if destination.exists():
        shutil.rmtree(destination)

    shutil.copytree(
        repo,
        destination,
        ignore=shutil.ignore_patterns(
            ".git",
            ".pio",
            "__pycache__",
            "*.pyc",
            "*.pyo",
        ),
    )

    return commit + ("-dirty" if dirty else "")


def get_commit_timestamp(repo: Path) -> int:
    ts = git(repo, "log", "-1", "--format=%ct")
    return int(ts)


def write_build_metadata(bolty_commit: str, pn532_commit: str, fw_version_code: int) -> None:
    BUILD_METADATA.parent.mkdir(parents=True, exist_ok=True)
    BUILD_METADATA.write_text(
        "#ifndef BUILD_METADATA_H\n"
        "#define BUILD_METADATA_H\n\n"
        f'#define BOLTY_GIT_COMMIT "{bolty_commit}"\n'
        f'#define PN532_LIB_GIT_COMMIT "{pn532_commit}"\n'
        f"#define FW_VERSION_CODE {fw_version_code}UL\n\n"
        "#endif\n",
        encoding="utf-8",
    )


require_clean_project_repo()
require_expected_upload_device()
bolty_commit = git(PROJECT_REPO, "rev-parse", "HEAD")
fw_version_code = get_commit_timestamp(PROJECT_REPO)
if os.environ.get("BOLTY_ALLOW_DIRTY_BUILD") == "1":
    pn532_commit = export_worktree(LIB_SOURCE_REPO, PINNED_LIB_DIR)
else:
    pn532_commit = export_git_head(LIB_SOURCE_REPO, PINNED_LIB_DIR)
if PINNED_LIB_BUILD_DIR.exists():
    shutil.rmtree(PINNED_LIB_BUILD_DIR)
write_build_metadata(bolty_commit, pn532_commit, fw_version_code)
