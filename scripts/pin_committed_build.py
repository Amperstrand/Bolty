Import("env")

from pathlib import Path
import io
import shutil
import subprocess
import tarfile


PROJECT_DIR = Path(env["PROJECT_DIR"])
PROJECT_REPO = PROJECT_DIR
PIOENV = env["PIOENV"]
LIB_SOURCE_REPO = Path("/home/ubuntu/src/pn532/Adafruit-PN532-NTAG424")
LIB_NAME = "Adafruit PN532 NTAG424"
PINNED_LIB_DIR = PROJECT_DIR / ".pio" / "libdeps" / PIOENV / LIB_NAME
PINNED_LIB_BUILD_DIR = PROJECT_DIR / ".pio" / "build" / PIOENV / "libeac" / LIB_NAME
BUILD_METADATA = PROJECT_DIR / "include" / "build_metadata.h"


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def require_clean_project_repo() -> None:
    status = git(PROJECT_REPO, "status", "--porcelain", "--untracked-files=no")
    if status:
        raise RuntimeError(
            "Bolty build is pinned to committed code only. Commit tracked changes before building.\n"
            + status
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


def get_commit_timestamp(repo: Path) -> int:
    """Return the Unix timestamp (seconds) of the HEAD commit.

    This is used as FW_VERSION_CODE — an integer that increases monotonically
    with every new commit, enabling the OTA client to compare versions without
    any manual version-bump discipline.
    """
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
bolty_commit = git(PROJECT_REPO, "rev-parse", "HEAD")
fw_version_code = get_commit_timestamp(PROJECT_REPO)
pn532_commit = export_git_head(LIB_SOURCE_REPO, PINNED_LIB_DIR)
if PINNED_LIB_BUILD_DIR.exists():
    shutil.rmtree(PINNED_LIB_BUILD_DIR)
write_build_metadata(bolty_commit, pn532_commit, fw_version_code)
