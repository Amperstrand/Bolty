from pathlib import Path
from typing import Any, cast


def stringify_raw_pem(pem_text: str) -> str:
    return (
        "#ifndef OTA_CA_CERT_H\n"
        "#define OTA_CA_CERT_H\n\n"
        "static const char OTA_CA_CERT_PEM[] = R\"BOLTYCERT(\n"
        + pem_text
        + ")BOLTYCERT\";\n\n"
        "#endif\n"
    )


Import("env")  # type: ignore[name-defined]
env = cast(Any, globals()["env"])

project_dir = Path(env["PROJECT_DIR"])
ca_cert = project_dir / "scripts" / "ota" / "certs" / "ota_ca_cert.pem"
header_path = project_dir / "include" / "ota_ca_cert.h"

if not ca_cert.exists():
    raise FileNotFoundError(
        f"OTA CA certificate not found at {ca_cert}. "
        "Run scripts/ota/generate_https_cert.sh first."
    )

header_path.parent.mkdir(parents=True, exist_ok=True)
header_path.write_text(stringify_raw_pem(ca_cert.read_text(encoding="utf-8")), encoding="utf-8")
print(f"OTA: embedded CA certificate from {ca_cert}")
