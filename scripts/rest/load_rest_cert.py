"""PlatformIO pre-build script: embed REST server TLS certificate + private key.

Reads scripts/rest/certs/rest_server_cert.pem and rest_server_key.pem,
generates include/rest_server_cert.h with embedded PEM strings.

Run scripts/rest/generate_rest_cert.sh first to create the PEM files.
"""
from pathlib import Path
from typing import Any, cast


def _embed_pem(pem_text: str, var_name: str) -> str:
    return (
        'static const char {var}[] = R"BOLTYREST(\n'.format(var=var_name)
        + pem_text
        + ')BOLTYREST";\n'
    )


Import("env")  # type: ignore[name-defined]
env = cast(Any, globals()["env"])

project_dir = Path(env["PROJECT_DIR"])
cert_dir = project_dir / "scripts" / "rest" / "certs"
server_cert = cert_dir / "rest_server_cert.pem"
server_key = cert_dir / "rest_server_key.pem"
header_path = project_dir / "include" / "rest_server_cert.h"

if not server_cert.exists() or not server_key.exists():
    raise FileNotFoundError(
        "REST server TLS files not found in %s. "
        "Run scripts/rest/generate_rest_cert.sh first." % cert_dir
    )

cert_pem = server_cert.read_text(encoding="utf-8")
key_pem = server_key.read_text(encoding="utf-8")

header = (
    "#ifndef REST_SERVER_CERT_H\n"
    "#define REST_SERVER_CERT_H\n\n"
    + _embed_pem(cert_pem, "REST_SERVER_CERT_PEM")
    + "\n"
    + _embed_pem(key_pem, "REST_SERVER_KEY_PEM")
    + "\n"
    "#endif\n"
)

header_path.parent.mkdir(parents=True, exist_ok=True)
header_path.write_text(header, encoding="utf-8")
print("REST: embedded server certificate from %s" % cert_dir)
