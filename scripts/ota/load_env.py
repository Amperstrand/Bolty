import os
from pathlib import Path
from typing import Any, cast

env_file = Path(os.environ.get("PROJECT_DIR", ".")) / "ota.env"

if not env_file.exists():
    try:
        Import("env")  # type: ignore[name-defined]
        env = cast(Any, globals()["env"])
        env_file = Path(env["PROJECT_DIR"]) / "ota.env"
    except NameError:
        pass

if not env_file.exists():
    raise FileNotFoundError(
        f"ota.env not found at {env_file}. Copy ota.env.example to ota.env and fill in credentials."
    )

ota_vars = {}
with open(env_file) as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            ota_vars[key.strip()] = value.strip()

try:
    Import("env")  # type: ignore[name-defined]
    env = cast(Any, globals()["env"])
    cpp_defines = []
    for key in ("OTA_SSID", "OTA_PASSWORD", "OTA_HOST", "OTA_AUTH_TOKEN"):
        if key in ota_vars:
            cpp_defines.append((key, env.StringifyMacro(ota_vars[key])))
    if "OTA_PORT" in ota_vars:
        cpp_defines.append(("OTA_PORT", int(ota_vars["OTA_PORT"])))
    else:
        cpp_defines.append(("OTA_PORT", 8765))
    env.Append(CPPDEFINES=cpp_defines)
    print(f"OTA: loaded {len(cpp_defines)} build flags from {env_file}")
except NameError:
    pass
