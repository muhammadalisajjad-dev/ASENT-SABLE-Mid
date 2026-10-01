"""
ASENT PIP Shim.
Placed earlier in PATH to intercept agent installation attempts.
Logs the exact command, creates an interception record, and redirects through the local ASENT index.
"""
from __future__ import annotations
import json
import os
import sys
import urllib.request
import subprocess
from pathlib import Path

ASENT_PORT = int(os.environ.get("ASENT_PORT", "8000"))
ASENT_INDEX_URL = f"http://127.0.0.1:{ASENT_PORT}/simple/"

def notify_asent(command: list[str], intercepted_pkgs: list[str]):
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{ASENT_PORT}/api/cavr/intercept-command",
            data=json.dumps({"command": " ".join(command), "packages": intercepted_pkgs}).encode(),
            headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req, timeout=3)
    except Exception:
        pass

def parse_pip_command(args: list[str]) -> list[str]:
    pkgs = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("install", "pip"):
            i += 1
            continue
        if arg.startswith("-"):
            # skip option flags like -r, -i, etc.
            if arg in ("-r", "--requirement", "-c", "--constraint"):
                i += 2
                continue
            i += 1
            continue
        # Positional pkg specifier
        pkgs.append(arg)
        i += 1
    return pkgs

def main():
    args = sys.argv[1:]
    pkgs = parse_pip_command(args)
    notify_asent(["pip"] + args, pkgs)

    # Invoke real pip with index-url override
    override_args = ["--index-url", ASENT_INDEX_URL]
    cmd = [sys.executable, "-m", "pip"] + args + override_args
    sys.exit(subprocess.call(cmd))

if __name__ == "__main__":
    main()
