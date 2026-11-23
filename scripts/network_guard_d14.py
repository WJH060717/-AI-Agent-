"""D14 process-level Python network guard, not an OS firewall or physical disconnect."""

import argparse
import ipaddress
import json
import runpy
import socket
import sys
from pathlib import Path

MODULES = {
    "pip",
    "apps.api.main",
    "apps.api.manage",
    "apps.worker",
    "scripts.backup",
    "scripts.preflight",
}


def validate_module(module: str) -> None:
    if module not in MODULES:
        raise ValueError("MODULE_NOT_ALLOWED")


def check_event(event: str, arguments: tuple) -> None:
    if event == "socket.getaddrinfo":
        host = arguments[0]
    elif event in {"socket.connect", "socket.sendto"}:
        address = arguments[1]
        if not isinstance(address, tuple) or not address:
            raise PermissionError("NON_LOOPBACK_NETWORK_REFUSED")
        host = address[0]
    else:
        return
    if host == "localhost":
        return
    try:
        if ipaddress.ip_address(host).is_loopback:
            return
    except ValueError:
        pass
    raise PermissionError("NON_LOOPBACK_NETWORK_REFUSED")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path)
    parser.add_argument("--module")
    parser.add_argument("--audit", type=Path, required=True)
    parser.add_argument("--self-test", action="store_true")
    args, remainder = parser.parse_known_args()
    if not args.self_test:
        validate_module(args.module)
        if args.app is None:
            parser.error("--app required")
    with args.audit.open("x", encoding="utf-8") as stream:
        stream.write(
            json.dumps({"guard_enabled": True, "scope": "Python socket audit only"}) + "\n"
        )
        stream.flush()

        def audit(event: str, arguments: tuple) -> None:
            try:
                check_event(event, arguments)
            except PermissionError:
                stream.write(json.dumps({"blocked_event": event}) + "\n")
                stream.flush()
                raise

        sys.addaudithook(audit)
        if args.self_test:
            with socket.socket() as connection:
                try:
                    connection.connect(("192.0.2.1", 9))
                except PermissionError:
                    print(json.dumps({"non_loopback_blocked_before_connect": True}))
                else:
                    raise RuntimeError("GUARD_FAILED")
            return
        sys.path.insert(0, str(args.app.resolve()))
        sys.argv = [args.module, *(remainder[1:] if remainder[:1] == ["--"] else remainder)]
        runpy.run_module(args.module, run_name="__main__", alter_sys=True)


if __name__ == "__main__":
    main()
