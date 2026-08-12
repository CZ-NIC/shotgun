"""
Ephemeral self-signed TLS cert/key generation via the openssl CLI.
"""
import pathlib
import shutil
import subprocess

import pytest

OPENSSL = shutil.which("openssl")

requires_openssl = pytest.mark.skipif(OPENSSL is None, reason="openssl binary not found")


def generate_cert(out_dir: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    assert OPENSSL, "openssl binary not found"
    cert_path = out_dir / "cert.pem"
    key_path = out_dir / "key.pem"
    subprocess.run(
        [
            OPENSSL, "req", "-x509", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-days", "1", "-nodes",
            "-keyout", str(key_path),
            "-out", str(cert_path),
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=IP:::1",
        ],
        check=True,
        capture_output=True,
    )
    return cert_path, key_path
