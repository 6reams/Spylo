import shutil
import socket
import ssl
import subprocess
from pathlib import Path
from typing import Optional

from rich.console import Console

console = Console()


def ensure_dir(path: str):
    Path(path).mkdir(parents=True, exist_ok=True)


def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


def run_cmd(cmd: list[str]) -> tuple[int, str, str]:
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def tcp_connect(host: str, port: int, timeout: int = 5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return s
    except Exception:
        s.close()
        return None


def grab_banner(host: str, port: int, timeout: int = 5) -> Optional[str]:
    s = tcp_connect(host, port, timeout)
    if not s:
        return None
    try:
        # Minimal HTTP probe
        s.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode())
        data = s.recv(1024)
        return data.decode(errors="ignore")
    except Exception:
        return None
    finally:
        s.close()


def fetch_tls_cert(host: str, port: int = 443, timeout: int = 8) -> Optional[ssl.SSLObject]:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            return cert


def extract_cert_summary(cert_dict: dict) -> dict:
    if not cert_dict:
        return {}
    def _join_name(x):
        try:
            return ", ".join(["=".join(t) for tup in cert_dict.get(x, []) for t in tup])
        except Exception:
            return str(cert_dict.get(x))
    san = []
    for typ, val in cert_dict.get("subjectAltName", []) or []:
        san.append(f"{typ}:{val}")
    return {
        "subject": cert_dict.get("subject"),
        "issuer": cert_dict.get("issuer"),
        "notBefore": cert_dict.get("notBefore"),
        "notAfter": cert_dict.get("notAfter"),
        "subjectAltName": san,
        "serialNumber": cert_dict.get("serialNumber"),
        "version": cert_dict.get("version"),
    }
