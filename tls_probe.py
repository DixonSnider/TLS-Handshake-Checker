#!/usr/bin/env python3
import argparse, socket, ssl, json, datetime
from typing import Optional, List, Tuple

VERSIONS = [
    ("TLSv1.0", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
]

def connect_once(host: str, port: int,
                 minv: ssl.TLSVersion, maxv: ssl.TLSVersion,
                 alpn_protocols: Optional[List[str]] = None) -> Tuple[Optional[ssl.SSLSocket], Optional[ssl.SSLObject], Optional[Exception]]:
    ctx = ssl.create_default_context()
    ctx.minimum_version = minv
    ctx.maximum_version = maxv
    if alpn_protocols:
        ctx.set_alpn_protocols(alpn_protocols)
    # Avoid certificate failure stopping the probe; we still want handshake info.
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    s = socket.create_connection((host, port), timeout=6.0)
    try:
        tls = ctx.wrap_socket(s, server_hostname=host)
        return tls, tls, None
    except Exception as e:
        s.close()
        return None, None, e

def parse_cert(cert_dict: dict) -> dict:
    # cert_dict format from getpeercert()
    subject = "; ".join(["=".join(x[0]) for x in cert_dict.get("subject", [[]])[0]]) if cert_dict.get("subject") else ""
    issuer = "; ".join(["=".join(x[0]) for x in cert_dict.get("issuer", [[]])[0]]) if cert_dict.get("issuer") else ""
    not_before = cert_dict.get("notBefore", "")
    not_after = cert_dict.get("notAfter", "")
    san = []
    for t, v in cert_dict.get("subjectAltName", []):
        if t == "DNS":
            san.append(v)
    # Convert to ISO if possible
    def to_iso(s):
        try:
            dt = datetime.datetime.strptime(s, "%b %d %H:%M:%S %Y %Z")
            return dt.strftime("%Y-%m-%d")
        except Exception:
            return s
    out = {
        "subject": subject,
        "issuer": issuer,
        "not_before": to_iso(not_before),
        "not_after": to_iso(not_after),
        "sans": san,
    }
    # days left
    try:
        end = datetime.datetime.strptime(cert_dict["notAfter"], "%b %d %H:%M:%S %Y %Z")
        out["days_left"] = (end - datetime.datetime.utcnow()).days
    except Exception:
        out["days_left"] = None
    return out

def probe(host: str, port: int, verbose: bool=False):
    supported = []
    negotiated = None
    alpn = None
    cipher = None
    cert = None
    error_map = {}

    # First, discover highest version
    tls, _, err = connect_once(host, port, ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_3, ["h2", "http/1.1"])
    if tls:
        negotiated = tls.version()
        alpn = tls.selected_alpn_protocol()
        cipher = tls.cipher()[0] if tls.cipher() else None
        try:
            cert = parse_cert(tls.getpeercert())
        except Exception:
            cert = None
        tls.close()
    else:
        error_map["negotiate"] = str(err)

    # Map supported versions by probing each explicitly
    for name, v in VERSIONS:
        try:
            t, _, e = connect_once(host, port, v, v, ["h2", "http/1.1"])
            if t:
                supported.append(name)
                t.close()
            else:
                error_map[name] = str(e)
        except Exception as e:
            error_map[name] = str(e)

    result = {
        "target": f"{host}:{port}",
        "sni": host,
        "supported_versions": supported,
        "negotiated_version": negotiated,
        "cipher": cipher,
        "alpn": alpn,
        "certificate": cert,
        "errors": error_map if verbose else None
    }

    # Pretty print
    print(f"Target: {host}:{port}")
    print(f"SNI: {host}")
    if supported:
        print("Supported TLS versions: " + ", ".join([v for v in supported if v.startswith("TLS")]))
    else:
        print("Supported TLS versions: (none detected)")
    print(f"Negotiated: {negotiated}")
    print(f"Cipher: {cipher}")
    print(f"ALPN: {alpn}")
    if cert:
        print("Certificate:")
        cn = ""
        # Try to show Subject CN if present in subject string
        for part in cert["subject"].split("; "):
            if part.startswith("commonName=") or part.startswith("CN="):
                cn = part.split("=",1)[1]
        print(f"  Subject CN: {cn or cert['subject']}")
        print(f"  SANs: {', '.join(cert['sans'][:6])}" + (" ..." if len(cert['sans'])>6 else ""))
        print(f"  Issuer: {cert['issuer']}")
        print(f"  Valid: {cert['not_before']} → {cert['not_after']} ({cert['days_left']} days left)")
    if verbose:
        print("\n--- JSON ---")
        print(json.dumps(result, indent=2, sort_keys=True))

def main():
    p = argparse.ArgumentParser(description="Probe a server's TLS handshake (versions, cipher, ALPN, cert).")
    p.add_argument("host")
    p.add_argument("port", type=int, nargs="?", default=443)
    p.add_argument("-v", "--verbose", action="store_true", help="Include raw JSON and error details")
    args = p.parse_args()
    probe(args.host, args.port, verbose=args.verbose)

if __name__ == "__main__":
    main()
