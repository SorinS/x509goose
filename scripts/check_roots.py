#!/usr/bin/env python3
"""Checks x509.pool's system root loading (tools/roots.goose) against the
rules of Go's SystemCertPool on Unix, which this script follows itself:
$SSL_CERT_FILE, else the first readable bundle of the known list; then
each directory of $SSL_CERT_DIR (':'-separated), else the known
directories, every regular file in them (PEM or DER); each certificate
once. Runs with the environment as it is, then with both variables
pointing into test/vectors, then with nothing to find.

    python3 scripts/check_roots.py [--goose PATH]
"""

import base64
import hashlib
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
VEC = os.path.join(ROOT, "test", "vectors")
FILES = ["/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/ca-bundle.pem",
         "/etc/pki/tls/cacert.pem", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "/etc/ssl/cert.pem",
         "/usr/local/etc/ssl/cert.pem", "/usr/local/share/certs/ca-root-nss.crt",
         "/etc/openssl/certs/ca-certificates.crt"]
DIRS = ["/etc/ssl/certs", "/etc/pki/tls/certs", "/usr/local/share/certs", "/etc/openssl/certs"]


def certs_of(path):
    try:
        b = open(path, "rb").read()
    except OSError:
        return None
    if b"-----BEGIN" in b:
        blocks = re.findall(rb"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", b, re.S)
        out = []
        for blk in blocks:
            try:
                out.append(base64.b64decode(b"".join(blk.split()), validate=True))
            except ValueError:
                pass
        return [d for d in out if d[:1] == b"\x30" and len(d) > 100]
    return [b] if b[:1] == b"\x30" else []


def expected(env):
    found = []
    if "SSL_CERT_FILE" in env:
        found += certs_of(env["SSL_CERT_FILE"]) or []
    else:
        for f in FILES:
            c = certs_of(f)
            if c is not None:
                found += c
                break
    dirs = env["SSL_CERT_DIR"].split(":") if "SSL_CERT_DIR" in env else DIRS
    for d in dirs:
        if not d or not os.path.isdir(d):
            continue
        for name in sorted(os.listdir(d)):
            p = os.path.join(d, name)
            if os.path.isfile(p):
                found += certs_of(p) or []
    seen, out = set(), []
    for d in found:
        h = hashlib.sha256(d).hexdigest()
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


def main():
    goose = sys.argv[sys.argv.index("--goose") + 1] if "--goose" in sys.argv else \
        os.environ.get("GOOSE") or shutil.which("goose") or os.path.join(ROOT, "..", "goose.git", "build", "goose")
    base = {k: v for k, v in os.environ.items() if k not in ("SSL_CERT_FILE", "SSL_CERT_DIR")}
    runs = [("environment as it is", dict(os.environ)),
            ("SSL_CERT_FILE and SSL_CERT_DIR", {**base, "SSL_CERT_FILE": os.path.join(VEC, "roots.pem"),
                                                "SSL_CERT_DIR": os.path.join(VEC, "rootdir") + ":/no/such/dir"}),
            ("nothing to find", {**base, "SSL_CERT_FILE": "/no/such/file", "SSL_CERT_DIR": ""})]
    failed = 0
    for label, env in runs:
        p = subprocess.run([goose, os.path.join(ROOT, "tools", "roots.goose")], env=env, capture_output=True, text=True)
        lines = [l for l in p.stdout.splitlines() if not l.startswith(("parsed ok", "typechecked ok", "bce:"))]
        want = expected(env)
        got_ok, got = lines[0].split()[1] == "1", lines[1:]
        good = p.returncode == 0 and got == want and got_ok == (len(want) > 0)
        failed += not good
        print(("ok    " if good else "FAIL  ") + f"{label}: {len(got)} roots" +
              ("" if good else f" (expected {len(want)}; {len(set(want) - set(got))} missing, "
                               f"{len(set(got) - set(want))} extra)"))
    print(f"\n{len(runs) - failed} passed, {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
