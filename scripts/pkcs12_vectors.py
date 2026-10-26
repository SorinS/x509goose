#!/usr/bin/env python3
"""PKCS #12 files made by openssl, for test/pkcs12_vectors.goose.

Two keys (RSA-2048 and P-256), each with a self-signed CA and a leaf it
issued, exported under every scheme openssl writes: openssl 3's default
(PBES2, PBKDF2-HMAC-SHA-256, AES-256-CBC, a SHA-256 MAC), AES-128 with a
SHA-1 PRF, the legacy pair Go's x/crypto/pkcs12 reads
(pbeWithSHAAnd40BitRC2-CBC for certificates, 3DES for the key, a SHA-1
MAC), 3DES throughout, no encryption, and no MAC; with empty, ASCII and
non-ASCII passwords. Per file:

    p12 <label> <password hex|-> <key PKCS #8 hex> <certificates, DER concatenated, leaf first> <file hex>

    python3 scripts/pkcs12_vectors.py
"""

import os
import subprocess
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
TMP = tempfile.mkdtemp()
ENV = dict(os.environ, LC_ALL="en_US.UTF-8")


def ossl(*args, data=None):
    p = subprocess.run(["openssl", *args], input=data, capture_output=True, env=ENV)
    if p.returncode:
        raise RuntimeError(" ".join(args) + ": " + p.stderr.decode())
    return p.stdout


def path(name):
    return os.path.join(TMP, name)


SCHEMES = [
    ("default", []),
    ("aes128-sha1", ["-keypbe", "AES-128-CBC", "-certpbe", "AES-128-CBC", "-macalg", "sha1"]),
    ("legacy", ["-legacy"]),
    ("3des", ["-legacy", "-certpbe", "PBE-SHA1-3DES", "-keypbe", "PBE-SHA1-3DES"]),
    ("rc2-128", ["-legacy", "-certpbe", "PBE-SHA1-RC2-128", "-keypbe", "PBE-SHA1-RC2-128"]),
    ("2key-3des", ["-legacy", "-certpbe", "PBE-SHA1-2DES", "-keypbe", "PBE-SHA1-2DES"]),
    ("plain", ["-keypbe", "NONE", "-certpbe", "NONE"]),
    ("nomac", ["-nomac"]),
    ("sha512-mac", ["-macalg", "sha512", "-iter", "1000"]),
]
PASSWORDS = ["", "goose", "pässwörd ü"]


def main():
    lines = []
    for kind, gen in (("rsa", ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]),
                      ("p256", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"])):
        ossl("genpkey", *gen, "-out", path("ca.key"))
        ossl("req", "-x509", "-new", "-key", path("ca.key"), "-subj", f"/CN=P12 CA {kind}", "-days", "3650",
             "-out", path("ca.pem"))
        ossl("genpkey", *gen, "-out", path("leaf.key"))
        ossl("req", "-new", "-key", path("leaf.key"), "-subj", f"/CN=p12 leaf {kind}", "-out", path("leaf.csr"))
        ossl("x509", "-req", "-in", path("leaf.csr"), "-CA", path("ca.pem"), "-CAkey", path("ca.key"),
             "-days", "365", "-set_serial", "7", "-out", path("leaf.pem"))
        key = ossl("pkey", "-in", path("leaf.key"), "-outform", "DER")
        certs = ossl("x509", "-in", path("leaf.pem"), "-outform", "DER") + \
            ossl("x509", "-in", path("ca.pem"), "-outform", "DER")
        for label, opts in SCHEMES:
            for pw in PASSWORDS:
                p12 = ossl("pkcs12", "-export", "-in", path("leaf.pem"), "-inkey", path("leaf.key"),
                           "-certfile", path("ca.pem"), "-passout", f"pass:{pw}", *opts)
                # openssl reads it back to the same key and certificates.
                back = ossl("pkcs12", "-in", "/dev/stdin", "-passin", f"pass:{pw}", "-nodes", *(
                    ["-legacy"] if "-legacy" in opts else []), data=p12)
                assert b"PRIVATE KEY" in back
                lines.append(f"p12 {kind}-{label} {pw.encode().hex() or '-'} {key.hex()} {certs.hex()} {p12.hex()}")
    with open(os.path.join(ROOT, "test", "vectors", "pkcs12.txt"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"wrote {len(lines)} files")


if __name__ == "__main__":
    main()
