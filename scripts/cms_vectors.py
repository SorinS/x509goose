#!/usr/bin/env python3
"""Make test/vectors/cms.txt: CMS SignedData made by `openssl cms -sign`,
for test/cms_vectors.goose to read and check.

Each line:

    cms LABEL RESULT TYPE CONTENT SIGNED CERT

RESULT is ok or the x509 error the reader must give (malformed,
unsupported, unknown-issuer, bad-signature); TYPE the eContentType;
CONTENT, SIGNED (the ContentInfo, DER) and CERT (the signer's certificate,
DER) in hex. Then, for each key type, a key and certificate for
x509.cms to sign with:

    key NAME CERT KEY

(DER and PKCS #8, in hex).

    python3 scripts/cms_vectors.py
"""

import os
import subprocess
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
PKINIT_AUTH = "1.3.6.1.5.2.3.1"
PKINIT_DH = "1.3.6.1.5.2.3.2"


def ossl(*args, input=None):
    p = subprocess.run(["openssl", *args], input=input, capture_output=True)
    if p.returncode != 0:
        raise RuntimeError(f"openssl {' '.join(args)}: {p.stderr.decode()}")
    return p.stdout


def main():
    d = tempfile.mkdtemp()
    f = lambda n: os.path.join(d, n)
    keys = {"rsa": ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
            "p256": ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
            "p384": ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"],
            "p521": ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-521"]}
    for name, opts in keys.items():
        ossl("genpkey", *opts, "-out", f(name + ".key"))
        ossl("req", "-x509", "-new", "-key", f(name + ".key"), "-subj", f"/CN=cms {name}", "-days", "3650",
             "-addext", "subjectKeyIdentifier=hash", "-out", f(name + ".pem"))
    content = bytes(range(256)) * 3 + b"PKINIT"
    with open(f("content"), "wb") as fh:
        fh.write(content)
    lines = []

    def sign(label, key, result, md="sha256", ctype=PKINIT_AUTH, extra=()):
        der = ossl("cms", "-sign", "-binary", "-nodetach", "-nosmimecap", "-outform", "DER", "-in", f("content"),
                   "-signer", f(key + ".pem"), "-inkey", f(key + ".key"), "-md", md, "-econtent_type", ctype, *extra)
        cert = ossl("x509", "-in", f(key + ".pem"), "-outform", "DER")
        lines.append(f"cms {label} {result} {ctype} {content.hex()} {der.hex()} {cert.hex()}")
        return der

    for key in keys:
        for md in ("sha256", "sha384", "sha512"):
            sign(f"{key}-{md}", key, "ok", md)
    sign("rsa-keyid", "rsa", "ok", extra=("-keyid",))
    sign("p256-keyid", "p256", "ok", extra=("-keyid",))
    sign("rsa-pss", "rsa", "ok", extra=("-keyopt", "rsa_padding_mode:pss"))
    sign("rsa-pss-sha384", "rsa", "ok", "sha384", extra=("-keyopt", "rsa_padding_mode:pss"))
    sign("dh-type", "p256", "ok", ctype=PKINIT_DH)
    sign("rsa-sha1", "rsa", "unsupported", "sha1")
    sign("p256-sha1", "p256", "unsupported", "sha1")
    sign("no-attrs", "rsa", "malformed", extra=("-noattr",))
    sign("no-certs", "rsa", "unknown-issuer", extra=("-nocerts",))
    # Two signers.
    sign("two-signers", "rsa", "malformed", extra=("-signer", f("p256.pem"), "-inkey", f("p256.key")))
    # The signature changed, then the content.
    der = bytearray(sign("tampered-sig", "p384", "bad-signature"))
    der[-5] ^= 1
    lines[-1] = " ".join(lines[-1].split()[:5] + [der.hex(), lines[-1].split()[6]])
    der = bytearray(sign("tampered-content", "rsa", "bad-signature"))
    i = der.find(content[:64])
    der[i + 10] ^= 1
    lines[-1] = " ".join(lines[-1].split()[:5] + [der.hex(), lines[-1].split()[6]])
    for key in keys:
        cert = ossl("x509", "-in", f(key + ".pem"), "-outform", "DER")
        pk = ossl("pkey", "-in", f(key + ".key"), "-outform", "DER")
        lines.append(f"key {key} {cert.hex()} {pk.hex()}")
    with open(os.path.join(ROOT, "test", "vectors", "cms.txt"), "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"{len(lines)} vectors")


if __name__ == "__main__":
    main()
