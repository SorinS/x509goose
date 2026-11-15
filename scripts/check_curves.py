#!/usr/bin/env python3
"""Checks what x509 makes on the brainpool curves, Ed448 and X448 with
openssl.

Runs tools/make_curves.goose into a temporary directory, then has
openssl: verify each leaf (x509_strict, sslserver, host name) under its
root, and refuse it under the other; read every private key (PKCS #8, and
SEC 1 for brainpool), whose public key must be its certificate's; verify
the requests and the CRLs, and find the leaves they revoke revoked under
-crl_check; verify the brainpool SignedData (and refuse them changed) and
decrypt the EnvelopedData for each brainpool recipient. openssl's cms has
no id-shake256-len and no X448 key agreement, so the Ed448 SignedData and
the X448 recipients are checked with openssl's primitives instead: the
messageDigest is SHAKE256 of the content, the Ed448 signature over the
signed attributes verifies (pkeyutl -rawin) and the digest algorithm is
id-shake256-len with 512 (RFC 8419); the X448 shared secret (pkeyutl
-derive), the KDF (kdf X963KDF or HKDF over ECC-CMS-SharedInfo, RFC 8418),
the key unwrap and the content's AES-CBC give the content back.

    python3 scripts/check_curves.py [--goose PATH]
"""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))
from curves_vectors import (children, seq, oid, integer, spki_der, shared_info, issuer_and_serial,  # noqa: E402
                            OID_SHAKE256_LEN, OID_ED448, OID_X448, KDF, WRAP, CBC)

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))


def ossl(*a, input=None):
    return subprocess.run(["openssl", *a], capture_output=True, input=input)


def out(p):
    return (p.stdout + p.stderr).decode(errors="replace")


def body(b, el):
    """The contents of an element from children()."""
    return b[el[2]:el[3]]


def whole(b, el):
    return b[el[1]:el[3]]


def explicit(b, el):
    """The element inside an EXPLICIT tag."""
    return children(b, el[1])[0]


def ed448_check(d, name, content):
    """The Ed448 SignedData sig_<name>.der by RFC 8419, with openssl's primitives."""
    cms = open(os.path.join(d, f"sig_{name}.der"), "rb").read()
    sd = explicit(cms, children(cms)[1])
    f = children(cms, sd[1])
    si = children(cms, children(cms, f[-1][1])[0][1])
    want_alg = seq(oid(OID_SHAKE256_LEN), integer(512))
    if whole(cms, f[1]) != b"\x31" + bytes([len(want_alg)]) + want_alg or whole(cms, si[2]) != want_alg:
        return False, "digest algorithm is not id-shake256-len (512)"
    if whole(cms, si[4]) != seq(oid(OID_ED448)):
        return False, "signature algorithm is not id-Ed448"
    attrs = b"\x31" + whole(cms, si[3])[1:]
    md = None
    for a in children(attrs):
        av = children(attrs, a[1])
        if whole(attrs, av[0]) == oid("1.2.840.113549.1.9.4"):
            md = body(attrs, children(attrs, av[1][1])[0])
    if md != hashlib.shake_256(content).digest(64):
        return False, "messageDigest is not SHAKE256 of the content (64 bytes)"
    sig = body(cms, si[5])
    pub = os.path.join(d, name + ".pub")
    with open(pub, "wb") as fh:
        fh.write(ossl("x509", "-in", os.path.join(d, name + ".pem"), "-noout", "-pubkey").stdout)
    for changed in (False, True):
        a = bytearray(attrs)
        if changed:
            a[-1] ^= 1
        with open(os.path.join(d, "attrs.bin"), "wb") as fh:
            fh.write(a)
        with open(os.path.join(d, "sig.bin"), "wb") as fh:
            fh.write(sig)
        p = ossl("pkeyutl", "-verify", "-pubin", "-inkey", pub, "-rawin", "-in", os.path.join(d, "attrs.bin"),
                 "-sigfile", os.path.join(d, "sig.bin"))
        if (p.returncode == 0) == changed:
            return False, ("changed attributes verify" if changed else "signature does not verify: " + out(p))
    return True, ""


def x448_decrypt(d, env_name, rcpt, content):
    """The content of EnvelopedData env_name for the X448 recipient rcpt, with openssl's primitives."""
    f = lambda n: os.path.join(d, n)
    cms = open(f(env_name), "rb").read()
    ed = explicit(cms, children(cms)[1])
    p = children(cms, ed[1])
    cert = ossl("x509", "-in", f(rcpt + ".pem"), "-outform", "DER").stdout
    rid = issuer_and_serial(cert)
    for ri in children(cms, p[1][1]):
        if ri[0] != 0xa1:
            continue
        k = children(cms, ri[1])
        orig = children(cms, explicit(cms, k[1])[1])          # originatorKey [1]: algorithm, publicKey
        if whole(cms, orig[0]) != seq(oid(OID_X448)):
            continue
        eph = body(cms, orig[1])[1:]
        ukm = body(cms, explicit(cms, k[2])) if len(k) == 5 else b""
        kea = children(cms, k[-2][1])
        kdf = next((n for n, o in KDF.items() if whole(cms, kea[0]) == oid(o)), None)
        if kdf is None:
            return None, "unknown KDF"
        wrap_alg = whole(cms, kea[1])
        n = next(n for n, o in WRAP.items() if wrap_alg == seq(oid(o)))
        for rek in children(cms, k[-1][1]):
            r = children(cms, rek[1])
            if whole(cms, r[0]) != rid:
                continue
            with open(f("eph.der"), "wb") as fh:
                fh.write(spki_der(OID_X448, eph))
            ossl("pkey", "-pubin", "-inform", "DER", "-in", f("eph.der"), "-out", f("eph.pub"))
            z = ossl("pkeyutl", "-derive", "-inkey", f(rcpt + ".key"), "-peerkey", f("eph.pub")).stdout
            info = shared_info(wrap_alg, ukm, n)
            if kdf.startswith("x963"):
                kek = ossl("kdf", "-keylen", str(n), "-binary", "-kdfopt", "digest:SHA" + kdf[-3:], "-kdfopt",
                           "hexsecret:" + z.hex(), "-kdfopt", "hexinfo:" + info.hex(), "X963KDF").stdout
            else:
                salt = ["-kdfopt", "hexsalt:" + ukm.hex()] if ukm else []
                kek = ossl("kdf", "-keylen", str(n), "-binary", "-kdfopt", "digest:SHA" + kdf[-3:], *salt, "-kdfopt",
                           "hexkey:" + z.hex(), "-kdfopt", "hexinfo:" + info.hex(), "HKDF").stdout
            with open(f("ek.bin"), "wb") as fh:
                fh.write(body(cms, r[1]))
            cek = ossl("enc", "-d", "-id-aes%d-wrap" % (8 * n), "-K", kek.hex(), "-iv", "A6A6A6A6A6A6A6A6",
                       "-in", f("ek.bin")).stdout
            eci = children(cms, p[2][1])
            alg = children(cms, eci[1][1])
            cl = next(n for n, o in CBC.items() if whole(cms, alg[0]) == oid(o))
            if len(cek) != cl:
                return None, f"key unwrap gave {len(cek)} bytes ({kdf})"
            with open(f("ct.bin"), "wb") as fh:
                fh.write(body(cms, eci[2]))
            pt = ossl("enc", "-d", "-aes-%d-cbc" % (8 * cl), "-K", cek.hex(), "-iv", body(cms, alg[1]).hex(),
                      "-in", f("ct.bin"))
            return pt.stdout, kdf
    return None, "no X448 RecipientInfo for " + rcpt


def main():
    goose = sys.argv[sys.argv.index("--goose") + 1] if "--goose" in sys.argv else \
        os.environ.get("GOOSE") or shutil.which("goose") or os.path.join(ROOT, "..", "goose.git", "build", "goose")
    d = tempfile.mkdtemp()
    p = subprocess.run([goose, os.path.join(ROOT, "tools", "make_curves.goose"), "--", d], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    f = lambda n: os.path.join(d, n)
    content = open(f("content.txt"), "rb").read()
    results = []

    def expect(label, proc, ok, needle=None):
        good = (proc.returncode == 0) == ok and (needle is None or needle in out(proc))
        results.append(good)
        print(("ok    " if good else "FAIL  ") + label + ("" if good else "\n      " + out(proc).strip()))

    def result(label, good, detail=""):
        results.append(good)
        print(("ok    " if good else "FAIL  ") + label + ("" if good else "\n      " + detail))

    bp = ["verify", "-x509_strict", "-purpose", "sslserver", "-CAfile", f("bp_root.pem"), "-untrusted", f("bp_int.pem")]
    ed = ["verify", "-x509_strict", "-purpose", "sslserver", "-CAfile", f("ed_root.pem")]
    for leaf, base, other in (("leaf_ed448", bp, ed), ("leaf_bp256", bp, ed), ("sm_bp384", bp, ed), ("sm_bp512", bp, ed),
                              ("leaf_by_ed448", ed, bp)):
        expect(f"{leaf} verifies", ossl(*base, "-verify_hostname", "www.example.com", f(leaf + ".pem")), True)
        expect(f"{leaf} under the other root refused", ossl(*other, f(leaf + ".pem")), False)
    expect("leaf_x448 verifies", ossl("verify", "-x509_strict", "-CAfile", f("bp_root.pem"), "-untrusted", f("bp_int.pem"),
                                      f("leaf_x448.pem")), True)
    for name in ("leaf_ed448", "leaf_bp256", "leaf_x448", "sm_bp384", "sm_bp512", "leaf_by_ed448"):
        pub_cert = ossl("x509", "-in", f(name + ".pem"), "-noout", "-pubkey").stdout
        pub_key = ossl("pkey", "-in", f(name + ".key"), "-pubout").stdout
        result(f"{name} key matches certificate", pub_cert == pub_key and pub_cert != b"")
    pub_sec1 = ossl("ec", "-in", f("leaf_bp256.sec1"), "-pubout").stdout
    result("leaf_bp256 SEC 1 key matches certificate",
           pub_sec1 == ossl("x509", "-in", f("leaf_bp256.pem"), "-noout", "-pubkey").stdout and pub_sec1 != b"")
    for csr in ("csr_bp256", "csr_ed448"):
        expect(f"{csr} signature", ossl("req", "-in", f(csr + ".pem"), "-verify", "-noout"), True, "verify OK")
    expect("brainpool crl", ossl("crl", "-in", f("crl_bp.pem"), "-CAfile", f("bp_int.pem"), "-noout"), True, "verify OK")
    expect("Ed448 crl", ossl("crl", "-in", f("crl_ed.pem"), "-CAfile", f("ed_root.pem"), "-noout"), True, "verify OK")
    expect("brainpool crl revokes leaf_bp256", ossl(*bp, "-crl_check", "-CRLfile", f("crl_bp.pem"), f("leaf_bp256.pem")),
           False, "revoked")
    expect("brainpool crl keeps leaf_ed448", ossl(*bp, "-crl_check", "-CRLfile", f("crl_bp.pem"), f("leaf_ed448.pem")), True)
    expect("Ed448 crl revokes leaf_by_ed448", ossl(*ed, "-crl_check", "-CRLfile", f("crl_ed.pem"), f("leaf_by_ed448.pem")),
           False, "revoked")

    # SignedData.
    for name in ("leaf_bp256", "sm_bp384", "sm_bp512"):
        sig = f(f"sig_{name}.der")
        v = ossl("cms", "-verify", "-inform", "DER", "-in", sig, "-CAfile", f("bp_root.pem"), "-purpose", "any", "-binary")
        result(f"SignedData by {name} verifies", v.returncode == 0 and v.stdout == content, out(v))
        data = bytearray(open(sig, "rb").read())
        data[data.find(content)] ^= 1
        v = ossl("cms", "-verify", "-inform", "DER", "-CAfile", f("bp_root.pem"), "-purpose", "any", "-binary",
                 input=bytes(data))
        result(f"SignedData by {name}, changed, refused", v.returncode != 0)
    good, why = ed448_check(d, "leaf_ed448", content)
    result("SignedData by Ed448 (RFC 8419), by openssl's primitives", good, why)
    v = ossl("cms", "-verify", "-inform", "DER", "-in", f("sig_leaf_ed448.der"), "-noverify", "-binary")
    note = "verifies" if v.returncode == 0 else "refuses it (" + out(v).strip().splitlines()[0][-60:] + ")"
    print(f"note  openssl cms -verify of the Ed448 SignedData {note}")

    # EnvelopedData.
    for env, who in (("env_all.der", "leaf_bp256"), ("env_all.der", "sm_bp384"), ("env_all.der", "sm_bp512"),
                     ("env_gcm.der", "sm_bp512")):
        v = ossl("cms", "-decrypt", "-inform", "DER", "-in", f(env), "-recip", f(who + ".pem"), "-inkey", f(who + ".key"))
        result(f"{env} decrypts for {who}", v.returncode == 0 and v.stdout == content, out(v))
    for env in ("env_all.der", "env_x448_hkdf.der"):
        pt, how = x448_decrypt(d, env, "leaf_x448", content)
        result(f"{env} decrypts for leaf_x448 ({how}), by openssl's primitives", pt == content, how)
    shutil.rmtree(d)
    print(f"\n{sum(results)} passed, {len(results) - sum(results)} failed")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
