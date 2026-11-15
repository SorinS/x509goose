#!/usr/bin/env python3
"""Make test/vectors/curves.txt: brainpool, Ed448 and X448 keys,
certificates, requests, CRLs, PKCS #12 files and CMS, for
test/curves_vectors.goose to read and check.

From openssl: brainpoolP256r1, P384r1 and P512r1 keys in PKCS #8 and SEC 1
with their SubjectPublicKeyInfo; Ed448 and X448 keys in PKCS #8 (and the
same as a OneAsymmetricKey v2 with its public key, built here) with
theirs; a brainpool hierarchy (brainpoolP512r1 root, brainpoolP384r1
intermediate, Ed448 and brainpoolP256r1 leaves, an X448 leaf made with
-force_pubkey) and an Ed448 root with a brainpoolP384r1 leaf, whose path
cases `openssl verify` must agree with; requests on brainpool and Ed448
keys; a CRL from the brainpool intermediate and one from the Ed448 root,
each revoking a leaf; PKCS #12 files of a brainpool and an Ed448 key;
SignedData by brainpool signers (SHA-256, -384, -512, without signed
attributes, by key identifier) and by Ed448 without signed attributes
(id-shake256: openssl cannot sign Ed448 with them), and EnvelopedData to
brainpool recipients (openssl's SHA-1 KDF, its SHA-384 one, AES-GCM, by
key identifier, several recipients).

Built here from openssl's primitives (pkeyutl, kdf, enc), as openssl's
cms has neither: an Ed448 SignedData with signed attributes (RFC 8419:
id-shake256-len, 512 bits) and EnvelopedData to X448 recipients (RFC 8418:
the X9.63 KDF over SHA-512, HKDF-SHA512 with a ukm, HKDF-SHA256).

    eckey <kind> <pkcs8> <sec1> <spki>
    okpkey <kind> <pkcs8> <spki> <pkcs8 v2>
    key <name> <pkcs8>
    cert <name> <hex DER>
    case <label> <leaf> <intermediates,...|-> <roots,...> <now> <host|-> <expected error>
    csr <name> <hex DER>
    crl <name> <issuer> <revoked certificate> <hex DER>
    p12 <name> <password> <pfx> <pkcs8>
    signed <label> <signer> <ContentInfo>
    enveloped <label> <recipient> <ContentInfo>

The content of each CMS is CONTENT.

    python3 scripts/curves_vectors.py
"""

import hashlib
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))
from gen_vectors import PKI, ERR, NOW, CA, LEAF, ossl, gtime, DAY  # noqa: E402

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
CONTENT = b"Hello from the new curves.\r\n"
CURVES = {"bp256": "brainpoolP256r1", "bp384": "brainpoolP384r1", "bp512": "brainpoolP512r1"}
SMIME = "basicConstraints=CA:FALSE;keyUsage=critical,digitalSignature,keyAgreement;subjectKeyIdentifier=hash"

OID_DATA = "1.2.840.113549.1.7.1"
OID_SIGNED = "1.2.840.113549.1.7.2"
OID_ENVELOPED = "1.2.840.113549.1.7.3"
OID_SHAKE256_LEN = "2.16.840.1.101.3.4.2.18"
OID_ED448 = "1.3.101.113"
OID_X448 = "1.3.101.111"
KDF = {"x963-sha512": "1.3.132.1.11.3", "hkdf-sha256": "1.2.840.113549.1.9.16.3.19",
       "hkdf-sha512": "1.2.840.113549.1.9.16.3.21"}
WRAP = {16: "2.16.840.1.101.3.4.1.5", 32: "2.16.840.1.101.3.4.1.45"}
CBC = {16: "2.16.840.1.101.3.4.1.2", 32: "2.16.840.1.101.3.4.1.42"}


# --- DER, as much as these need -------------------------------------------------

def tlv(tag, body):
    n = len(body)
    if n < 0x80:
        return bytes([tag, n]) + body
    ln = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(ln)]) + ln + body


def seq(*parts):
    return tlv(0x30, b"".join(parts))


def oid(dotted):
    arcs = [int(x) for x in dotted.split(".")]
    out = bytearray([40 * arcs[0] + arcs[1]])
    for a in arcs[2:]:
        chunk = [a & 0x7f]
        a >>= 7
        while a:
            chunk.append(0x80 | (a & 0x7f))
            a >>= 7
        out += bytes(reversed(chunk))
    return tlv(0x06, bytes(out))


def integer(v):
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big")
    return tlv(0x02, b)


def octets(b):
    return tlv(0x04, b)


def bits(b):
    return tlv(0x03, b"\x00" + b)


def ctx(n, body, constructed=True):
    return tlv((0xa0 if constructed else 0x80) | n, body)


def read(b, off=0):
    """(tag, content start, end) of the element at off."""
    tag = b[off]
    n = b[off + 1]
    p = off + 2
    if n & 0x80:
        k = n & 0x7f
        n = int.from_bytes(b[p:p + k], "big")
        p += k
    return tag, p, p + n


def children(b, off=0):
    tag, p, end = read(b, off)
    out = []
    while p < end:
        t, s, e = read(b, p)
        out.append((t, p, s, e))
        p = e
    return out


def set_of(*elems):
    return tlv(0x31, b"".join(sorted(elems)))


def issuer_and_serial(cert):
    tbs = children(cert)[0]
    f = children(cert, tbs[1])
    i = 1 if f[0][0] == 0xa0 else 0       # version [0]
    serial, issuer = f[i], f[i + 2]
    return seq(cert[issuer[1]:issuer[3]], cert[serial[1]:serial[3]])


def raw_public(spki):
    """The subjectPublicKey of a SubjectPublicKeyInfo, without its unused-bits octet."""
    k = children(spki)[1]
    return spki[k[2] + 1:k[3]]


def spki_der(alg, raw):
    return seq(seq(oid(alg)), bits(raw))


# --- What openssl's cms cannot make ------------------------------------------------

def run(*args, input=None):
    if input is None:
        return ossl(*args).stdout
    # enc will not take a key wrap's input from a pipe.
    with tempfile.NamedTemporaryFile() as fh:
        fh.write(input)
        fh.flush()
        return ossl(*args, "-in", fh.name).stdout


def ed448_signed(tmp, key, cert):
    """SignedData by Ed448 with signed attributes (RFC 8419 §3.1)."""
    f = lambda n: os.path.join(tmp, n)
    digest_alg = seq(oid(OID_SHAKE256_LEN), integer(512))
    attrs = [seq(oid("1.2.840.113549.1.9.3"), set_of(oid(OID_DATA))),
             seq(oid("1.2.840.113549.1.9.4"), set_of(octets(hashlib.shake_256(CONTENT).digest(64))))]
    signed_attrs = set_of(*attrs)
    with open(f("attrs"), "wb") as fh:
        fh.write(signed_attrs)
    sig = run("pkeyutl", "-sign", "-rawin", "-inkey", key, "-in", f("attrs"))
    si = seq(integer(1), issuer_and_serial(cert), digest_alg, b"\xa0" + signed_attrs[1:],
             seq(oid(OID_ED448)), octets(sig))
    sd = seq(integer(1), set_of(digest_alg), seq(oid(OID_DATA), ctx(0, octets(CONTENT))),
             ctx(0, cert), set_of(si))
    return seq(oid(OID_SIGNED), ctx(0, sd))


def shared_info(wrap_alg, ukm, kek_len):
    body = wrap_alg
    if ukm:
        body += ctx(0, octets(ukm))
    return seq(body, ctx(2, octets((kek_len * 8).to_bytes(4, "big"))))


def kek_of(kdf, z, ukm, info, n):
    if kdf.startswith("x963"):
        out = run("kdf", "-keylen", str(n), "-binary", "-kdfopt", "digest:SHA" + kdf[-3:],
                  "-kdfopt", "hexsecret:" + z.hex(), "-kdfopt", "hexinfo:" + info.hex(), "X963KDF")
    else:
        salt = ["-kdfopt", "hexsalt:" + ukm.hex()] if ukm else []
        out = run("kdf", "-keylen", str(n), "-binary", "-kdfopt", "digest:SHA" + kdf[-3:], *salt,
                  "-kdfopt", "hexkey:" + z.hex(), "-kdfopt", "hexinfo:" + info.hex(), "HKDF")
    assert len(out) == n
    return out


def x448_enveloped(tmp, cert, kdf, n, ukm=b""):
    """EnvelopedData to an X448 certificate (RFC 8418), AES-n*8-CBC content."""
    f = lambda x: os.path.join(tmp, x)
    tbs = children(cert)[0]
    fields = children(cert, tbs[1])
    i = 1 if fields[0][0] == 0xa0 else 0
    spki = fields[i + 5]
    with open(f("rcpt.der"), "wb") as fh:
        fh.write(cert[spki[1]:spki[3]])
    run("pkey", "-pubin", "-inform", "DER", "-in", f("rcpt.der"), "-out", f("rcpt.pub"))
    run("genpkey", "-algorithm", "X448", "-out", f("eph.key"))
    eph_pub = raw_public(run("pkey", "-in", f("eph.key"), "-pubout", "-outform", "DER"))
    z = run("pkeyutl", "-derive", "-inkey", f("eph.key"), "-peerkey", f("rcpt.pub"))
    wrap_alg = seq(oid(WRAP[n]))
    kek = kek_of(kdf, z, ukm, shared_info(wrap_alg, ukm, n), n)
    cek = os.urandom(n)
    iv = os.urandom(16)
    ek = run("enc", "-id-aes%d-wrap" % (8 * n), "-K", kek.hex(), "-iv", "A6A6A6A6A6A6A6A6", input=cek)
    ct = run("enc", "-aes-%d-cbc" % (8 * n), "-K", cek.hex(), "-iv", iv.hex(), input=CONTENT)
    orig = ctx(0, ctx(1, seq(oid(OID_X448)) + bits(eph_pub)))
    kari = integer(3) + orig + (ctx(1, octets(ukm)) if ukm else b"") + seq(oid(KDF[kdf]), wrap_alg) + \
        seq(seq(issuer_and_serial(cert), octets(ek)))
    eci = seq(oid(OID_DATA), seq(oid(CBC[n]), octets(iv)), tlv(0x80, ct))
    ed = seq(integer(2), set_of(ctx(1, kari)), eci)
    return seq(oid(OID_ENVELOPED), ctx(0, ed))


# --- The vectors -----------------------------------------------------------------------

class Curves(PKI):
    def key(self, name, kind):
        out = self.path(f"{name}.key")
        if kind in CURVES:
            ossl("genpkey", "-algorithm", "EC", "-pkeyopt", f"ec_paramgen_curve:{CURVES[kind]}",
                 "-pkeyopt", "ec_param_enc:named_curve", "-out", out)
        elif kind in ("ed448", "x448"):
            ossl("genpkey", "-algorithm", kind.upper(), "-out", out)
        else:
            super().key(name, kind)

    def is_ed(self, name):
        return getattr(self, "kind", {}).get(name) in ("ed25519", "ed448")

    def cert(self, name, kind, subject, issuer=None, ext="", digest="sha256", **kw):
        # A self-signed Ed448 certificate takes no digest; the base class
        # knows only Ed25519's name for that.
        if issuer is None and kind == "ed448":
            self.kind = getattr(self, "kind", {})
            self.kind[name] = kind
        super().cert(name, kind, subject, issuer, ext, digest, **kw)

    def forced(self, name, kind, subject, issuer, ext, digest="sha256"):
        """A certificate for a key that cannot sign its request (X448)."""
        self.key(name, kind)
        with open(self.path(f"{name}.ext"), "w") as fh:
            fh.write(ext.replace(";", "\n") + "\n")
        ossl("pkey", "-in", self.path(f"{name}.key"), "-pubout", "-out", self.path(f"{name}.pub"))
        opts = [] if self.is_ed(issuer) else [f"-{digest}"]
        ossl("x509", "-new", "-force_pubkey", self.path(f"{name}.pub"), "-subj", subject,
             "-CA", self.path(f"{issuer}.pem"), "-CAkey", self.path(f"{issuer}.key"), *opts,
             "-not_before", gtime(NOW - 30 * DAY), "-not_after", gtime(NOW + 3650 * DAY),
             "-set_serial", str(0x1000 + len(self.der)), "-extfile", self.path(f"{name}.ext"),
             "-out", self.path(f"{name}.pem"))
        self.der[name] = ossl("x509", "-in", self.path(f"{name}.pem"), "-outform", "DER").stdout
        self.kind[name] = kind


def main():
    lines = []
    with tempfile.TemporaryDirectory() as tmp:
        f = lambda n: os.path.join(tmp, n)
        for kind, curve in CURVES.items():
            kp = f(kind + ".pem")
            ossl("genpkey", "-algorithm", "EC", "-pkeyopt", f"ec_paramgen_curve:{curve}",
                 "-pkeyopt", "ec_param_enc:named_curve", "-out", kp)
            pkcs8 = run("pkey", "-in", kp, "-outform", "DER")
            sec1 = run("ec", "-in", kp, "-outform", "DER")
            spki = run("pkey", "-in", kp, "-pubout", "-outform", "DER")
            lines.append(f"eckey {kind} {pkcs8.hex()} {sec1.hex()} {spki.hex()}")
        for kind in ("ed448", "x448"):
            kp = f(kind + ".pem")
            ossl("genpkey", "-algorithm", kind.upper(), "-out", kp)
            pkcs8 = run("pkey", "-in", kp, "-outform", "DER")
            spki = run("pkey", "-in", kp, "-pubout", "-outform", "DER")
            # OneAsymmetricKey v2 (RFC 5958): version 1 and [1] publicKey.
            p = children(pkcs8)
            v2 = seq(integer(1), pkcs8[p[1][1]:p[1][3]], pkcs8[p[2][1]:p[2][3]], tlv(0x81, b"\x00" + raw_public(spki)))
            lines.append(f"okpkey {kind} {pkcs8.hex()} {spki.hex()} {v2.hex()}")

        pki = Curves(tmp)
        pki.cert("bp_root", "bp512", "/CN=Goose Brainpool Root/O=Goose", ext=CA, digest="sha512")
        pki.cert("bp_int", "bp384", "/CN=Goose Brainpool Issuing/O=Goose", "bp_root", ext=CA, digest="sha512")
        pki.cert("leaf_ed448", "ed448", "/CN=example.com", "bp_int", ext=LEAF, digest="sha384")
        pki.cert("leaf_bp256", "bp256", "/CN=example.com", "bp_int", ext=LEAF, digest="sha384")
        pki.cert("ed_root", "ed448", "/CN=Goose Ed448 Root/O=Goose", ext=CA)
        pki.cert("leaf_by_ed448", "bp384", "/CN=example.com", "ed_root", ext=LEAF)
        pki.cert("ed_other_root", "ed448", "/CN=Goose Ed448 Root/O=Goose", ext=CA)
        pki.forced("leaf_x448", "x448", "/CN=X448 (test)", "bp_int",
                   "basicConstraints=CA:FALSE;keyUsage=critical,keyAgreement;subjectKeyIdentifier=hash", digest="sha384")
        for kind in ("bp256", "bp384", "bp512", "ed448"):
            pki.cert("sm_" + kind, kind, f"/CN=S-MIME {kind} (test)", "bp_int", ext=SMIME, digest="sha384")
        for name in ("leaf_x448", "sm_bp256", "sm_bp384", "sm_bp512", "sm_ed448"):
            lines.append(f"key {name} {run('pkey', '-in', pki.path(name + '.key'), '-outform', 'DER').hex()}")
        for name in pki.der:
            lines.append(f"cert {name} {pki.der[name].hex()}")

        def case(label, leaf, inters, roots, host, want):
            with open(f("chain.pem"), "w") as fh:
                for i in inters:
                    fh.write(open(pki.path(f"{i}.pem")).read())
            with open(f("roots.pem"), "w") as fh:
                for r in roots:
                    fh.write(open(pki.path(f"{r}.pem")).read())
            args = ["verify", "-attime", str(NOW), "-CAfile", f("roots.pem"), "-purpose", "sslserver"]
            if inters:
                args += ["-untrusted", f("chain.pem")]
            if host != "-":
                args += ["-verify_hostname", host]
            ok = ossl(*args, pki.path(f"{leaf}.pem"), check=False).returncode == 0
            assert ok == (want == "ok"), (label, want)
            lines.append(f"case {label} {leaf} {','.join(inters) or '-'} {','.join(roots)} {NOW} {host} {ERR[want]}")

        case("ed448_leaf_under_brainpool", "leaf_ed448", ["bp_int"], ["bp_root"], "www.example.com", "ok")
        case("brainpool_p256_leaf", "leaf_bp256", ["bp_int"], ["bp_root"], "example.com", "ok")
        case("brainpool_leaf_under_ed448", "leaf_by_ed448", [], ["ed_root"], "example.com", "ok")
        case("ed448_wrong_issuer_key", "leaf_by_ed448", [], ["ed_other_root"], "-", "bad_signature")
        case("brainpool_no_root", "leaf_bp256", ["bp_int"], ["ed_root"], "-", "unknown_issuer")
        case("brainpool_wrong_host", "leaf_bp256", ["bp_int"], ["bp_root"], "example.org", "hostname")

        for kind in ("bp384", "ed448"):
            pki.key("csr_" + kind, kind)
            csr = run("req", "-new", "-key", pki.path(f"csr_{kind}.key"), "-subj", "/CN=csr.example.com/O=Goose",
                      "-addext", "subjectAltName=DNS:csr.example.com", "-outform", "DER")
            lines.append(f"csr csr_{kind} {csr.hex()}")
        pki.crl("crl_bp", "bp_int", [("leaf_bp256", "keyCompromise")], md="sha384")
        lines.append(f"crl crl_bp bp_int leaf_bp256 {pki.crls['crl_bp'].hex()}")
        pki.crl("crl_ed", "ed_root", [("leaf_by_ed448", "superseded")], md="default")
        lines.append(f"crl crl_ed ed_root leaf_by_ed448 {pki.crls['crl_ed'].hex()}")

        for name in ("sm_bp384", "sm_ed448"):
            pfx = run("pkcs12", "-export", "-inkey", pki.path(name + ".key"), "-in", pki.path(name + ".pem"),
                      "-passout", "pass:goose-test")
            lines.append(f"p12 {name} goose-test {pfx.hex()} "
                         f"{run('pkey', '-in', pki.path(name + '.key'), '-outform', 'DER').hex()}")

        with open(f("content"), "wb") as fh:
            fh.write(CONTENT)

        def sign(label, who, *extra):
            der = run("cms", "-sign", "-binary", "-nodetach", "-outform", "DER", "-in", f("content"),
                      "-signer", pki.path(who + ".pem"), "-inkey", pki.path(who + ".key"), *extra)
            lines.append(f"signed {label} {who} {der.hex()}")

        sign("bp256-sha256", "sm_bp256", "-md", "sha256")
        sign("bp384-sha384", "sm_bp384", "-md", "sha384")
        sign("bp512-sha512", "sm_bp512", "-md", "sha512")
        sign("bp256-noattr", "sm_bp256", "-noattr")
        sign("bp384-keyid", "sm_bp384", "-keyid", "-md", "sha384")
        sign("ed448-noattr", "sm_ed448", "-noattr")
        lines.append(f"signed ed448-attrs sm_ed448 {ed448_signed(tmp, pki.path('sm_ed448.key'), pki.der['sm_ed448']).hex()}")

        def enc(label, who, *extra):
            der = run("cms", "-encrypt", "-binary", "-outform", "DER", "-in", f("content"), *extra)
            lines.append(f"enveloped {label} {who} {der.hex()}")

        enc("bp256-sha1kdf", "sm_bp256", pki.path("sm_bp256.pem"))
        enc("bp384-sha384kdf", "sm_bp384", "-recip", pki.path("sm_bp384.pem"), "-keyopt", "ecdh_kdf_md:sha384")
        enc("bp512-gcm", "sm_bp512", "-aes-128-gcm", pki.path("sm_bp512.pem"))
        enc("bp256-keyid", "sm_bp256", "-keyid", pki.path("sm_bp256.pem"))
        enc("bp-multi", "sm_bp384", pki.path("sm_bp256.pem"), pki.path("sm_bp384.pem"), pki.path("sm_bp512.pem"))
        for label, kdf, n, ukm in (("x448-x963-sha512", "x963-sha512", 32, b""),
                                   ("x448-hkdf-sha512-ukm", "hkdf-sha512", 16, b"goose ukm 0123456789"),
                                   ("x448-hkdf-sha256", "hkdf-sha256", 32, b"")):
            der = x448_enveloped(tmp, pki.der["leaf_x448"], kdf, n, ukm)
            lines.append(f"enveloped {label} leaf_x448 {der.hex()}")

    with open(os.path.join(ROOT, "test", "vectors", "curves.txt"), "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"wrote test/vectors/curves.txt: {len(lines)} lines")


if __name__ == "__main__":
    main()
