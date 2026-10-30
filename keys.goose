// x509.keys: private and public keys in their DER forms, and signing.
// Parsing and marshalling PKCS #8 (RSA, EC, Ed25519, ML-DSA, DSA), SEC 1
// (EC), PKCS #1 (RSA) and SubjectPublicKeyInfo, as Go's x509 Parse/Marshal
// functions do; key generation; and signatures in the forms X.509 and
// TLS carry them (ECDSA and DSA as DER), with their AlgorithmIdentifiers.
//
// ML-DSA private keys are their 32-byte seed (RFC 9881). PKCS #8 carries
// the seed alone ([0] IMPLICIT OCTET STRING, what Go and this package
// write) or the seed with the expanded key (openssl's default, read only
// when the two agree); the expanded key without its seed is refused, as
// Go refuses it. DSA keys go beyond Go, which has no DSA private keys in
// x509: PKCS #8 and openssl's "DSA PRIVATE KEY" are read, PKCS #8 written.

namespace x509;

import std;
import x509;
import asn1;
import bignum;
import bignum.rsa;
import bignum.ec;
import bignum.ed25519;
import bignum.mldsa;
import bignum.dsa;
import bignum.hmac;
import bignum.entropy;

// A private key of one of the KEY_* types: an EC scalar (big-endian, the
// curve's length), an Ed25519 or ML-DSA seed, a DSA key, or an RSA key.
struct PrivateKey { kind: i64, ec_sk: u8[..66], seed: u8[32], dsa: bignum::DsaKey, rsa: bignum::RsaPrivateKey }

fn empty_key() -> PrivateKey {
    PrivateKey { kind: KEY_UNKNOWN, ec_sk: [], seed: [0; 32], dsa: bignum::DsaKey { p: [], q: [], g: [], y: [], x: [] },
                 rsa: bignum::RsaPrivateKey { n: [], e: [], d: [], p: [], q: [], dp: [], dq: [], qinv: [] } }
}

fn curve_oid(kind: i64) -> const u8[:] {
    if kind == KEY_EC_P256 { "1.2.840.10045.3.1.7" } else if kind == KEY_EC_P384 { "1.3.132.0.34" }
    else if kind == KEY_EC_P224 { "1.3.132.0.33" } else { "1.3.132.0.35" }
}

// A new key from the OS's entropy; `bits` is the modulus size of RSA
// keys and the size of p for DSA keys (with a 256-bit q; 160 bits for p
// of 1024, which takes nothing larger).
fn generate_key(kind: i64, bits: i64 = 2048) -> PrivateKey {
    var k = empty_key();
    k.kind = kind;
    if kind == KEY_RSA {
        k.rsa = bignum::rsa_generate(bits);
    } else if is_mldsa(kind) {
        let seed, pk = bignum::mldsa_keygen(mldsa_set(kind));
        for i in 32 { k.seed[i] = seed[i]; }
    } else if kind == KEY_DSA {
        let p, q, g = bignum::dsa_generate_parameters(bits, if bits == 1024 { 160 } else { 256 });
        let dk, ok = bignum::dsa_generate_key(p, q, g);
        assert(ok);
        k.dsa = dk;
    } else if kind == KEY_ED25519 {
        let seed, pk = bignum::ed25519_keypair();
        for i in 32 { k.seed[i] = seed[i]; }
    } else {
        assert(is_ec(kind));
        let c = curve_of_key(kind);
        let sk, pk = bignum::ec_keypair(c);
        k.ec_sk.append(sk);
    }
    return k;
}

// --- Parsing ----------------------------------------------------------------

fn parse_rsa_private(k: PrivateKey&, d: const u8[:], t: asn1::Tlv) -> bool {
    let f, ok = asn1::children_of(d, t, asn1::SEQUENCE);
    if !ok || f.len != 9 { return false; }
    let v, okv = asn1::read_i64(d, f[0]);
    if !okv || v != 0 { return false; }                  // two-prime keys only
    let n, ok1 = asn1::read_uint(d, f[1]);
    let e, ok2 = asn1::read_uint(d, f[2]);
    let dd, ok3 = asn1::read_uint(d, f[3]);
    let p, ok4 = asn1::read_uint(d, f[4]);
    let q, ok5 = asn1::read_uint(d, f[5]);
    if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 { return false; }
    let rk, okk = bignum::rsa_key_from_bytes(n, e, dd, p, q);    // in constant time
    if !okk { return false; }
    k.rsa = rk;
    k.kind = KEY_RSA;
    return true;
}

// ECPrivateKey ::= SEQUENCE { 1, privateKey OCTET STRING, [0] curve OPTIONAL, [1] public OPTIONAL }
fn parse_ec_private(k: PrivateKey&, d: const u8[:], t: asn1::Tlv, curve: i64) -> bool {
    let f, ok = asn1::children_of(d, t, asn1::SEQUENCE);
    if !ok || f.len < 2 || f.len > 4 { return false; }
    let v, okv = asn1::read_i64(d, f[0]);
    let sk, oks = asn1::read_octets(d, f[1]);
    if !okv || v != 1 || !oks { return false; }
    var kind = curve;
    for x in f[2..] {
        if x.tag == asn1::ctx(0, true) {
            let o, oko = asn1::explicit(d, x);
            let named = ec_named_curve(d, o);
            if named == KEY_UNKNOWN || (kind != KEY_UNKNOWN && kind != named) { return false; }
            kind = named;
        } else if x.tag != asn1::ctx(1, true) {
            return false;
        }
    }
    if !is_ec(kind) { return false; }
    let c = curve_of_key(kind);
    if sk.len != c.len { return false; }
    let scalar, okc = bignum::ec_scalar(c, sk);
    if !okc { return false; }
    k.ec_sk.clear();
    k.ec_sk.append(sk);
    k.kind = kind;
    return true;
}

// ML-DSA-PrivateKey ::= CHOICE { seed [0] IMPLICIT OCTET STRING (SIZE (32)),
// expandedKey OCTET STRING, both SEQUENCE { seed, expandedKey } }.
fn parse_mldsa_private(k: PrivateKey&, d: const u8[:], t: asn1::Tlv, set: i64) -> bool {
    var seed: u8[>..] = [];
    if t.tag == asn1::ctx(0, false) {
        seed.append(d[t.off..t.end]);
    } else if t.tag == asn1::SEQUENCE {
        let f, ok = asn1::children(d, t);
        if !ok || f.len != 2 { return false; }
        let s, ok1 = asn1::read_octets(d, f[0]);
        let e, ok2 = asn1::read_octets(d, f[1]);
        if !ok1 || !ok2 || s.len != 32 || e.len != bignum::mldsa_sk_len(set) { return false; }
        if bignum::mldsa_expand_key(set, s) != e { return false; }
        seed.append(s);
    } else {
        return false;
    }
    if seed.len != 32 { return false; }
    for i in 32 { k.seed[i] = seed[i]; }
    k.kind = mldsa_kind(set);
    return true;
}

// A DSA key from its parameters and x, with y = g^x mod p.
fn dsa_private(k: PrivateKey&, p: const u8[:], q: const u8[:], g: const u8[:], x: const u8[:], y: const u8[:] = "") -> bool {
    let pub, okp = bignum::dsa_key_from(p, q, g, g);    // checks p, q and g first
    if !okp || x.len > q.len { return false; }
    let gx = bignum::dsa_powmod(g, x, p);
    if y.len > 0 && bignum::cmp(bignum::from_bytes_be(gx), bignum::from_bytes_be(y)) != 0 { return false; }
    let dk, ok = bignum::dsa_key_from(p, q, g, gx, x);
    if !ok { return false; }
    k.dsa = dk;
    k.kind = KEY_DSA;
    return true;
}

// DSAPrivateKey (openssl's "DSA PRIVATE KEY") ::= SEQUENCE { 0, p, q, g, y, x }.
fn parse_dsa_legacy(k: PrivateKey&, d: const u8[:], f: const asn1::Tlv[:]) -> bool {
    let v, okv = asn1::read_i64(d, f[0]);
    let p, ok1 = asn1::read_uint(d, f[1]);
    let q, ok2 = asn1::read_uint(d, f[2]);
    let g, ok3 = asn1::read_uint(d, f[3]);
    let y, ok4 = asn1::read_uint(d, f[4]);
    let x, ok5 = asn1::read_uint(d, f[5]);
    if !okv || v != 0 || !ok1 || !ok2 || !ok3 || !ok4 || !ok5 { return false; }
    return dsa_private(k, p, q, g, x, y);
}

// A private key in PKCS #8, SEC 1, PKCS #1 or openssl's DSA DER
// (ParsePKCS8PrivateKey, ParseECPrivateKey and ParsePKCS1PrivateKey in one).
fn parse_private_key(d: const u8[:]) -> PrivateKey, bool {
    var k = empty_key();
    let top, ok = asn1::parse(d);
    let f, okf = asn1::children_of(d, top, asn1::SEQUENCE);
    if !ok || !okf || f.len < 2 { return k, false; }
    if f.len >= 3 && f[1].tag == asn1::SEQUENCE && f[2].tag == asn1::OCTET_STRING {
        // PrivateKeyInfo: version 0 (or 1 with a public key), algorithm, key.
        let alg, oka = asn1::children(d, f[1]);
        if !oka || alg.len < 1 { return k, false; }
        let inner, oki = asn1::read(d, f[2].off, f[2].end);
        if !oki || inner.end != f[2].end { return k, false; }
        if asn1::oid_is(d, alg[0], "1.2.840.113549.1.1.1") {
            if alg.len != 2 || !asn1::read_null(d, alg[1]) { return k, false; }
            let okr = parse_rsa_private(k, d, inner);
            return k, okr;
        }
        if asn1::oid_is(d, alg[0], "1.3.101.112") {
            let seed, okseed = asn1::read_octets(d, inner);
            if alg.len != 1 || !okseed || seed.len != 32 { return k, false; }
            for i in 32 { k.seed[i] = seed[i]; }
            k.kind = KEY_ED25519;
            return k, true;
        }
        let set = mldsa_set_of_oid(d, alg[0]);
        if set != 0 {
            if alg.len != 1 { return k, false; }
            let okm = parse_mldsa_private(k, d, inner, set);
            return k, okm;
        }
        if asn1::oid_is(d, alg[0], "1.2.840.10040.4.1") {
            if alg.len != 2 { return k, false; }
            let p, q, g, okp = dss_parms(d, alg[1]);
            let x, okx = asn1::read_uint(d, inner);
            if !okp || !okx { return k, false; }
            let okd = dsa_private(k, p, q, g, x);
            return k, okd;
        }
        if asn1::oid_is(d, alg[0], "1.2.840.10045.2.1") && alg.len == 2 {
            let curve = ec_named_curve(d, alg[1]);
            if curve == KEY_UNKNOWN { return k, false; }
            let oke = parse_ec_private(k, d, inner, curve);
            return k, oke;
        }
        return k, false;
    }
    if f.len == 9 { let okr = parse_rsa_private(k, d, top); return k, okr; }
    if f.len == 6 { let okd = parse_dsa_legacy(k, d, f); return k, okd; }
    if f[1].tag == asn1::OCTET_STRING { let oke = parse_ec_private(k, d, top, KEY_UNKNOWN); return k, oke; }
    return k, false;
}

// The first private key in a PEM text ("PRIVATE KEY", "EC PRIVATE KEY",
// "RSA PRIVATE KEY" or "DSA PRIVATE KEY").
fn parse_private_key_pem(text: const u8[:]) -> PrivateKey, bool {
    let ders, ok = asn1::pem_decode(text, "");
    for d in ders {
        let k, okk = parse_private_key(d);
        if okk { return k, true; }
    }
    return empty_key(), false;
}

// --- Marshalling ------------------------------------------------------------

fn put_limbs_uint(out: u8[>..]&, xs) {
    let v = bignum::big_of(xs);
    let b = bignum::to_bytes_be(v, (bignum::bit_len(v) + 7) / 8);
    asn1::put_uint(out, b);
}

fn seq(out: u8[>..]&, content: const u8[:]) { asn1::put(out, asn1::SEQUENCE, content); }

// The public key as its subjectPublicKey contents: RSAPublicKey DER, the
// uncompressed EC point, the Ed25519 or ML-DSA key, or the DSA INTEGER y.
fn public_key_bytes(k: const PrivateKey&) -> u8[>..] {
    var out: u8[>..] = [];
    if k.kind == KEY_RSA {
        var body: u8[>..] = [];
        put_limbs_uint(body, k.rsa.n);
        put_limbs_uint(body, k.rsa.e);
        seq(out, body);
    } else if k.kind == KEY_ED25519 {
        out.append(bignum::ed25519_public(k.seed));
    } else if is_mldsa(k.kind) {
        out = bignum::mldsa_public_key(mldsa_set(k.kind), k.seed);
    } else if k.kind == KEY_DSA {
        asn1::put_uint(out, k.dsa.y);
    } else {
        let c = curve_of_key(k.kind);
        out = bignum::ec_public_key(c, k.ec_sk);
    }
    return out;
}

fn mldsa_oid(set: i64) -> const u8[:] {
    if set == 44 { "2.16.840.1.101.3.4.3.17" } else if set == 65 { "2.16.840.1.101.3.4.3.18" } else { "2.16.840.1.101.3.4.3.19" }
}

// The public key's AlgorithmIdentifier.
fn key_alg_id(k: const PrivateKey&) -> u8[>..] {
    let kind = k.kind;
    var body: u8[>..] = [];
    if kind == KEY_RSA {
        asn1::put_oid(body, "1.2.840.113549.1.1.1");
        asn1::put_null(body);
    } else if kind == KEY_ED25519 {
        asn1::put_oid(body, "1.3.101.112");
    } else if is_mldsa(kind) {
        asn1::put_oid(body, mldsa_oid(mldsa_set(kind)));
    } else if kind == KEY_DSA {
        asn1::put_oid(body, "1.2.840.10040.4.1");
        var params: u8[>..] = [];
        asn1::put_uint(params, k.dsa.p);
        asn1::put_uint(params, k.dsa.q);
        asn1::put_uint(params, k.dsa.g);
        seq(body, params);
    } else {
        asn1::put_oid(body, "1.2.840.10045.2.1");
        asn1::put_oid(body, curve_oid(kind));
    }
    var out: u8[>..] = [];
    seq(out, body);
    return out;
}

// SubjectPublicKeyInfo (MarshalPKIXPublicKey).
fn marshal_public_key(k: const PrivateKey&) -> u8[>..] {
    var body = key_alg_id(k);
    asn1::put_bits(body, public_key_bytes(k));
    var out: u8[>..] = [];
    seq(out, body);
    return out;
}

// RSAPrivateKey (MarshalPKCS1PrivateKey).
fn marshal_pkcs1(k: const PrivateKey&) -> u8[>..] {
    assert(k.kind == KEY_RSA);
    var body: u8[>..] = [];
    asn1::put_i64(body, 0);
    put_limbs_uint(body, k.rsa.n);
    put_limbs_uint(body, k.rsa.e);
    put_limbs_uint(body, k.rsa.d);
    put_limbs_uint(body, k.rsa.p);
    put_limbs_uint(body, k.rsa.q);
    put_limbs_uint(body, k.rsa.dp);
    put_limbs_uint(body, k.rsa.dq);
    put_limbs_uint(body, k.rsa.qinv);
    var out: u8[>..] = [];
    seq(out, body);
    return out;
}

// ECPrivateKey (MarshalECPrivateKey): with the curve when standalone,
// without it inside PKCS #8; the public key always.
fn marshal_ec(k: const PrivateKey&, with_curve: bool) -> u8[>..] {
    assert(is_ec(k.kind));
    var body: u8[>..] = [];
    asn1::put_i64(body, 1);
    asn1::put_octets(body, k.ec_sk);
    if with_curve {
        var o: u8[>..] = [];
        asn1::put_oid(o, curve_oid(k.kind));
        asn1::put(body, asn1::ctx(0, true), o);
    }
    var pk: u8[>..] = [];
    asn1::put_bits(pk, public_key_bytes(k));
    asn1::put(body, asn1::ctx(1, true), pk);
    var out: u8[>..] = [];
    seq(out, body);
    return out;
}

fn marshal_sec1(k: const PrivateKey&) -> u8[>..] { marshal_ec(k, true) }

// PrivateKeyInfo (MarshalPKCS8PrivateKey).
fn marshal_pkcs8(k: const PrivateKey&) -> u8[>..] {
    var body: u8[>..] = [];
    asn1::put_i64(body, 0);
    body.append(key_alg_id(k));
    var inner: u8[>..] = [];
    if k.kind == KEY_RSA { inner = marshal_pkcs1(k); }
    else if k.kind == KEY_ED25519 { asn1::put_octets(inner, k.seed); }
    else if is_mldsa(k.kind) { asn1::put(inner, asn1::ctx(0, false), k.seed); }
    else if k.kind == KEY_DSA { asn1::put_uint(inner, k.dsa.x); }
    else { inner = marshal_ec(k, false); }
    asn1::put_octets(body, inner);
    var out: u8[>..] = [];
    seq(out, body);
    return out;
}

// --- Signing ------------------------------------------------------------------

// The signature algorithm a key signs with by default: PKCS #1 v1.5 with
// SHA-256 for RSA (as Go), ECDSA with the curve's hash (SHA-256 for P-224,
// as Go), Ed25519, ML-DSA of the key's set, DSA with SHA-256 (as openssl).
fn default_sig(kind: i64) -> i64, i64 {
    if kind == KEY_RSA { return SIG_RSA_PKCS1, 256; }
    if kind == KEY_ED25519 { return SIG_ED25519, 0; }
    if is_mldsa(kind) { return SIG_MLDSA, mldsa_set(kind); }
    if kind == KEY_DSA { return SIG_DSA, 256; }
    if kind == KEY_EC_P256 || kind == KEY_EC_P224 { return SIG_ECDSA, 256; }
    if kind == KEY_EC_P384 { return SIG_ECDSA, 384; }
    return SIG_ECDSA, 512;
}

fn hash_oid(h: i64) -> const u8[:] {
    if h == 256 { "2.16.840.1.101.3.4.2.1" } else if h == 384 { "2.16.840.1.101.3.4.2.2" } else { "2.16.840.1.101.3.4.2.3" }
}

// The AlgorithmIdentifier of a signature algorithm and hash.
fn sig_alg_id(alg: i64, h: i64) -> u8[>..] {
    var body: u8[>..] = [];
    if alg == SIG_RSA_PKCS1 {
        asn1::put_oid(body, if h == 256 { "1.2.840.113549.1.1.11" } else if h == 384 { "1.2.840.113549.1.1.12" } else { "1.2.840.113549.1.1.13" });
        asn1::put_null(body);
    } else if alg == SIG_ECDSA {
        asn1::put_oid(body, if h == 256 { "1.2.840.10045.4.3.2" } else if h == 384 { "1.2.840.10045.4.3.3" } else { "1.2.840.10045.4.3.4" });
    } else if alg == SIG_ED25519 {
        asn1::put_oid(body, "1.3.101.112");
    } else if alg == SIG_MLDSA {
        asn1::put_oid(body, mldsa_oid(h));
    } else if alg == SIG_DSA {
        asn1::put_oid(body, if h == 224 { "2.16.840.1.101.3.4.3.1" } else if h == 256 { "2.16.840.1.101.3.4.3.2" }
                            else if h == 384 { "2.16.840.1.101.3.4.3.3" } else { "2.16.840.1.101.3.4.3.4" });
    } else {
        // RSASSA-PSS-params: the hash, MGF1 over it, a salt as long as it.
        asn1::put_oid(body, "1.2.840.113549.1.1.10");
        var hid: u8[>..] = [];
        var hb: u8[>..] = [];
        asn1::put_oid(hb, hash_oid(h));
        asn1::put_null(hb);
        seq(hid, hb);
        var params: u8[>..] = [];
        asn1::put(params, asn1::ctx(0, true), hid);
        var mgf: u8[>..] = [];
        asn1::put_oid(mgf, "1.2.840.113549.1.1.8");
        mgf.append(hid);
        var mgfs: u8[>..] = [];
        seq(mgfs, mgf);
        asn1::put(params, asn1::ctx(1, true), mgfs);
        var salt: u8[>..] = [];
        asn1::put_i64(salt, h / 8);
        asn1::put(params, asn1::ctx(2, true), salt);
        seq(body, params);
    }
    var out: u8[>..] = [];
    seq(out, body);
    return out;
}

// Whether a key can sign with an algorithm.
fn sig_fits_key(kind: i64, alg: i64, h: i64) -> bool {
    if alg == SIG_RSA_PKCS1 || alg == SIG_RSA_PSS { return kind == KEY_RSA && (h == 256 || h == 384 || h == 512); }
    if alg == SIG_ECDSA { return is_ec(kind) && (h == 256 || h == 384 || h == 512); }
    if alg == SIG_ED25519 { return kind == KEY_ED25519; }
    if alg == SIG_MLDSA { return is_mldsa(kind) && mldsa_set(kind) == h; }
    if alg == SIG_DSA { return kind == KEY_DSA && (h == 224 || h == 256 || h == 384 || h == 512); }
    return false;
}

// A signature over msg and true: PKCS #1 v1.5 or PSS (salt as long as the
// hash), ECDSA or DSA as a DER SEQUENCE (RFC 6979 nonces), Ed25519, or
// ML-DSA (hedged, with the empty context). Empty and false when RSA's
// private operation fails its check (a fault), as Go's Sign returns an
// error, or for an RSA key too small for the hash.
fn sign(k: const PrivateKey&, alg: i64, h: i64, msg: const u8[:]) -> u8[>..], bool {
    assert(sig_fits_key(k.kind, alg, h));
    var out: u8[>..] = [];
    if alg == SIG_ED25519 { out.append(bignum::ed25519_sign(k.seed, msg)); return out, true; }
    if alg == SIG_MLDSA { out.append(bignum::mldsa_sign(h, k.seed, msg)); return out, true; }
    let s, ok = sign_digest(k, alg, h, bignum::hash_bits(h, msg));
    return s, ok;
}

// The same over a digest made by the hash h, as Go's crypto.Signer takes
// one: RSA, ECDSA and DSA; empty and false for Ed25519 and ML-DSA, which
// sign messages, not digests, and for a digest of another length.
fn sign_digest(k: const PrivateKey&, alg: i64, h: i64, digest: const u8[:]) -> u8[>..], bool {
    assert(sig_fits_key(k.kind, alg, h));
    var out: u8[>..] = [];
    if alg == SIG_ED25519 || alg == SIG_MLDSA || digest.len != bignum::hash_len(h) { return out, false; }
    if alg == SIG_RSA_PKCS1 {
        let s, ok = bignum::rsa_sign_pkcs1_digest(k.rsa, digest, h);
        return s, ok;
    }
    if alg == SIG_RSA_PSS {
        let s, ok = bignum::rsa_sign_pss_digest(k.rsa, digest, -1, h);
        return s, ok;
    }
    if alg == SIG_DSA {
        out.append(bignum::dsa_sig_to_der(bignum::dsa_sign_deterministic(k.dsa, digest, h)));
    } else {
        let c = curve_of_key(k.kind);
        out.append(bignum::ecdsa_sig_to_der(bignum::ecdsa_sign_digest(c, k.ec_sk, digest, h)));
    }
    return out, true;
}
