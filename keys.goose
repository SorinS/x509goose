// x509.keys: private and public keys in their DER forms, and signing.
// Parsing and marshalling PKCS #8 (RSA, EC, Ed25519), SEC 1 (EC),
// PKCS #1 (RSA) and SubjectPublicKeyInfo, as Go's x509 Parse/Marshal
// functions do; key generation; and signatures in the forms X.509 and
// TLS carry them (ECDSA as DER), with their AlgorithmIdentifiers.

namespace x509;

import std;
import x509;
import asn1;
import bignum;
import bignum.rsa;
import bignum.ec;
import bignum.ed25519;
import bignum.hmac;
import bignum.entropy;

// A private key of one of the KEY_* types: an EC scalar (big-endian, the
// curve's length), an Ed25519 seed, or an RSA key.
struct PrivateKey { kind: i64, ec_sk: u8[..66], ed_seed: u8[32], rsa: bignum::RsaPrivateKey }

fn empty_key() -> PrivateKey {
    PrivateKey { kind: KEY_UNKNOWN, ec_sk: [], ed_seed: [0; 32],
                 rsa: bignum::RsaPrivateKey { n: [], e: [], d: [], p: [], q: [], dp: [], dq: [], qinv: [] } }
}

fn curve_oid(kind: i64) -> const u8[:] {
    if kind == KEY_EC_P256 { "1.2.840.10045.3.1.7" } else if kind == KEY_EC_P384 { "1.3.132.0.34" }
    else if kind == KEY_EC_P224 { "1.3.132.0.33" } else { "1.3.132.0.35" }
}

// A new key from the OS's entropy; rsa_bits for RSA keys.
fn generate_key(kind: i64, rsa_bits: i64 = 2048) -> PrivateKey {
    var k = empty_key();
    k.kind = kind;
    if kind == KEY_RSA {
        k.rsa = bignum::rsa_generate(rsa_bits);
    } else if kind == KEY_ED25519 {
        let seed, pk = bignum::ed25519_keypair();
        for i in 32 { k.ed_seed[i] = seed[i]; }
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
    let rk, okk = bignum::rsa_key_from(bignum::from_bytes_be(n), bignum::from_bytes_be(e), bignum::from_bytes_be(dd),
                                       bignum::from_bytes_be(p), bignum::from_bytes_be(q));
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

// A private key in PKCS #8, SEC 1 or PKCS #1 DER (ParsePKCS8PrivateKey,
// ParseECPrivateKey and ParsePKCS1PrivateKey in one).
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
            for i in 32 { k.ed_seed[i] = seed[i]; }
            k.kind = KEY_ED25519;
            return k, true;
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
    if f[1].tag == asn1::OCTET_STRING { let oke = parse_ec_private(k, d, top, KEY_UNKNOWN); return k, oke; }
    return k, false;
}

// The first private key in a PEM text ("PRIVATE KEY", "EC PRIVATE KEY" or
// "RSA PRIVATE KEY").
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
// uncompressed EC point, or the Ed25519 key.
fn public_key_bytes(k: const PrivateKey&) -> u8[>..] {
    var out: u8[>..] = [];
    if k.kind == KEY_RSA {
        var body: u8[>..] = [];
        put_limbs_uint(body, k.rsa.n);
        put_limbs_uint(body, k.rsa.e);
        seq(out, body);
    } else if k.kind == KEY_ED25519 {
        out.append(bignum::ed25519_public(k.ed_seed));
    } else {
        let c = curve_of_key(k.kind);
        out = bignum::ec_public_key(c, k.ec_sk);
    }
    return out;
}

// The public key's AlgorithmIdentifier.
fn key_alg_id(kind: i64) -> u8[>..] {
    var body: u8[>..] = [];
    if kind == KEY_RSA {
        asn1::put_oid(body, "1.2.840.113549.1.1.1");
        asn1::put_null(body);
    } else if kind == KEY_ED25519 {
        asn1::put_oid(body, "1.3.101.112");
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
    var body = key_alg_id(k.kind);
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
    body.append(key_alg_id(k.kind));
    var inner: u8[>..] = [];
    if k.kind == KEY_RSA { inner = marshal_pkcs1(k); }
    else if k.kind == KEY_ED25519 { asn1::put_octets(inner, k.ed_seed); }
    else { inner = marshal_ec(k, false); }
    asn1::put_octets(body, inner);
    var out: u8[>..] = [];
    seq(out, body);
    return out;
}

// --- Signing ------------------------------------------------------------------

// The signature algorithm a key signs with by default: PKCS #1 v1.5 with
// SHA-256 for RSA (as Go), ECDSA with the curve's hash (SHA-256 for P-224,
// as Go), Ed25519.
fn default_sig(kind: i64) -> i64, i64 {
    if kind == KEY_RSA { return SIG_RSA_PKCS1, 256; }
    if kind == KEY_ED25519 { return SIG_ED25519, 0; }
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
    return false;
}

// A signature over msg: PKCS #1 v1.5 or PSS (salt as long as the hash),
// ECDSA as a DER SEQUENCE (RFC 6979 nonces), or Ed25519.
fn sign(k: const PrivateKey&, alg: i64, h: i64, msg: const u8[:]) -> u8[>..] {
    assert(sig_fits_key(k.kind, alg, h));
    var out: u8[>..] = [];
    if alg == SIG_RSA_PKCS1 { return bignum::rsa_sign_pkcs1(k.rsa, msg, h); }
    if alg == SIG_RSA_PSS { return bignum::rsa_sign_pss(k.rsa, msg, -1, h); }
    if alg == SIG_ED25519 { out.append(bignum::ed25519_sign(k.ed_seed, msg)); return out; }
    let c = curve_of_key(k.kind);
    // ecdsa_sign hashes with the curve's own hash; any other goes through
    // the digest.
    if h == c.hash { return bignum::ecdsa_sig_to_der(bignum::ecdsa_sign(c, k.ec_sk, msg)); }
    return bignum::ecdsa_sig_to_der(bignum::ecdsa_sign_digest(c, k.ec_sk, bignum::hash_bits(h, msg), h));
}
