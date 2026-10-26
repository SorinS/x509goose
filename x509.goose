// x509: X.509 certificates (RFC 5280) for the Goose language: parsing,
// names, subject alternative names, public keys, signature checking with
// bignum, host name matching (RFC 6125) and certification path validation.
//
// A Cert keeps its own copy of the DER and, for everything else, either
// decoded scalars (times, flags, lengths) or asn1::Tlv offsets into that
// copy. Lists of certificates (intermediates, roots) are DER concatenated
// back to back, which needs no framing because DER delimits itself.

namespace x509;

import std;
import asn1 from "../asn1goose.git";
import bignum from "../bigmongoose.git";
import bignum.rsa;
import bignum.ec;
import bignum.ed25519;
import bignum.hmac;

// Errors, from parsing or validation; OK is 0.
let OK: i64 = 0;
let ERR_MALFORMED: i64 = 1;
let ERR_UNSUPPORTED_ALGORITHM: i64 = 2;
let ERR_BAD_SIGNATURE: i64 = 3;
let ERR_EXPIRED: i64 = 4;
let ERR_NOT_YET_VALID: i64 = 5;
let ERR_UNKNOWN_ISSUER: i64 = 6;
let ERR_NOT_CA: i64 = 7;
let ERR_PATH_LENGTH: i64 = 8;
let ERR_KEY_USAGE: i64 = 9;
let ERR_EXTENDED_KEY_USAGE: i64 = 10;
let ERR_HOSTNAME: i64 = 11;
let ERR_UNKNOWN_CRITICAL_EXTENSION: i64 = 12;
let ERR_CHAIN_TOO_LONG: i64 = 13;
let ERR_NAME_CONSTRAINTS: i64 = 14;
let ERR_POLICY: i64 = 15;
let ERR_REVOKED: i64 = 16;
let ERR_REVOCATION_UNKNOWN: i64 = 17;

fn error_text(e: i64) -> const u8[:] {
    if e == OK { return "ok"; }
    if e == ERR_MALFORMED { return "malformed certificate"; }
    if e == ERR_UNSUPPORTED_ALGORITHM { return "unsupported algorithm"; }
    if e == ERR_BAD_SIGNATURE { return "bad signature"; }
    if e == ERR_EXPIRED { return "expired"; }
    if e == ERR_NOT_YET_VALID { return "not yet valid"; }
    if e == ERR_UNKNOWN_ISSUER { return "unknown issuer"; }
    if e == ERR_NOT_CA { return "issuer is not a CA"; }
    if e == ERR_PATH_LENGTH { return "path length constraint exceeded"; }
    if e == ERR_KEY_USAGE { return "key usage does not allow this"; }
    if e == ERR_EXTENDED_KEY_USAGE { return "extended key usage does not allow this"; }
    if e == ERR_HOSTNAME { return "host name does not match"; }
    if e == ERR_UNKNOWN_CRITICAL_EXTENSION { return "unknown critical extension"; }
    if e == ERR_CHAIN_TOO_LONG { return "chain too long"; }
    if e == ERR_NAME_CONSTRAINTS { return "name not allowed by a name constraint"; }
    if e == ERR_POLICY { return "no acceptable certificate policy"; }
    if e == ERR_REVOKED { return "revoked"; }
    if e == ERR_REVOCATION_UNKNOWN { return "revocation status unknown"; }
    return "unknown error";
}

// Signature algorithms.
let SIG_UNKNOWN: i64 = 0;
let SIG_RSA_PKCS1: i64 = 1;          // with sig_hash
let SIG_RSA_PSS: i64 = 2;            // with sig_hash and pss_salt
let SIG_ECDSA: i64 = 3;              // with sig_hash
let SIG_ED25519: i64 = 4;

// Public key types.
let KEY_UNKNOWN: i64 = 0;
let KEY_RSA: i64 = 1;
let KEY_EC_P256: i64 = 2;
let KEY_EC_P384: i64 = 3;
let KEY_ED25519: i64 = 4;
let KEY_EC_P521: i64 = 5;
let KEY_EC_P224: i64 = 6;

// Key usage bits (RFC 5280 §4.2.1.3), as KU_* masks of Cert.key_usage.
let KU_DIGITAL_SIGNATURE: u32 = 1;
let KU_NON_REPUDIATION: u32 = 2;
let KU_KEY_ENCIPHERMENT: u32 = 4;
let KU_DATA_ENCIPHERMENT: u32 = 8;
let KU_KEY_AGREEMENT: u32 = 16;
let KU_KEY_CERT_SIGN: u32 = 32;
let KU_CRL_SIGN: u32 = 64;

// Extended key usages, as EKU_* masks of Cert.ext_key_usage.
let EKU_ANY: u32 = 1;
let EKU_SERVER_AUTH: u32 = 2;
let EKU_CLIENT_AUTH: u32 = 4;
let EKU_CODE_SIGNING: u32 = 8;
let EKU_EMAIL_PROTECTION: u32 = 16;
let EKU_TIME_STAMPING: u32 = 32;
let EKU_OCSP_SIGNING: u32 = 64;
let EKU_OTHER: u32 = 128;

struct Cert {
    version: i64,                    // 1, 2 or 3
    serial: asn1::Tlv,               // INTEGER
    tbs: asn1::Tlv,                  // the signed part, header included
    sig_alg: i64, sig_hash: i64, pss_salt: i64,
    sig: asn1::Tlv,                  // the BIT STRING
    issuer: asn1::Tlv, subject: asn1::Tlv,   // Names, compared as DER
    not_before: i64, not_after: i64,         // seconds since 1970
    spki: asn1::Tlv,                 // SubjectPublicKeyInfo
    key_type: i64,
    key: asn1::Tlv,                  // the subjectPublicKey BIT STRING
    has_basic_constraints: bool, is_ca: bool, path_len: i64,   // path_len -1: none
    has_key_usage: bool, key_usage: u32,
    has_ext_key_usage: bool, ext_key_usage: u32,
    has_san: bool, san: asn1::Tlv,   // GeneralNames
    ski: asn1::Tlv, aki: asn1::Tlv,  // key identifiers (OCTET STRING content), or start == end
    has_name_constraints: bool, name_constraints: asn1::Tlv,   // NameConstraints
    has_policies: bool, policies: asn1::Tlv,                   // certificatePolicies
    has_policy_mappings: bool, policy_mappings: asn1::Tlv,     // PolicyMappings
    require_explicit_policy: i64, inhibit_policy_mapping: i64, // policyConstraints, -1: absent
    inhibit_any_policy: i64,                                   // -1: absent
    has_crl_dp: bool, crl_dp: asn1::Tlv,                       // CRLDistributionPoints
    unknown_critical: bool,
    der: u8[>..],
}

fn no_tlv() -> asn1::Tlv { asn1::Tlv { tag: 0, cls: 0, constructed: false, number: 0, start: 0, off: 0, end: 0 } }

fn empty_cert() -> Cert {
    Cert {
        version: 0, serial: no_tlv(), tbs: no_tlv(), sig_alg: SIG_UNKNOWN, sig_hash: 0, pss_salt: 0,
        sig: no_tlv(), issuer: no_tlv(), subject: no_tlv(), not_before: 0, not_after: 0,
        spki: no_tlv(), key_type: KEY_UNKNOWN, key: no_tlv(),
        has_basic_constraints: false, is_ca: false, path_len: -1,
        has_key_usage: false, key_usage: 0, has_ext_key_usage: false, ext_key_usage: 0,
        has_san: false, san: no_tlv(), ski: no_tlv(), aki: no_tlv(),
        has_name_constraints: false, name_constraints: no_tlv(), has_policies: false, policies: no_tlv(),
        has_policy_mappings: false, policy_mappings: no_tlv(), require_explicit_policy: -1,
        inhibit_policy_mapping: -1, inhibit_any_policy: -1, has_crl_dp: false, crl_dp: no_tlv(),
        unknown_critical: false,
        der: [],
    }
}

// The hash (256, 384, 512) an AlgorithmIdentifier of SHA-2 names, or 0.
fn hash_of_oid(der: const u8[:], t: asn1::Tlv) -> i64 {
    if asn1::oid_is(der, t, "2.16.840.1.101.3.4.2.1") { return 256; }
    if asn1::oid_is(der, t, "2.16.840.1.101.3.4.2.2") { return 384; }
    if asn1::oid_is(der, t, "2.16.840.1.101.3.4.2.3") { return 512; }
    return 0;
}

// A SHA-2 AlgorithmIdentifier: the OID, then NULL or nothing.
fn hash_alg(der: const u8[:], t: asn1::Tlv) -> i64 {
    let p, ok = asn1::children_of(der, t, asn1::SEQUENCE);
    if !ok || p.len < 1 || p.len > 2 || (p.len == 2 && !asn1::read_null(der, p[1])) { return 0; }
    return hash_of_oid(der, p[0]);
}

// RSASSA-PSS-params (RFC 4055): the hash, MGF1 on the same hash, the salt
// length, trailer field 1. Absent fields mean SHA-1, which is refused.
fn pss_params(der: const u8[:], t: asn1::Tlv) -> i64, i64, bool {
    let p, ok = asn1::children_of(der, t, asn1::SEQUENCE);
    if !ok { return 0, 0, false; }
    var hash = 0;
    var mgf_hash = 0;
    var salt: i64 = 20;
    var last: i64 = -1;
    for f in p {
        if f.cls != asn1::CLASS_CONTEXT || !f.constructed || f.number <= last { return 0, 0, false; }
        last = f.number;
        let inner, oki = asn1::explicit(der, f);
        if !oki { return 0, 0, false; }
        if f.number == 0 {
            hash = hash_alg(der, inner);
        } else if f.number == 1 {
            let m, okm = asn1::children_of(der, inner, asn1::SEQUENCE);
            if !okm || m.len != 2 || !asn1::oid_is(der, m[0], "1.2.840.113549.1.1.8") { return 0, 0, false; }
            mgf_hash = hash_alg(der, m[1]);
        } else if f.number == 2 {
            let v, okv = asn1::read_i64(der, inner);
            if !okv || v < 0 || v > 512 { return 0, 0, false; }
            salt = v;
        } else if f.number == 3 {
            let v, okv = asn1::read_i64(der, inner);
            if !okv || v != 1 { return 0, 0, false; }
        } else {
            return 0, 0, false;
        }
    }
    if hash == 0 || mgf_hash != hash { return 0, 0, false; }
    return hash, salt, true;
}

// A signature AlgorithmIdentifier: the algorithm, its hash and PSS salt
// length; SIG_UNKNOWN for anything else (SHA-1 included).
fn sig_alg_of(der: const u8[:], t: asn1::Tlv) -> i64, i64, i64 {
    let p, ok = asn1::children_of(der, t, asn1::SEQUENCE);
    if !ok || p.len < 1 || p.len > 2 { return SIG_UNKNOWN, 0, 0; }
    let oid = p[0];
    let null_or_absent = p.len == 1 || asn1::read_null(der, p[1]);
    if null_or_absent {
        if asn1::oid_is(der, oid, "1.2.840.113549.1.1.11") { return SIG_RSA_PKCS1, 256, 0; }
        if asn1::oid_is(der, oid, "1.2.840.113549.1.1.12") { return SIG_RSA_PKCS1, 384, 0; }
        if asn1::oid_is(der, oid, "1.2.840.113549.1.1.13") { return SIG_RSA_PKCS1, 512, 0; }
    }
    // ECDSA and Ed25519 identifiers carry no parameters at all.
    if p.len == 1 {
        if asn1::oid_is(der, oid, "1.2.840.10045.4.3.2") { return SIG_ECDSA, 256, 0; }
        if asn1::oid_is(der, oid, "1.2.840.10045.4.3.3") { return SIG_ECDSA, 384, 0; }
        if asn1::oid_is(der, oid, "1.2.840.10045.4.3.4") { return SIG_ECDSA, 512, 0; }
        if asn1::oid_is(der, oid, "1.3.101.112") { return SIG_ED25519, 0, 0; }
    }
    if p.len == 2 && asn1::oid_is(der, oid, "1.2.840.113549.1.1.10") {
        let h, salt, okp = pss_params(der, p[1]);
        if okp { return SIG_RSA_PSS, h, salt; }
    }
    return SIG_UNKNOWN, 0, 0;
}

// The key type of an EC named-curve OID, or KEY_UNKNOWN.
fn ec_named_curve(der: const u8[:], o: asn1::Tlv) -> i64 {
    if asn1::oid_is(der, o, "1.2.840.10045.3.1.7") { return KEY_EC_P256; }
    if asn1::oid_is(der, o, "1.3.132.0.34") { return KEY_EC_P384; }
    if asn1::oid_is(der, o, "1.3.132.0.35") { return KEY_EC_P521; }
    if asn1::oid_is(der, o, "1.3.132.0.33") { return KEY_EC_P224; }
    return KEY_UNKNOWN;
}

fn is_ec(kind: i64) -> bool {
    kind == KEY_EC_P256 || kind == KEY_EC_P384 || kind == KEY_EC_P521 || kind == KEY_EC_P224
}

// The curve of an EC key type.
fn curve_of_key(kind: i64) -> bignum::Curve {
    assert(is_ec(kind));
    if kind == KEY_EC_P256 { return bignum::p256(); }
    if kind == KEY_EC_P384 { return bignum::p384(); }
    if kind == KEY_EC_P224 { return bignum::p224(); }
    return bignum::p521();
}

// The key type of a SubjectPublicKeyInfo, and its subjectPublicKey.
fn spki_of(der: const u8[:], t: asn1::Tlv) -> i64, asn1::Tlv, bool {
    let p, ok = asn1::children_of(der, t, asn1::SEQUENCE);
    if !ok || p.len != 2 || p[1].tag != asn1::BIT_STRING { return KEY_UNKNOWN, t, false; }
    let alg, oka = asn1::children_of(der, p[0], asn1::SEQUENCE);
    if !oka || alg.len < 1 { return KEY_UNKNOWN, t, false; }
    var kind = KEY_UNKNOWN;
    if asn1::oid_is(der, alg[0], "1.2.840.113549.1.1.1") && alg.len == 2 && asn1::read_null(der, alg[1]) {
        kind = KEY_RSA;
    } else if asn1::oid_is(der, alg[0], "1.2.840.10045.2.1") && alg.len == 2 {
        kind = ec_named_curve(der, alg[1]);
    } else if asn1::oid_is(der, alg[0], "1.3.101.112") && alg.len == 1 {
        kind = KEY_ED25519;
    }
    return kind, p[1], true;
}

// The key bytes of a BIT STRING without unused bits.
fn key_bytes(der: const u8[:], t: asn1::Tlv) -> u8[>..], bool {
    let b, unused, ok = asn1::read_bits(der, t);
    return b, ok && unused == 0;
}

let ANY_POLICY: const u8[:] = "2.5.29.32.0";

// GeneralSubtrees: each a SEQUENCE of a GeneralName and no minimum or
// maximum (RFC 5280 says they must be absent for the name forms in use).
fn subtrees_ok(der: const u8[:], t: asn1::Tlv) -> bool {
    let subs, ok = asn1::children(der, t);
    if !ok || subs.len == 0 { return false; }
    for s in subs {
        let p, okp = asn1::children_of(der, s, asn1::SEQUENCE);
        if !okp || p.len != 1 || p[0].cls != asn1::CLASS_CONTEXT { return false; }
    }
    return true;
}

// NameConstraints ::= SEQUENCE { permittedSubtrees [0], excludedSubtrees [1] },
// at least one of them.
fn name_constraints_ok(der: const u8[:], t: asn1::Tlv) -> bool {
    let p, ok = asn1::children_of(der, t, asn1::SEQUENCE);
    if !ok || p.len == 0 || p.len > 2 { return false; }
    var last: i64 = -1;
    for x in p {
        if x.cls != asn1::CLASS_CONTEXT || !x.constructed || x.number > 1 || x.number <= last { return false; }
        last = x.number;
        if !subtrees_ok(der, x) { return false; }
    }
    return true;
}

// certificatePolicies: PolicyInformation ::= SEQUENCE { policyIdentifier, qualifiers OPTIONAL },
// each policy once.
fn policies_ok(der: const u8[:], t: asn1::Tlv) -> bool {
    let ps, ok = asn1::children_of(der, t, asn1::SEQUENCE);
    if !ok || ps.len == 0 { return false; }
    for i in ps.len {
        let pi, okp = asn1::children_of(der, ps[i], asn1::SEQUENCE);
        if !okp || pi.len < 1 || pi.len > 2 || pi[0].tag != asn1::OID { return false; }
        if pi.len == 2 && pi[1].tag != asn1::SEQUENCE { return false; }
        for j in i {
            let pj, okj = asn1::children(der, ps[j]);
            if der[pj[0].off..pj[0].end] == der[pi[0].off..pi[0].end] { return false; }
        }
    }
    return true;
}

// PolicyMappings: pairs of issuer and subject policies, neither anyPolicy.
fn mappings_ok(der: const u8[:], t: asn1::Tlv) -> bool {
    let ms, ok = asn1::children_of(der, t, asn1::SEQUENCE);
    if !ok || ms.len == 0 { return false; }
    for m in ms {
        let pair, okp = asn1::children_of(der, m, asn1::SEQUENCE);
        if !okp || pair.len != 2 || pair[0].tag != asn1::OID || pair[1].tag != asn1::OID { return false; }
        if asn1::oid_is(der, pair[0], ANY_POLICY) || asn1::oid_is(der, pair[1], ANY_POLICY) { return false; }
    }
    return true;
}

// The URIs of a certificate's CRL distribution points (fullName entries).
fn crl_urls(c: const Cert&) -> u8[][>..] {
    var out: u8[][>..] = [];
    if !c.has_crl_dp { return out; }
    let d = c.der[..];
    let dps, ok = asn1::children(d, c.crl_dp);
    for dp in dps {
        let fs, okf = asn1::children(d, dp);
        for f in fs {
            if f.tag != asn1::ctx(0, true) { continue; }         // distributionPoint
            let names, okn = asn1::children(d, f);
            for n in names {
                if n.tag != asn1::ctx(0, true) { continue; }     // fullName
                let gns, okg = asn1::children(d, n);
                for g in gns {
                    if g.tag == asn1::ctx(6, false) {
                        var u: u8[>..] = [];
                        u.append(d[g.off..g.end]);
                        out.push(copy(u));
                    }
                }
            }
        }
    }
    return out;
}

fn parse_extensions(c: Cert&, der: const u8[:], t: asn1::Tlv) -> bool {
    let wrap, okw = asn1::explicit(der, t);
    let exts, ok = asn1::children_of(der, wrap, asn1::SEQUENCE);
    if !okw || !ok || exts.len == 0 { return false; }
    var seen: u8[][>..] = [];
    for e in exts {
        let f, okf = asn1::children_of(der, e, asn1::SEQUENCE);
        if !okf || f.len < 2 || f.len > 3 || f[0].tag != asn1::OID { return false; }
        // Each extension at most once.
        let id = der[f[0].off..f[0].end];
        for s in seen { if s == id { return false; } }
        var idc: u8[>..] = [];
        idc.append(id);
        seen.push(copy(idc));
        var critical = false;
        if f.len == 3 {
            let v, okb = asn1::read_bool(der, f[1]);
            if !okb || !v { return false; }              // DER omits a FALSE default
            critical = true;
        }
        let val = f[f.len - 1];
        if val.tag != asn1::OCTET_STRING { return false; }
        let inner, oki = asn1::read(der, val.off, val.end);
        if asn1::oid_is(der, f[0], "2.5.29.19") {
            // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLen INTEGER OPTIONAL }
            let b, okb = asn1::children_of(der, inner, asn1::SEQUENCE);
            if !oki || inner.end != val.end || !okb || b.len > 2 { return false; }
            c.has_basic_constraints = true;
            var i = 0;
            if b.len > 0 && b[0].tag == asn1::BOOLEAN {
                let v, okv = asn1::read_bool(der, b[0]);
                if !okv || !v { return false; }
                c.is_ca = true;
                i = 1;
            }
            if i < b.len {
                let n, okn = asn1::read_i64(der, b[i]);
                if !okn || n < 0 || !c.is_ca || i + 1 != b.len { return false; }
                c.path_len = n;
            }
        } else if asn1::oid_is(der, f[0], "2.5.29.15") {
            let bits, unused, okb = asn1::read_bits(der, inner);
            if !oki || inner.end != val.end || !okb { return false; }
            c.has_key_usage = true;
            for i in 9 { if asn1::bit(bits, i) { c.key_usage = c.key_usage | (1 << i as u32); } }
        } else if asn1::oid_is(der, f[0], "2.5.29.37") {
            let ks, okk = asn1::children_of(der, inner, asn1::SEQUENCE);
            if !oki || inner.end != val.end || !okk || ks.len == 0 { return false; }
            c.has_ext_key_usage = true;
            for k in ks {
                if k.tag != asn1::OID { return false; }
                c.ext_key_usage = c.ext_key_usage | (
                    if asn1::oid_is(der, k, "2.5.29.37.0") { EKU_ANY }
                    else if asn1::oid_is(der, k, "1.3.6.1.5.5.7.3.1") { EKU_SERVER_AUTH }
                    else if asn1::oid_is(der, k, "1.3.6.1.5.5.7.3.2") { EKU_CLIENT_AUTH }
                    else if asn1::oid_is(der, k, "1.3.6.1.5.5.7.3.3") { EKU_CODE_SIGNING }
                    else if asn1::oid_is(der, k, "1.3.6.1.5.5.7.3.4") { EKU_EMAIL_PROTECTION }
                    else if asn1::oid_is(der, k, "1.3.6.1.5.5.7.3.8") { EKU_TIME_STAMPING }
                    else if asn1::oid_is(der, k, "1.3.6.1.5.5.7.3.9") { EKU_OCSP_SIGNING }
                    else { EKU_OTHER });
            }
        } else if asn1::oid_is(der, f[0], "2.5.29.17") {
            let ns, okn = asn1::children_of(der, inner, asn1::SEQUENCE);
            if !oki || inner.end != val.end || !okn || ns.len == 0 { return false; }
            c.has_san = true;
            c.san = inner;
        } else if asn1::oid_is(der, f[0], "2.5.29.14") {
            if !oki || inner.end != val.end || inner.tag != asn1::OCTET_STRING { return false; }
            c.ski = inner;
        } else if asn1::oid_is(der, f[0], "2.5.29.35") {
            // AuthorityKeyIdentifier: keyIdentifier [0] IMPLICIT OCTET STRING, if present.
            let a, oka = asn1::children_of(der, inner, asn1::SEQUENCE);
            if !oki || inner.end != val.end || !oka { return false; }
            for x in a { if x.tag == asn1::ctx(0, false) { c.aki = x; } }
        } else if asn1::oid_is(der, f[0], "2.5.29.30") {
            if !oki || inner.end != val.end || !name_constraints_ok(der, inner) { return false; }
            c.has_name_constraints = true;
            c.name_constraints = inner;
        } else if asn1::oid_is(der, f[0], "2.5.29.32") {
            if !oki || inner.end != val.end || !policies_ok(der, inner) { return false; }
            c.has_policies = true;
            c.policies = inner;
        } else if asn1::oid_is(der, f[0], "2.5.29.33") {
            if !oki || inner.end != val.end || !mappings_ok(der, inner) { return false; }
            c.has_policy_mappings = true;
            c.policy_mappings = inner;
        } else if asn1::oid_is(der, f[0], "2.5.29.36") {
            // PolicyConstraints ::= SEQUENCE { requireExplicitPolicy [0] SkipCerts OPTIONAL,
            //                                  inhibitPolicyMapping [1] SkipCerts OPTIONAL }
            let pc, okc = asn1::children_of(der, inner, asn1::SEQUENCE);
            if !oki || inner.end != val.end || !okc || pc.len == 0 || pc.len > 2 { return false; }
            var last: i64 = -1;
            for x in pc {
                let v, okv = asn1::read_i64(der, x, x.tag);
                if x.cls != asn1::CLASS_CONTEXT || x.constructed || x.number > 1 || x.number <= last
                    || !okv || v < 0 {
                    return false;
                }
                last = x.number;
                if x.number == 0 { c.require_explicit_policy = v; } else { c.inhibit_policy_mapping = v; }
            }
        } else if asn1::oid_is(der, f[0], "2.5.29.54") {
            let v, okv = asn1::read_i64(der, inner);
            if !oki || inner.end != val.end || !okv || v < 0 { return false; }
            c.inhibit_any_policy = v;
        } else if asn1::oid_is(der, f[0], "2.5.29.31") {
            let dps, okd = asn1::children_of(der, inner, asn1::SEQUENCE);
            if !oki || inner.end != val.end || !okd || dps.len == 0 { return false; }
            c.has_crl_dp = true;
            c.crl_dp = inner;
        } else if critical {
            // Anything else critical is not implemented, so it makes the
            // certificate unusable here.
            c.unknown_critical = true;
        }
    }
    return true;
}

// Parses a DER certificate; OK or ERR_MALFORMED. Unsupported algorithms
// and keys parse (sig_alg or key_type say so) and fail when used.
fn parse(der: const u8[:]) -> Cert, i64 {
    var c = empty_cert();
    c.der.append(der);
    let d = c.der[..];
    let top, okt = asn1::parse(d);
    let parts, okp = asn1::children_of(d, top, asn1::SEQUENCE);
    if !okt || !okp || parts.len != 3 || parts[2].tag != asn1::BIT_STRING { return c, ERR_MALFORMED; }
    c.tbs = parts[0];
    c.sig = parts[2];
    let f, okf = asn1::children_of(d, parts[0], asn1::SEQUENCE);
    if !okf || f.len < 6 { return c, ERR_MALFORMED; }
    var i = 0;
    c.version = 1;
    if f[0].tag == asn1::ctx(0, true) {
        let v, okv = asn1::explicit(d, f[0]);
        let n, okn = asn1::read_i64(d, v);
        if !okv || !okn || n < 1 || n > 2 { return c, ERR_MALFORMED; }   // v1 is never written out
        c.version = n + 1;
        i = 1;
    }
    if f.len < i + 6 { return c, ERR_MALFORMED; }
    let serial, oks = asn1::read_int_bytes(d, f[i]);
    if !oks || serial.len > 21 { return c, ERR_MALFORMED; }
    c.serial = f[i];
    // The algorithm inside the signed part must be the outer one, exactly.
    if d[f[i + 1].start..f[i + 1].end] != d[parts[1].start..parts[1].end] { return c, ERR_MALFORMED; }
    let alg, h, salt = sig_alg_of(d, parts[1]);
    c.sig_alg = alg;
    c.sig_hash = h;
    c.pss_salt = salt;
    c.issuer = f[i + 2];
    c.subject = f[i + 4];
    let issuer_ok, okis = asn1::children_of(d, c.issuer, asn1::SEQUENCE);
    let subject_ok, oksu = asn1::children_of(d, c.subject, asn1::SEQUENCE);
    if !okis || !oksu || issuer_ok.len == 0 { return c, ERR_MALFORMED; }
    let val, okval = asn1::children_of(d, f[i + 3], asn1::SEQUENCE);
    if !okval || val.len != 2 { return c, ERR_MALFORMED; }
    let nb, oknb = asn1::read_time(d, val[0]);
    let na, okna = asn1::read_time(d, val[1]);
    if !oknb || !okna { return c, ERR_MALFORMED; }
    c.not_before = nb;
    c.not_after = na;
    c.spki = f[i + 5];
    let kind, key, okk = spki_of(d, c.spki);
    if !okk { return c, ERR_MALFORMED; }
    c.key_type = kind;
    c.key = key;
    var j = i + 6;
    // issuerUniqueID [1] and subjectUniqueID [2], then extensions [3].
    while j < f.len && (f[j].tag == asn1::ctx(1, false) || f[j].tag == asn1::ctx(2, false)) {
        if c.version < 2 { return c, ERR_MALFORMED; }
        j++;
    }
    if j < f.len {
        if f[j].tag != asn1::ctx(3, true) || c.version != 3 || j + 1 != f.len { return c, ERR_MALFORMED; }
        if !parse_extensions(c, d, f[j]) { return c, ERR_MALFORMED; }
    }
    // A subject may be empty only with a critical subjectAltName.
    if subject_ok.len == 0 && !c.has_san { return c, ERR_MALFORMED; }
    let sigbits, okb = key_bytes(d, c.sig);
    if !okb { return c, ERR_MALFORMED; }
    return c, OK;
}

// The first certificate in a PEM text.
fn parse_pem(text: const u8[:]) -> Cert, i64 {
    let ders, ok = asn1::pem_decode(text, "CERTIFICATE");
    for der in ders { return parse(der); }
    return empty_cert(), ERR_MALFORMED;
}

// --- Names ------------------------------------------------------------------

fn attr_name(der: const u8[:], t: asn1::Tlv) -> const u8[:] {
    if asn1::oid_is(der, t, "2.5.4.3") { return "CN"; }
    if asn1::oid_is(der, t, "2.5.4.6") { return "C"; }
    if asn1::oid_is(der, t, "2.5.4.7") { return "L"; }
    if asn1::oid_is(der, t, "2.5.4.8") { return "ST"; }
    if asn1::oid_is(der, t, "2.5.4.9") { return "street"; }
    if asn1::oid_is(der, t, "2.5.4.10") { return "O"; }
    if asn1::oid_is(der, t, "2.5.4.11") { return "OU"; }
    if asn1::oid_is(der, t, "2.5.4.5") { return "serialNumber"; }
    if asn1::oid_is(der, t, "2.5.4.4") { return "SN"; }
    if asn1::oid_is(der, t, "2.5.4.42") { return "GN"; }
    if asn1::oid_is(der, t, "2.5.4.12") { return "title"; }
    if asn1::oid_is(der, t, "2.5.4.97") { return "organizationIdentifier"; }
    if asn1::oid_is(der, t, "0.9.2342.19200300.100.1.25") { return "DC"; }
    if asn1::oid_is(der, t, "0.9.2342.19200300.100.1.1") { return "UID"; }
    if asn1::oid_is(der, t, "1.2.840.113549.1.9.1") { return "emailAddress"; }
    return "";
}

// RFC 4514 escaping of an attribute value.
fn put_escaped(out: u8[>..]&, v: const u8[:]) {
    for i in v.len {
        let ch = v[i];
        let special = ch == ',' || ch == '+' || ch == '"' || ch == '\\' || ch == '<' || ch == '>' || ch == ';'
            || (i == 0 && (ch == '#' || ch == ' ')) || (i == v.len - 1 && ch == ' ');
        if special { out.push('\\'); }
        if ch < 0x20 || ch == 0x7f {
            out.push('\\');
            format_int(out, ch, 16, 2, '0');
        } else {
            out.push(ch);
        }
    }
}

fn hex_upper(out: u8[>..]&, b: const u8[:]) {
    for x in b {
        let digits = "0123456789ABCDEF";
        out.push(digits[x >> 4]);
        out.push(digits[x & 15]);
    }
}

// A Name as RFC 4514 text, most specific first: "CN=example.com,O=Example,C=US".
// Attributes without a short name appear as their OID and the value's DER
// in hex ("1.2.3=#0c0161").
fn name_text(der: const u8[:], name: asn1::Tlv) -> u8[>..] {
    var out: u8[>..] = [];
    let rdns, ok = asn1::children_of(der, name, asn1::SEQUENCE);
    if !ok { return out; }
    var i = rdns.len;
    while i > 0 {
        i--;
        if i < rdns.len - 1 { out.push(','); }
        let atvs, oka = asn1::children_of(der, rdns[i], asn1::SET);
        if !oka { continue; }
        var first = true;
        for atv in atvs {
            let p, okp = asn1::children_of(der, atv, asn1::SEQUENCE);
            if !okp || p.len != 2 { continue; }
            if !first { out.push('+'); }
            first = false;
            let short = attr_name(der, p[0]);
            let s, oks = asn1::read_string(der, p[1]);
            if short.len > 0 && oks {
                out.append(short);
                out.push('=');
                put_escaped(out, s);
            } else {
                let o, oko = asn1::read_oid(der, p[0]);
                out.append(o);
                out.append("=#");
                hex_upper(out, der[p[1].start..p[1].end]);
            }
        }
    }
    return out;
}

// Every value of one attribute in a Name ("2.5.4.3" for commonName).
fn name_values(der: const u8[:], name: asn1::Tlv, oid: const u8[:]) -> u8[][>..] {
    var out: u8[][>..] = [];
    let rdns, ok = asn1::children_of(der, name, asn1::SEQUENCE);
    for rdn in rdns {
        let atvs, oka = asn1::children_of(der, rdn, asn1::SET);
        for atv in atvs {
            let p, okp = asn1::children_of(der, atv, asn1::SEQUENCE);
            if okp && p.len == 2 && asn1::oid_is(der, p[0], oid) {
                let s, oks = asn1::read_string(der, p[1]);
                if oks { out.push(copy(s)); }
            }
        }
    }
    return out;
}

fn subject_text(c: const Cert&) -> u8[>..] { name_text(c.der, c.subject) }
fn issuer_text(c: const Cert&) -> u8[>..] { name_text(c.der, c.issuer) }

// The serial number in hex, as openssl prints it.
fn serial_hex(c: const Cert&) -> u8[>..] {
    var out: u8[>..] = [];
    let d = c.der[..];
    var from = c.serial.off;
    if c.serial.end - from > 1 && d[from] == 0 { from++; }
    hex_upper(out, d[from..c.serial.end]);
    return out;
}

// Whether c was issued by a certificate with this subject (DER equality,
// which is what CAs produce and what most validators compare).
fn issued_by(c: const Cert&, issuer: const Cert&) -> bool {
    c.der[c.issuer.start..c.issuer.end] == issuer.der[issuer.subject.start..issuer.subject.end]
}

fn self_issued(c: const Cert&) -> bool { issued_by(c, c) }

// --- Subject alternative names ----------------------------------------------

// The dNSName entries.
fn dns_names(c: const Cert&) -> u8[][>..] {
    var out: u8[][>..] = [];
    if !c.has_san { return out; }
    let ns, ok = asn1::children(c.der, c.san);
    for n in ns {
        if n.tag == asn1::ctx(2, false) {
            var s: u8[>..] = [];
            s.append(c.der[n.off..n.end]);
            out.push(copy(s));
        }
    }
    return out;
}

// The iPAddress entries, 4 or 16 bytes each.
fn ip_addresses(c: const Cert&) -> u8[][>..] {
    var out: u8[][>..] = [];
    if !c.has_san { return out; }
    let ns, ok = asn1::children(c.der, c.san);
    for n in ns {
        if n.tag == asn1::ctx(7, false) {
            var s: u8[>..] = [];
            s.append(c.der[n.off..n.end]);
            out.push(copy(s));
        }
    }
    return out;
}

// --- Host names (RFC 6125) --------------------------------------------------

fn lower(c: u8) -> u8 { if c >= 'A' && c <= 'Z' { c + 32 } else { c } }

fn eq_nocase(a: const u8[:], b: const u8[:]) -> bool {
    if a.len != b.len { return false; }
    for i in a.len { if lower(a[i]) != lower(b[i]) { return false; } }
    return true;
}

// A dotted IPv4 literal as 4 bytes.
fn parse_ipv4(s: const u8[:]) -> u8[4], bool {
    var out: u8[4] = [0; 4];
    var n = 0;
    var v = -1;
    for i in s.len + 1 {
        if i == s.len || s[i] == '.' {
            if v < 0 || n == 4 { return out, false; }
            out[n] = v as! u8;
            n++;
            v = -1;
        } else if s[i] >= '0' && s[i] <= '9' {
            if v == 0 { return out, false; }             // no leading zeros
            v = (if v < 0 { 0 } else { v }) * 10 + (s[i] - '0');
            if v > 255 { return out, false; }
        } else {
            return out, false;
        }
    }
    return out, n == 4;
}

// Whether a SAN dNSName pattern covers a host. A wildcard is only a whole
// left-most label, covers exactly one label, and needs two more after it.
fn dns_match(pattern: const u8[:], host: const u8[:]) -> bool {
    var h = host;
    if h.len > 0 && h[h.len - 1] == '.' { h = h[..h.len - 1]; }
    if pattern.len == 0 || h.len == 0 { return false; }
    if pattern.len >= 2 && pattern[0] == '*' && pattern[1] == '.' {
        let rest = pattern[2..];
        var dots = 0;
        for ch in rest { if ch == '.' { dots++; } }
        if dots < 1 { return false; }
        var first_dot = -1;
        for i in h.len { if h[i] == '.' { first_dot = i; break; } }
        if first_dot <= 0 { return false; }
        return eq_nocase(h[first_dot + 1..], rest);
    }
    for ch in pattern { if ch == '*' { return false; } }
    return eq_nocase(pattern, h);
}

// Whether c is valid for a host name or IPv4 literal, by its SAN alone;
// the subject's commonName is not consulted (as browsers no longer do).
fn matches_host(c: const Cert&, host: const u8[:]) -> bool {
    let ip, is_ip = parse_ipv4(host);
    if is_ip {
        for a in ip_addresses(c) { if a == ip[..] { return true; } }
        return false;
    }
    for n in dns_names(c) { if dns_match(n, host) { return true; } }
    return false;
}

// --- Signatures ---------------------------------------------------------------

// Verifies sig over msg with the key of `key_cert`, by algorithm alg with
// hash h (and PSS salt length).
fn verify_with(key_cert: const Cert&, alg: i64, h: i64, salt: i64, msg: const u8[:], sig: const u8[:]) -> i64 {
    let d = key_cert.der[..];
    let kb, okk = key_bytes(d, key_cert.key);
    if !okk { return ERR_MALFORMED; }
    if alg == SIG_RSA_PKCS1 || alg == SIG_RSA_PSS {
        if key_cert.key_type != KEY_RSA { return ERR_BAD_SIGNATURE; }
        let rk, okr = asn1::parse(kb);
        let p, okp = asn1::children_of(kb, rk, asn1::SEQUENCE);
        if !okr || !okp || p.len != 2 { return ERR_MALFORMED; }
        let n, okn = asn1::read_uint(kb, p[0]);
        let e, oke = asn1::read_uint(kb, p[1]);
        if !okn || !oke { return ERR_MALFORMED; }
        let pub, okpub = bignum::rsa_public_from(bignum::from_bytes_be(n), bignum::from_bytes_be(e));
        if !okpub { return ERR_UNSUPPORTED_ALGORITHM; }
        let good = if alg == SIG_RSA_PKCS1 { bignum::rsa_verify_pkcs1(pub, msg, sig, h) }
                   else { bignum::rsa_verify_pss(pub, msg, sig, salt, h) };
        return if good { OK } else { ERR_BAD_SIGNATURE };
    }
    if alg == SIG_ECDSA {
        if !is_ec(key_cert.key_type) { return ERR_BAD_SIGNATURE; }
        let curve = curve_of_key(key_cert.key_type);
        let raw, okd = bignum::ecdsa_sig_from_der(curve, sig);
        if !okd { return ERR_BAD_SIGNATURE; }
        let good = bignum::ecdsa_verify_digest(curve, kb, bignum::hash_bits(h, msg), raw);
        return if good { OK } else { ERR_BAD_SIGNATURE };
    }
    if alg == SIG_ED25519 {
        if key_cert.key_type != KEY_ED25519 { return ERR_BAD_SIGNATURE; }
        return if bignum::ed25519_verify(kb, msg, sig) { OK } else { ERR_BAD_SIGNATURE };
    }
    return ERR_UNSUPPORTED_ALGORITHM;
}

// Whether `issuer`'s key signed c.
fn check_signature(c: const Cert&, issuer: const Cert&) -> i64 {
    if c.sig_alg == SIG_UNKNOWN { return ERR_UNSUPPORTED_ALGORITHM; }
    let d = c.der[..];
    let sig, ok = key_bytes(d, c.sig);
    if !ok { return ERR_MALFORMED; }
    return verify_with(issuer, c.sig_alg, c.sig_hash, c.pss_salt, d[c.tbs.start..c.tbs.end], sig);
}

// TLS 1.3 SignatureScheme values (RFC 8446 §4.2.3).
let RSA_PKCS1_SHA256: u16 = 0x0401;
let RSA_PKCS1_SHA384: u16 = 0x0501;
let RSA_PKCS1_SHA512: u16 = 0x0601;
let ECDSA_SECP256R1_SHA256: u16 = 0x0403;
let ECDSA_SECP384R1_SHA384: u16 = 0x0503;
let ECDSA_SECP521R1_SHA512: u16 = 0x0603;
let RSA_PSS_RSAE_SHA256: u16 = 0x0804;
let RSA_PSS_RSAE_SHA384: u16 = 0x0805;
let RSA_PSS_RSAE_SHA512: u16 = 0x0806;
let ED25519: u16 = 0x0807;

// Verifies a TLS signature (CertificateVerify, say) made with c's key
// under a SignatureScheme. ECDSA schemes bind the curve, as TLS 1.3 does.
fn verify_scheme(c: const Cert&, scheme: u16, msg: const u8[:], sig: const u8[:]) -> i64 {
    if scheme == RSA_PKCS1_SHA256 { return verify_with(c, SIG_RSA_PKCS1, 256, 0, msg, sig); }
    if scheme == RSA_PKCS1_SHA384 { return verify_with(c, SIG_RSA_PKCS1, 384, 0, msg, sig); }
    if scheme == RSA_PKCS1_SHA512 { return verify_with(c, SIG_RSA_PKCS1, 512, 0, msg, sig); }
    if scheme == RSA_PSS_RSAE_SHA256 { return verify_with(c, SIG_RSA_PSS, 256, 32, msg, sig); }
    if scheme == RSA_PSS_RSAE_SHA384 { return verify_with(c, SIG_RSA_PSS, 384, 48, msg, sig); }
    if scheme == RSA_PSS_RSAE_SHA512 { return verify_with(c, SIG_RSA_PSS, 512, 64, msg, sig); }
    if scheme == ECDSA_SECP256R1_SHA256 {
        if c.key_type != KEY_EC_P256 { return ERR_BAD_SIGNATURE; }
        return verify_with(c, SIG_ECDSA, 256, 0, msg, sig);
    }
    if scheme == ECDSA_SECP384R1_SHA384 {
        if c.key_type != KEY_EC_P384 { return ERR_BAD_SIGNATURE; }
        return verify_with(c, SIG_ECDSA, 384, 0, msg, sig);
    }
    if scheme == ECDSA_SECP521R1_SHA512 {
        if c.key_type != KEY_EC_P521 { return ERR_BAD_SIGNATURE; }
        return verify_with(c, SIG_ECDSA, 512, 0, msg, sig);
    }
    if scheme == ED25519 { return verify_with(c, SIG_ED25519, 0, 0, msg, sig); }
    return ERR_UNSUPPORTED_ALGORITHM;
}

// --- Validation options -----------------------------------------------------

// Which certificates must have a usable CRL: none, the leaf, or every one
// below the root.
let CRL_NONE: i64 = 0;
let CRL_LEAF: i64 = 1;
let CRL_ALL: i64 = 2;

// The inputs of path validation beyond the certificates and the time: CRL
// checking, and RFC 5280's policy inputs, with the acceptable policies as
// dotted OIDs separated by spaces (empty for any policy).
struct Options {
    crl_check: i64,
    require_explicit_policy: bool, inhibit_policy_mapping: bool, inhibit_any_policy: bool,
    policies: u8[>..],
}

fn options() -> Options {
    Options { crl_check: CRL_NONE, require_explicit_policy: false, inhibit_policy_mapping: false,
              inhibit_any_policy: false, policies: [] }
}
