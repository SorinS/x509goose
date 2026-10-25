// x509.create: making certificates, certificate requests and CRLs, as
// Go's x509.CreateCertificate, CreateCertificateRequest and
// CreateRevocationList do. A Template holds a certificate's fields; names
// are built from RFC 4514 text, SANs and name constraints with small
// builders, and the issuer is a parsed Cert (or none, for a self-signed
// one) with its private key.

namespace x509;

import std;
import x509;
import asn1;
import keys;
import bignum;
import bignum.sha1;
import bignum.entropy;

// --- Names --------------------------------------------------------------------

fn attr_oid(name: const u8[:]) -> const u8[:] {
    if name == "CN" { return "2.5.4.3"; }
    if name == "C" { return "2.5.4.6"; }
    if name == "L" { return "2.5.4.7"; }
    if name == "ST" { return "2.5.4.8"; }
    if name == "street" { return "2.5.4.9"; }
    if name == "O" { return "2.5.4.10"; }
    if name == "OU" { return "2.5.4.11"; }
    if name == "serialNumber" { return "2.5.4.5"; }
    if name == "SN" { return "2.5.4.4"; }
    if name == "GN" { return "2.5.4.42"; }
    if name == "title" { return "2.5.4.12"; }
    if name == "DC" { return "0.9.2342.19200300.100.1.25"; }
    if name == "UID" { return "0.9.2342.19200300.100.1.1"; }
    if name == "emailAddress" { return "1.2.840.113549.1.9.1"; }
    return "";
}

fn printable(s: const u8[:]) -> bool {
    for c in s {
        let ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == ' '
            || c == '\'' || c == '(' || c == ')' || c == '+' || c == ',' || c == '-' || c == '.' || c == '/'
            || c == ':' || c == '=' || c == '?';
        if !ok { return false; }
    }
    return true;
}

// One AttributeTypeAndValue. Values are PrintableString where they fit,
// else UTF8String; emailAddress and DC are IA5String; C and serialNumber
// must be printable.
fn put_atv(out: u8[>..]&, oid: const u8[:], value: const u8[:]) -> bool {
    var body: u8[>..] = [];
    asn1::put_oid(body, oid);
    if oid == "1.2.840.113549.1.9.1" || oid == "0.9.2342.19200300.100.1.25" {
        for c in value { if c >= 0x80 { return false; } }
        asn1::put(body, asn1::IA5_STRING, value);
    } else if printable(value) {
        asn1::put(body, asn1::PRINTABLE_STRING, value);
    } else {
        if oid == "2.5.4.6" || oid == "2.5.4.5" || !asn1::utf8_valid(value) { return false; }
        asn1::put(body, asn1::UTF8_STRING, value);
    }
    asn1::put(out, asn1::SEQUENCE, body);
    return true;
}

// A Name from RFC 4514 text, most specific first ("CN=example.com,O=Ex,C=US"),
// with `+` for multi-valued RDNs and backslash escapes; the empty text is
// the empty Name. False for an attribute without a known short name.
fn name_der(text: const u8[:]) -> u8[>..], bool {
    var rdns: u8[][>..] = [];
    var rdn: u8[>..] = [];
    var key: u8[>..] = [];
    var val: u8[>..] = [];
    var in_value = false;
    var ok = true;
    var i = 0;
    while i <= text.len {
        let end = i == text.len;
        let c: u8 = if end { 0 } else { text[i] };
        if !end && c == '\\' && i + 1 < text.len {
            val.push(text[i + 1]);
            i += 2;
            continue;
        }
        if !in_value && !end && c == '=' { in_value = true; i++; continue; }
        if end || c == ',' || c == '+' {
            if key.len > 0 || val.len > 0 {
                let oid = attr_oid(key);
                if oid.len == 0 || !in_value || !put_atv(rdn, oid, val) { rdns.clear(); var bad: u8[>..] = []; return bad, false; }
            }
            key.clear();
            val.clear();
            in_value = false;
            if (end || c == ',') && rdn.len > 0 {
                var set: u8[>..] = [];
                asn1::put(set, asn1::SET, rdn);
                rdns.push(copy(set));
                rdn.clear();
            }
            i++;
            continue;
        }
        if in_value { val.push(c); } else { key.push(c); }
        i++;
    }
    // The text is most specific first; the DER sequence is the reverse.
    var body: u8[>..] = [];
    var n = rdns.len;
    while n > 0 {
        n--;
        var k = 0;
        for r in rdns { if k == n { body.append(r); } k++; }
    }
    var out: u8[>..] = [];
    asn1::put(out, asn1::SEQUENCE, body);
    return out, true;
}

// --- General names --------------------------------------------------------------

// Builders for a GeneralNames list (subjectAltName) or GeneralSubtrees
// (name constraints): each appends one entry.
fn add_dns(list: u8[..4096]&, name: const u8[:]) {
    var e: u8[>..] = [];
    asn1::put(e, asn1::ctx(2, false), name);
    list.append(e);
}

fn add_email(list: u8[..4096]&, mailbox: const u8[:]) {
    var e: u8[>..] = [];
    asn1::put(e, asn1::ctx(1, false), mailbox);
    list.append(e);
}

fn add_uri(list: u8[..4096]&, uri: const u8[:]) {
    var e: u8[>..] = [];
    asn1::put(e, asn1::ctx(6, false), uri);
    list.append(e);
}

// An address (4 or 16 bytes); in name constraints, the address followed
// by its mask.
fn add_ip(list: u8[..4096]&, addr: const u8[:]) {
    var e: u8[>..] = [];
    asn1::put(e, asn1::ctx(7, false), addr);
    list.append(e);
}

fn add_dirname(list: u8[..4096]&, name: const u8[:]) {
    var e: u8[>..] = [];
    asn1::put(e, asn1::ctx(4, true), name);
    list.append(e);
}

// --- Certificates -----------------------------------------------------------------

// A certificate's fields. A zero `sig_alg` means the issuer key's default;
// an empty `serial` a random 16-byte one. `basic_constraints` writes the
// extension (always for a CA); `path_len` -1 means none. `key_usage` and
// `ext_key_usage` (KU_* and EKU_* masks) are left out at 0. SAN, the name
// constraints' subtrees, and the policies (dotted OIDs separated by
// spaces) and CRL URLs (separated by spaces) are left out when empty.
// `extra` holds more Extension elements, DER, to append as they are.
struct Template {
    serial: u8[..20], not_before: i64, not_after: i64,
    subject: u8[..2048],
    sig_alg: i64, sig_hash: i64,
    basic_constraints: bool, is_ca: bool, path_len: i64,
    key_usage: u32, ext_key_usage: u32,
    san: u8[..4096],
    permitted: u8[..4096], excluded: u8[..4096],
    policies: u8[..1024], crl_urls: u8[..1024],
    extra: u8[>..],
}

fn template(subject_text: const u8[:], not_before: i64, not_after: i64) -> Template, bool {
    var t = Template {
        serial: [], not_before: not_before, not_after: not_after, subject: [], sig_alg: 0, sig_hash: 0,
        basic_constraints: false, is_ca: false, path_len: -1, key_usage: 0, ext_key_usage: 0,
        san: [], permitted: [], excluded: [], policies: [], crl_urls: [], extra: [],
    };
    let n, ok = name_der(subject_text);
    if ok { t.subject.append(n); }
    return t, ok;
}

fn put_ext(out: u8[>..]&, oid: const u8[:], critical: bool, value: const u8[:]) {
    var body: u8[>..] = [];
    asn1::put_oid(body, oid);
    if critical { asn1::put_bool(body, true); }
    asn1::put_octets(body, value);
    asn1::put(out, asn1::SEQUENCE, body);
}

// A BIT STRING of the lowest `nbits` bits of mask, bit i of the mask as
// the string's bit i, with DER's trailing zeros dropped.
fn put_named_bits(out: u8[>..]&, mask: u32) {
    var bytes: u8[2] = [0; 2];
    var last = -1;
    for i in 9 {
        if mask & (1 << (i as u32)) != 0 {
            bytes[i / 8] = bytes[i / 8] | (0x80 >> (i % 8)) as! u8;
            last = i;
        }
    }
    let n = last / 8 + 1;
    let unused = 7 - last % 8;
    asn1::put_bits(out, bytes[..n], unused);
}

fn eku_oid(bit: u32) -> const u8[:] {
    if bit == EKU_ANY { return "2.5.29.37.0"; }
    if bit == EKU_SERVER_AUTH { return "1.3.6.1.5.5.7.3.1"; }
    if bit == EKU_CLIENT_AUTH { return "1.3.6.1.5.5.7.3.2"; }
    if bit == EKU_CODE_SIGNING { return "1.3.6.1.5.5.7.3.3"; }
    if bit == EKU_EMAIL_PROTECTION { return "1.3.6.1.5.5.7.3.4"; }
    if bit == EKU_TIME_STAMPING { return "1.3.6.1.5.5.7.3.8"; }
    return "1.3.6.1.5.5.7.3.9";
}

// The key identifier of a public key: the SHA-1 of its subjectPublicKey
// (RFC 5280 §4.2.1.2, method 1), as Go and openssl make it.
fn key_id(spki: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    let t, ok = asn1::parse(spki);
    let p, okp = asn1::children_of(spki, t, asn1::SEQUENCE);
    if !ok || !okp || p.len != 2 { return out, false; }
    let bits, unused, okb = asn1::read_bits(spki, p[1]);
    if !okb { return out, false; }
    out.append(bignum::sha1(bits));
    return out, true;
}

fn put_extensions(out: u8[>..]&, t: const Template&, spki: const u8[:], issuer_key_id: const u8[:]) -> bool {
    var exts: u8[>..] = [];
    if t.basic_constraints || t.is_ca {
        var bc: u8[>..] = [];
        if t.is_ca { asn1::put_bool(bc, true); }
        if t.is_ca && t.path_len >= 0 { asn1::put_i64(bc, t.path_len); }
        var v: u8[>..] = [];
        asn1::put(v, asn1::SEQUENCE, bc);
        put_ext(exts, "2.5.29.19", true, v);
    }
    if t.key_usage != 0 {
        var v: u8[>..] = [];
        put_named_bits(v, t.key_usage);
        put_ext(exts, "2.5.29.15", true, v);
    }
    if t.ext_key_usage != 0 {
        var body: u8[>..] = [];
        for i in 8 {
            let bit: u32 = 1 << (i as u32);
            if t.ext_key_usage & bit != 0 && bit != EKU_OTHER { asn1::put_oid(body, eku_oid(bit)); }
        }
        var v: u8[>..] = [];
        asn1::put(v, asn1::SEQUENCE, body);
        put_ext(exts, "2.5.29.37", false, v);
    }
    let ski, oks = key_id(spki);
    if !oks { return false; }
    var skiv: u8[>..] = [];
    asn1::put_octets(skiv, ski);
    put_ext(exts, "2.5.29.14", false, skiv);
    if issuer_key_id.len > 0 {
        var aki: u8[>..] = [];
        asn1::put(aki, asn1::ctx(0, false), issuer_key_id);
        var v: u8[>..] = [];
        asn1::put(v, asn1::SEQUENCE, aki);
        put_ext(exts, "2.5.29.35", false, v);
    }
    if t.san.len > 0 {
        var v: u8[>..] = [];
        asn1::put(v, asn1::SEQUENCE, t.san);
        // Critical when the subject is empty (RFC 5280 §4.2.1.6).
        put_ext(exts, "2.5.29.17", t.subject.len <= 2, v);
    }
    if t.permitted.len > 0 || t.excluded.len > 0 {
        var body: u8[>..] = [];
        for which in 2 {
            let list = if which == 0 { t.permitted[..] } else { t.excluded[..] };
            if list.len == 0 { continue; }
            // Each GeneralName becomes a GeneralSubtree.
            var subs: u8[>..] = [];
            var off = 0;
            while off < list.len {
                let g, okg = asn1::read(list, off, list.len);
                if !okg { return false; }
                asn1::put(subs, asn1::SEQUENCE, list[g.start..g.end]);
                off = g.end;
            }
            asn1::put(body, asn1::ctx(which as! u32, true), subs);
        }
        var v: u8[>..] = [];
        asn1::put(v, asn1::SEQUENCE, body);
        put_ext(exts, "2.5.29.30", true, v);
    }
    if t.policies.len > 0 {
        var body: u8[>..] = [];
        for oid in split(t.policies, ' ') {
            if oid.len == 0 { continue; }
            let enc, oke = asn1::oid_encode(oid);
            if !oke { return false; }
            var pi: u8[>..] = [];
            asn1::put(pi, asn1::OID, enc);
            asn1::put(body, asn1::SEQUENCE, pi);
        }
        var v: u8[>..] = [];
        asn1::put(v, asn1::SEQUENCE, body);
        put_ext(exts, "2.5.29.32", false, v);
    }
    if t.crl_urls.len > 0 {
        var body: u8[>..] = [];
        for url in split(t.crl_urls, ' ') {
            if url.len == 0 { continue; }
            var gn: u8[>..] = [];
            asn1::put(gn, asn1::ctx(6, false), url);
            var full: u8[>..] = [];
            asn1::put(full, asn1::ctx(0, true), gn);
            var dpn: u8[>..] = [];
            asn1::put(dpn, asn1::ctx(0, true), full);
            asn1::put(body, asn1::SEQUENCE, dpn);
        }
        var v: u8[>..] = [];
        asn1::put(v, asn1::SEQUENCE, body);
        put_ext(exts, "2.5.29.31", false, v);
    }
    exts.append(t.extra);
    var seq3: u8[>..] = [];
    asn1::put(seq3, asn1::SEQUENCE, exts);
    asn1::put(out, asn1::ctx(3, true), seq3);
    return true;
}

// Signs a to-be-signed SEQUENCE: tbs, AlgorithmIdentifier, BIT STRING.
fn signed(tbs: const u8[:], alg_id: const u8[:], key: const PrivateKey&, alg: i64, h: i64) -> u8[>..] {
    var body: u8[>..] = [];
    body.append(tbs);
    body.append(alg_id);
    asn1::put_bits(body, sign(key, alg, h, tbs));
    var out: u8[>..] = [];
    asn1::put(out, asn1::SEQUENCE, body);
    return out;
}

fn pick_alg(t_alg: i64, t_hash: i64, key: const PrivateKey&) -> i64, i64 {
    if t_alg != 0 { return t_alg, t_hash; }
    return default_sig(key.kind);
}

// A certificate for the public key `spki` (SubjectPublicKeyInfo DER),
// issued by `issuer` (empty for self-signed) with `issuer_key`, which for
// a self-signed certificate is the subject's own. OK, or why not:
// ERR_KEY_USAGE when the issuer may not sign certificates, ERR_MALFORMED
// for a template or key that will not encode, ERR_UNSUPPORTED_ALGORITHM
// when the key cannot sign with the algorithm asked for.
fn create_certificate(t: const Template&, spki: const u8[:], issuer_der: const u8[:],
                      issuer_key: const PrivateKey&) -> u8[>..], i64 {
    var none: u8[>..] = [];
    let alg, h = pick_alg(t.sig_alg, t.sig_hash, issuer_key);
    if !sig_fits_key(issuer_key.kind, alg, h) { return none, ERR_UNSUPPORTED_ALGORITHM; }
    var issuer_name: u8[>..] = [];
    var issuer_kid: u8[>..] = [];
    if issuer_der.len == 0 {
        issuer_name.append(t.subject);
        let kid, okk = key_id(spki);
        if !okk { return none, ERR_MALFORMED; }
        issuer_kid = copy(kid);
        // The key must be the subject's own.
        if marshal_public_key(issuer_key) != spki { return none, ERR_BAD_SIGNATURE; }
    } else {
        let ic, e = parse(issuer_der);
        if e != OK { return none, e; }
        if !ic.is_ca || (ic.has_key_usage && ic.key_usage & KU_KEY_CERT_SIGN == 0) { return none, ERR_KEY_USAGE; }
        issuer_name.append(ic.der[ic.subject.start..ic.subject.end]);
        if ic.ski.end > ic.ski.off { issuer_kid.append(ic.der[ic.ski.off..ic.ski.end]); }
        if marshal_public_key(issuer_key) != ic.der[ic.spki.start..ic.spki.end] { return none, ERR_BAD_SIGNATURE; }
    }
    var serial: u8[>..] = [];
    serial.append(t.serial);
    if serial.len == 0 {
        serial.resize(16, 0);
        bignum::random_bytes(serial);
        serial[0] = (serial[0] & 0x7f) | 0x01;               // positive, and 16 bytes long
    }
    let alg_id = sig_alg_id(alg, h);
    var tbs: u8[>..] = [];
    var v3: u8[>..] = [];
    asn1::put_i64(v3, 2);
    asn1::put(tbs, asn1::ctx(0, true), v3);
    asn1::put_uint(tbs, serial);
    tbs.append(alg_id);
    tbs.append(issuer_name);
    var validity: u8[>..] = [];
    asn1::put_time(validity, t.not_before);
    asn1::put_time(validity, t.not_after);
    asn1::put(tbs, asn1::SEQUENCE, validity);
    if t.subject.len == 0 { asn1::put(tbs, asn1::SEQUENCE, ""); } else { tbs.append(t.subject); }
    tbs.append(spki);
    if !put_extensions(tbs, t, spki, issuer_kid) { return none, ERR_MALFORMED; }
    var tbs_seq: u8[>..] = [];
    asn1::put(tbs_seq, asn1::SEQUENCE, tbs);
    var cert = signed(tbs_seq, alg_id, issuer_key, alg, h);
    // What was made must parse.
    let c, pe = parse(cert);
    if pe != OK { cert.clear(); }
    return cert, pe;
}

// --- Certificate requests (PKCS #10, RFC 2986) ------------------------------------

struct Csr {
    subject: asn1::Tlv, spki: asn1::Tlv, key_type: i64, key: asn1::Tlv,
    info: asn1::Tlv, sig_alg: i64, sig_hash: i64, pss_salt: i64, sig: asn1::Tlv,
    has_san: bool, san: asn1::Tlv,
    der: u8[>..],
}

// A request for subject (Name DER) and the SAN entries in `san` (a
// GeneralNames builder's contents; empty for none), signed by key.
fn create_csr(subject: const u8[:], san: const u8[:], key: const PrivateKey&) -> u8[>..] {
    let alg, h = default_sig(key.kind);
    var info: u8[>..] = [];
    asn1::put_i64(info, 0);
    info.append(subject);
    info.append(marshal_public_key(key));
    var attrs: u8[>..] = [];
    if san.len > 0 {
        // extensionRequest (PKCS #9): a SET holding the Extensions.
        var v: u8[>..] = [];
        asn1::put(v, asn1::SEQUENCE, san);
        var exts: u8[>..] = [];
        put_ext(exts, "2.5.29.17", false, v);
        var extseq: u8[>..] = [];
        asn1::put(extseq, asn1::SEQUENCE, exts);
        var attr: u8[>..] = [];
        asn1::put_oid(attr, "1.2.840.113549.1.9.14");
        asn1::put(attr, asn1::SET, extseq);
        asn1::put(attrs, asn1::SEQUENCE, attr);
    }
    asn1::put(info, asn1::ctx(0, true), attrs);
    var info_seq: u8[>..] = [];
    asn1::put(info_seq, asn1::SEQUENCE, info);
    return signed(info_seq, sig_alg_id(alg, h), key, alg, h);
}

fn parse_csr(der: const u8[:]) -> Csr, i64 {
    var r = Csr { subject: no_tlv(), spki: no_tlv(), key_type: KEY_UNKNOWN, key: no_tlv(), info: no_tlv(),
                  sig_alg: SIG_UNKNOWN, sig_hash: 0, pss_salt: 0, sig: no_tlv(), has_san: false, san: no_tlv(), der: [] };
    r.der.append(der);
    let d = r.der[..];
    let top, ok = asn1::parse(d);
    let parts, okp = asn1::children_of(d, top, asn1::SEQUENCE);
    if !ok || !okp || parts.len != 3 || parts[2].tag != asn1::BIT_STRING { return r, ERR_MALFORMED; }
    r.info = parts[0];
    r.sig = parts[2];
    let alg, h, salt = sig_alg_of(d, parts[1]);
    r.sig_alg = alg;
    r.sig_hash = h;
    r.pss_salt = salt;
    let f, okf = asn1::children_of(d, parts[0], asn1::SEQUENCE);
    if !okf || f.len != 4 || f[3].tag != asn1::ctx(0, true) { return r, ERR_MALFORMED; }
    let v, okv = asn1::read_i64(d, f[0]);
    if !okv || v != 0 { return r, ERR_MALFORMED; }
    r.subject = f[1];
    r.spki = f[2];
    let kind, key, okk = spki_of(d, f[2]);
    if !okk { return r, ERR_MALFORMED; }
    r.key_type = kind;
    r.key = key;
    let attrs, oka = asn1::children(d, f[3]);
    if !oka { return r, ERR_MALFORMED; }
    for a in attrs {
        let p, okat = asn1::children_of(d, a, asn1::SEQUENCE);
        if !okat || p.len != 2 || p[1].tag != asn1::SET { return r, ERR_MALFORMED; }
        if !asn1::oid_is(d, p[0], "1.2.840.113549.1.9.14") { continue; }
        let vals, okvals = asn1::children(d, p[1]);
        if !okvals || vals.len != 1 { return r, ERR_MALFORMED; }
        let exts, okx = asn1::children_of(d, vals[0], asn1::SEQUENCE);
        if !okx { return r, ERR_MALFORMED; }
        for e in exts {
            let ef, okef = asn1::children_of(d, e, asn1::SEQUENCE);
            if !okef || ef.len < 2 { return r, ERR_MALFORMED; }
            if asn1::oid_is(d, ef[0], "2.5.29.17") {
                let val = ef[ef.len - 1];
                let inner, oki = asn1::read(d, val.off, val.end);
                if !oki { return r, ERR_MALFORMED; }
                r.has_san = true;
                r.san = inner;
            }
        }
    }
    return r, OK;
}

// Whether the request is signed by the key it carries (CheckSignature).
fn check_csr(r: const Csr&) -> i64 {
    // verify_with takes a Cert; a stand-in holding the request's key does.
    var holder = empty_cert();
    holder.der.append(r.der);
    holder.key_type = r.key_type;
    holder.key = r.key;
    let d = r.der[..];
    let sig, ok = key_bytes(d, r.sig);
    if !ok { return ERR_MALFORMED; }
    if r.sig_alg == SIG_UNKNOWN { return ERR_UNSUPPORTED_ALGORITHM; }
    return verify_with(holder, r.sig_alg, r.sig_hash, r.pss_salt, d[r.info.start..r.info.end], sig);
}

fn csr_dns_names(r: const Csr&) -> u8[][>..] {
    var holder = empty_cert();
    holder.der.append(r.der);
    holder.has_san = r.has_san;
    holder.san = r.san;
    return dns_names(holder);
}

// --- CRLs -------------------------------------------------------------------------

// One revoked certificate: its serial (big-endian magnitude), when, and
// why (a REASON_* value, or -1 for none given).
struct Revoked { serial: u8[..20], time: i64, reason: i64 }

// A v2 CRL from `issuer` (DER) and its key, with an authority key
// identifier and a CRL number.
fn create_crl(issuer_der: const u8[:], key: const PrivateKey&, entries: const Revoked[:], this_update: i64,
              next_update: i64, number: i64) -> u8[>..], i64 {
    var none: u8[>..] = [];
    let ic, e = parse(issuer_der);
    if e != OK { return none, e; }
    if ic.has_key_usage && ic.key_usage & KU_CRL_SIGN == 0 { return none, ERR_KEY_USAGE; }
    if marshal_public_key(key) != ic.der[ic.spki.start..ic.spki.end] { return none, ERR_BAD_SIGNATURE; }
    let alg, h = default_sig(key.kind);
    let alg_id = sig_alg_id(alg, h);
    var tbs: u8[>..] = [];
    asn1::put_i64(tbs, 1);
    tbs.append(alg_id);
    tbs.append(ic.der[ic.subject.start..ic.subject.end]);
    asn1::put_time(tbs, this_update);
    asn1::put_time(tbs, next_update);
    if entries.len > 0 {
        var list: u8[>..] = [];
        for r in entries {
            var ent: u8[>..] = [];
            asn1::put_uint(ent, r.serial);
            asn1::put_time(ent, r.time);
            if r.reason >= 0 {
                var reason: u8[>..] = [];
                asn1::put_i64(reason, r.reason, asn1::ENUMERATED);
                var ext: u8[>..] = [];
                put_ext(ext, "2.5.29.21", false, reason);
                asn1::put(ent, asn1::SEQUENCE, ext);
            }
            asn1::put(list, asn1::SEQUENCE, ent);
        }
        asn1::put(tbs, asn1::SEQUENCE, list);
    }
    var exts: u8[>..] = [];
    if ic.ski.end > ic.ski.off {
        var aki: u8[>..] = [];
        asn1::put(aki, asn1::ctx(0, false), ic.der[ic.ski.off..ic.ski.end]);
        var v: u8[>..] = [];
        asn1::put(v, asn1::SEQUENCE, aki);
        put_ext(exts, "2.5.29.35", false, v);
    }
    var num: u8[>..] = [];
    asn1::put_i64(num, number);
    put_ext(exts, "2.5.29.20", false, num);
    var extseq: u8[>..] = [];
    asn1::put(extseq, asn1::SEQUENCE, exts);
    asn1::put(tbs, asn1::ctx(0, true), extseq);
    var tbs_seq: u8[>..] = [];
    asn1::put(tbs_seq, asn1::SEQUENCE, tbs);
    return signed(tbs_seq, alg_id, key, alg, h), OK;
}
