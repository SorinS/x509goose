// x509.cms: CMS SignedData (RFC 5652 §5), as PKINIT (RFC 4556) carries
// its requests and the KDC its replies in it: made with one signer and
// read and checked with one.
//
// Made: SignedData version 3 (its content type is never id-data here),
// the content encapsulated, the signer's certificate and any others in
// `certificates`, one SignerInfo (version 1, issuerAndSerialNumber) with
// the signed attributes contentType and messageDigest. The digest is
// SHA-256, -384 or -512; the signature PKCS #1 v1.5, PSS or ECDSA. An
// unsigned SignedData (no certificates, no signers) is what anonymous
// PKINIT sends (RFC 8062 §4.1).
//
// Read: strict DER, one signer or none. The signer is found among the
// certificates sent by issuer and serial number or by subject key
// identifier; signed attributes are required (RFC 5652 §5.3: the content
// type is not id-data), each once with one value, the contentType equal
// to the eContentType and the messageDigest to the content's digest. The
// signature is over the attributes' DER with the SET OF tag, by
// rsaEncryption with the digest algorithm, or by a signature algorithm
// whose hash is the digest algorithm. SHA-1 is refused unless asked for.
// Checking the signer's certificate (its path, its usages) is the
// caller's.
//
// For S/MIME (RFC 8551), cms_sign_with also signs id-data (SignedData
// version 1), detached (eContent absent) or not, with the signingTime and
// smimeCapabilities attributes when asked, the signer named by key
// identifier when asked (version 3), by Ed25519 too (RFC 8419: the
// digest SHA-512, the signature over the attributes themselves), by Ed448
// (RFC 8419: the digest id-shake256-len with 512 output bits over the
// signed attributes, id-shake256 without them; pure Ed448, no context),
// and by ML-DSA (RFC 9882: pure ML-DSA-44, -65 or -87 with the empty
// context over the attributes, or the content without them; the digest SHA-512 when
// made, and SHA-256, -384, -512, SHAKE128 or SHAKE256 when read).
// cms_verify_detached checks a signature over content sent beside it;
// over id-data the signed attributes may be absent, the signature then
// over the content. cms_der reads BER (indefinite lengths, constructed
// OCTET STRINGs), as mail clients send CMS, into the DER this reads.
// Enveloping is cms_env's.

namespace x509;

import std;
import x509;
import keys;
import asn1;
import bignum;
import bignum.hmac;
import bignum.sha3;

let OID_CMS_DATA: const u8[:] = "1.2.840.113549.1.7.1";
let OID_CMS_SIGNED_DATA: const u8[:] = "1.2.840.113549.1.7.2";
let OID_CMS_CONTENT_TYPE: const u8[:] = "1.2.840.113549.1.9.3";
let OID_CMS_MESSAGE_DIGEST: const u8[:] = "1.2.840.113549.1.9.4";
let OID_RSA_ENCRYPTION: const u8[:] = "1.2.840.113549.1.1.1";
let OID_CMS_SIGNING_TIME: const u8[:] = "1.2.840.113549.1.9.5";
let OID_SMIME_CAPABILITIES: const u8[:] = "1.2.840.113549.1.9.15";
let OID_ED25519: const u8[:] = "1.3.101.112";
let OID_SHAKE128: const u8[:] = "2.16.840.1.101.3.4.2.11";
let OID_SHAKE256: const u8[:] = "2.16.840.1.101.3.4.2.12";
let OID_SHAKE256_LEN: const u8[:] = "2.16.840.1.101.3.4.2.18";
let OID_ED448: const u8[:] = "1.3.101.113";

// Digests beyond SHA-1 and SHA-2 (160, 256, 384, 512): SHAKE128 with a
// 32-byte output and SHAKE256 with a 64-byte one (RFC 8702), which ML-DSA
// signers may use (RFC 9882; openssl's default for them is SHAKE256).
let CMS_SHAKE128: i64 = 4128;
let CMS_SHAKE256: i64 = 4256;
// id-shake256-len with its parameter 512 (RFC 8419 §2.3): SHAKE256 with a
// 64-byte output as well, the digest of Ed448 signers with signed
// attributes (RFC 8419 §3.1).
let CMS_SHAKE256_LEN: i64 = 4257;

// What cms_sign_with does beyond cms_sign.
struct CmsSignOptions {
    detached:     bool = false,   // eContent left out: the content travels beside the SignedData
    signing_time: i64  = -1,      // the signingTime attribute, seconds since 1970; -1: none
    capabilities: bool = false,   // the smimeCapabilities attribute (RFC 8551 §2.5.2)
    by_key_id:    bool = false,   // the signer named by subject key identifier (SignerInfo version 3)
    no_certs:     bool = false,   // no `certificates`: the verifier has the signer's (RFC 3161's certReq false)
    extra_attrs:  u8[>..] = [],   // more signed attributes, whole Attribute elements laid end to end
}

// A SignedData as read: offsets into its own copy of the DER.
struct SignedData {
    content_type: asn1::Tlv,      // eContentType, an OID
    content: asn1::Tlv,           // eContent's OCTET STRING (content_len 0 and start == end if absent)
    has_content: bool,
    certs: asn1::Tlv,             // the certificates' SET (start == end if absent)
    signer: asn1::Tlv,            // the one SignerInfo (start == end if none)
    der: u8[>..],
}

fn cms_no_tlv() -> asn1::Tlv { asn1::Tlv { tag: 0, cls: 0, constructed: false, number: 0, start: 0, off: 0, end: 0 } }

// A SET OF from elements laid end to end in `elems` (each a whole TLV),
// sorted by their encodings as DER wants.
fn cms_set_of(out: u8[>..]&, elems: const u8[:]) {
    var starts: i64[>..] = [];
    var ends: i64[>..] = [];
    var at = 0;
    while at < elems.len {
        let t, ok = asn1::read(elems, at, elems.len);
        assert(ok);
        starts.push(t.start);
        ends.push(t.end);
        at = t.end;
    }
    // Insertion sort: a handful of elements.
    var i = 1;
    while i < starts.len {
        var j = i;
        while j > 0 && cms_less(elems[starts[j]..ends[j]], elems[starts[j - 1]..ends[j - 1]]) {
            let s = starts[j]; starts[j] = starts[j - 1]; starts[j - 1] = s;
            let e = ends[j]; ends[j] = ends[j - 1]; ends[j - 1] = e;
            j -= 1;
        }
        i += 1;
    }
    var body: u8[>..] = [];
    var k = 0;
    while k < starts.len {
        body.append(elems[starts[k]..ends[k]]);
        k += 1;
    }
    asn1::put(out, asn1::SET, body);
}

// X.690 §11.6's order: as octet strings, the shorter padded with zeros.
fn cms_less(a: const u8[:], b: const u8[:]) -> bool {
    var i = 0;
    while i < a.len || i < b.len {
        let x: u8 = if i < a.len { a[i] } else { 0 };
        let y: u8 = if i < b.len { b[i] } else { 0 };
        if x != y { return x < y; }
        i += 1;
    }
    return false;
}

fn cms_digest_alg_id(out: u8[>..]&, h: i64) {
    var body: u8[>..] = [];
    asn1::put_oid(body, if h == 160 { "1.3.14.3.2.26" } else if h == CMS_SHAKE128 { OID_SHAKE128 }
                        else if h == CMS_SHAKE256 { OID_SHAKE256 } else if h == CMS_SHAKE256_LEN { OID_SHAKE256_LEN }
                        else { hash_oid(h) });
    if h == CMS_SHAKE256_LEN { asn1::put_i64(body, 512); }
    asn1::put(out, asn1::SEQUENCE, body);
}

// The hash (160, 256, 384, 512, CMS_SHAKE128, CMS_SHAKE256,
// CMS_SHAKE256_LEN) a digest AlgorithmIdentifier names (parameters absent
// or NULL; absent for SHAKE; 512 for id-shake256-len), or 0.
fn cms_digest_of(der: const u8[:], t: asn1::Tlv) -> i64 {
    let p, ok = asn1::children_of(der, t, asn1::SEQUENCE);
    if ok && p.len == 2 && asn1::oid_is(der, p[0], OID_SHAKE256_LEN) {
        let bits, okb = asn1::read_i64(der, p[1]);
        return if okb && bits == 512 { CMS_SHAKE256_LEN } else { 0 };
    }
    if !ok || p.len < 1 || p.len > 2 || (p.len == 2 && !asn1::read_null(der, p[1])) { return 0; }
    if asn1::oid_is(der, p[0], "1.3.14.3.2.26") { return 160; }
    if asn1::oid_is(der, p[0], OID_SHAKE128) && p.len == 1 { return CMS_SHAKE128; }
    if asn1::oid_is(der, p[0], OID_SHAKE256) && p.len == 1 { return CMS_SHAKE256; }
    return hash_of_oid(der, p[0]);
}

// The digest of data by h (a hash cms_digest_of gives).
fn cms_hash(h: i64, data: const u8[:]) -> u8[>..] {
    if h == CMS_SHAKE128 { return bignum::shake(128, data, 32); }
    if h == CMS_SHAKE256 || h == CMS_SHAKE256_LEN { return bignum::shake(256, data, 64); }
    return bignum::hash_bits(h, data);
}

fn cms_encap(out: u8[>..]&, content_type: const u8[:], content: const u8[:]) {
    var body: u8[>..] = [];
    asn1::put_oid(body, content_type);
    var oct: u8[>..] = [];
    asn1::put_octets(oct, content);
    asn1::put(body, asn1::ctx(0, true), oct);
    asn1::put(out, asn1::SEQUENCE, body);
}

fn cms_content_info(sd: const u8[:]) -> u8[>..] {
    var body: u8[>..] = [];
    asn1::put_oid(body, OID_CMS_SIGNED_DATA);
    asn1::put(body, asn1::ctx(0, true), sd);
    var out: u8[>..] = [];
    asn1::put(out, asn1::SEQUENCE, body);
    return out;
}

// The signed attributes' content (laid end to end, sorted): contentType
// and messageDigest.
fn cms_signed_attrs(content_type: const u8[:], digest: const u8[:]) -> u8[>..] {
    let o = CmsSignOptions { .. };
    return cms_signed_attrs_with(content_type, digest, o);
}

// An Attribute of one value (an encoded element), appended to out.
fn cms_attr(out: u8[>..]&, oid: const u8[:], value: const u8[:]) {
    var a: u8[>..] = [];
    asn1::put_oid(a, oid);
    cms_set_of(a, value);
    asn1::put(out, asn1::SEQUENCE, a);
}

// SMIMECapabilities (RFC 8551 §2.5.2), the ciphers this reads, the
// preferred first: AES-256-GCM, AES-128-GCM, AES-256-CBC, AES-128-CBC.
fn cms_capabilities() -> u8[>..] {
    var caps: u8[>..] = [];
    for oid in ["2.16.840.1.101.3.4.1.46", "2.16.840.1.101.3.4.1.6", "2.16.840.1.101.3.4.1.42", "2.16.840.1.101.3.4.1.2"] {
        var c: u8[>..] = [];
        asn1::put_oid(c, oid);
        asn1::put(caps, asn1::SEQUENCE, c);
    }
    var out: u8[>..] = [];
    asn1::put(out, asn1::SEQUENCE, caps);
    return out;
}

// The signed attributes as a SET (sorted): contentType and messageDigest,
// then signingTime and smimeCapabilities if o asks for them.
fn cms_signed_attrs_with(content_type: const u8[:], digest: const u8[:], o: const CmsSignOptions&) -> u8[>..] {
    var all: u8[>..] = [];
    var v: u8[>..] = [];
    asn1::put_oid(v, content_type);
    cms_attr(all, OID_CMS_CONTENT_TYPE, v);
    v.clear();
    asn1::put_octets(v, digest);
    cms_attr(all, OID_CMS_MESSAGE_DIGEST, v);
    if o.signing_time >= 0 {
        v.clear();
        asn1::put_time(v, o.signing_time);     // UTCTime through 2049 (RFC 5652 §11.3)
        cms_attr(all, OID_CMS_SIGNING_TIME, v);
    }
    if o.capabilities { cms_attr(all, OID_SMIME_CAPABILITIES, cms_capabilities()); }
    all.append(o.extra_attrs);
    var set: u8[>..] = [];
    cms_set_of(set, all);
    return set;
}

// A ContentInfo holding a SignedData of `content` (of type content_type,
// a dotted OID) signed by `key`, whose certificate is `signer`, by
// algorithm alg with hash h (SIG_RSA_PKCS1, SIG_RSA_PSS or SIG_ECDSA;
// 256, 384 or 512). `others` are more certificates to send (the chain
// up from the signer's), DER laid end to end. False if signing fails.
fn cms_sign(content_type: const u8[:], content: const u8[:], key: const PrivateKey&, signer: const Cert&,
            others: const u8[:], alg: i64, h: i64) -> u8[>..], bool {
    assert(alg == SIG_RSA_PKCS1 || alg == SIG_RSA_PSS || alg == SIG_ECDSA);
    let o = CmsSignOptions { .. };
    let out, ok = cms_sign_with(content_type, content, key, signer, others, alg, h, o);
    return out, ok;
}

// cms_sign with options: detached, signingTime, smimeCapabilities, the
// signer by key identifier; SIG_ED25519 too (h is then ignored: the
// digest is SHA-512), SIG_ED448 (h ignored: the digest is id-shake256-len,
// 512 bits), and SIG_MLDSA (RFC 9882: pure ML-DSA of the key's
// set over the signed attributes, the empty context; h the digest, 256,
// 384, 512 or CMS_SHAKE256, 0 for SHA-512, which every set takes). The
// SignedData is version 1 over id-data with the signer by issuer and
// serial, else 3. SIG_RSA_PKCS1 with h 160 signs by SHA-1, the signature
// algorithm rsaEncryption, for SCEP servers that know nothing newer (RFC
// 8894 §3.5.2); nothing else should. False if signing fails, the key is not
// for alg, or the signer's certificate has no key identifier to name it by.
fn cms_sign_with(content_type: const u8[:], content: const u8[:], key: const PrivateKey&, signer: const Cert&,
                 others: const u8[:], alg: i64, h: i64, o: const CmsSignOptions&) -> u8[>..], bool {
    assert(alg == SIG_RSA_PKCS1 || alg == SIG_RSA_PSS || alg == SIG_ECDSA || alg == SIG_ED25519 || alg == SIG_ED448 ||
           alg == SIG_MLDSA);
    var none: u8[>..] = [];
    let ed = alg == SIG_ED25519 || alg == SIG_ED448;
    let ml = alg == SIG_MLDSA;
    if ml && (!is_mldsa(key.kind) || (h != 0 && h != 256 && h != 384 && h != 512 && h != CMS_SHAKE256)) { return none, false; }
    let sha1 = alg == SIG_RSA_PKCS1 && h == 160 && key.kind == KEY_RSA;
    if !sha1 && !sig_fits_key(key.kind, alg, if ed { 0 } else if ml { mldsa_set(key.kind) } else { h }) { return none, false; }
    let dh = if alg == SIG_ED448 { CMS_SHAKE256_LEN } else if ed || (ml && h == 0) { 512 } else { h };   // the digest's hash
    let sh = if ed { 0 } else if ml { mldsa_set(key.kind) } else { h };   // the signature's (ML-DSA: the set)
    let d = signer.der[..];
    if o.by_key_id && signer.ski.end == signer.ski.start { return none, false; }
    let attrs = cms_signed_attrs_with(content_type, cms_hash(dh, content), o);
    var sig: u8[>..] = [];
    if sha1 {
        let s1, ok1 = bignum::rsa_sign_pkcs1(key.rsa, attrs, 160);
        if !ok1 { return none, false; }
        sig = copy(s1);
    } else {
        let s2, ok2 = sign(key, alg, sh, attrs);
        if !ok2 { return none, false; }
        sig = copy(s2);
    }
    var si: u8[>..] = [];
    if o.by_key_id {
        asn1::put_i64(si, 3);
        asn1::put(si, asn1::ctx(0, false), d[signer.ski.off..signer.ski.end]);
    } else {
        var sid: u8[>..] = [];
        sid.append(d[signer.issuer.start..signer.issuer.end]);
        sid.append(d[signer.serial.start..signer.serial.end]);
        asn1::put_i64(si, 1);
        asn1::put(si, asn1::SEQUENCE, sid);
    }
    cms_digest_alg_id(si, dh);
    // [0] IMPLICIT: the attributes' SET with its tag changed.
    let at, okat = asn1::parse(attrs);
    asn1::put(si, asn1::ctx(0, true), attrs[at.off..]);
    if sha1 {
        var rsa_alg: u8[>..] = [];
        asn1::put_oid(rsa_alg, OID_RSA_ENCRYPTION);
        asn1::put_null(rsa_alg);
        asn1::put(si, asn1::SEQUENCE, rsa_alg);
    } else {
        si.append(sig_alg_id(alg, sh));
    }
    asn1::put_octets(si, sig);
    var sis: u8[>..] = [];
    asn1::put(sis, asn1::SEQUENCE, si);

    var sd: u8[>..] = [];
    asn1::put_i64(sd, if o.by_key_id || content_type != OID_CMS_DATA { 3 } else { 1 });
    var dalg: u8[>..] = [];
    cms_digest_alg_id(dalg, dh);
    asn1::put(sd, asn1::SET, dalg);
    if o.detached {
        var enc: u8[>..] = [];
        asn1::put_oid(enc, content_type);
        asn1::put(sd, asn1::SEQUENCE, enc);
    } else {
        cms_encap(sd, content_type, content);
    }
    if !o.no_certs {
        var certs: u8[>..] = [];
        certs.append(d);
        certs.append(others);
        var cset: u8[>..] = [];
        cms_set_of(cset, certs);
        let ct, okct = asn1::parse(cset);
        asn1::put(sd, asn1::ctx(0, true), cset[ct.off..]);
    }
    asn1::put(sd, asn1::SET, sis);
    var sdq: u8[>..] = [];
    asn1::put(sdq, asn1::SEQUENCE, sd);
    return cms_content_info(sdq), true;
}

// A ContentInfo holding a SignedData of `content` with no certificates
// and no signers (RFC 8062's anonymous PKINIT).
fn cms_unsigned(content_type: const u8[:], content: const u8[:]) -> u8[>..] {
    var sd: u8[>..] = [];
    asn1::put_i64(sd, 3);
    asn1::put(sd, asn1::SET, "");
    cms_encap(sd, content_type, content);
    asn1::put(sd, asn1::SET, "");
    var sdq: u8[>..] = [];
    asn1::put(sdq, asn1::SEQUENCE, sd);
    return cms_content_info(sdq);
}

// Reads a ContentInfo holding a SignedData: OK, or ERR_MALFORMED (more
// than one signer, or anything but DER), or ERR_UNSUPPORTED_ALGORITHM.
fn cms_parse_signed(der: const u8[:]) -> SignedData, i64 {
    var sd = SignedData { content_type: cms_no_tlv(), content: cms_no_tlv(), has_content: false, certs: cms_no_tlv(),
                          signer: cms_no_tlv(), der: der };
    let d = sd.der[..];
    let top, ok = asn1::parse(d);
    if !ok { return sd, ERR_MALFORMED; }
    let ci, okc = asn1::children_of(d, top, asn1::SEQUENCE);
    if !okc || ci.len != 2 || !asn1::oid_is(d, ci[0], OID_CMS_SIGNED_DATA) || ci[1].tag != asn1::ctx(0, true) {
        return sd, ERR_MALFORMED;
    }
    let inner, oki = asn1::explicit(d, ci[1]);
    if !oki { return sd, ERR_MALFORMED; }
    let f, okf = asn1::children_of(d, inner, asn1::SEQUENCE);
    if !okf || f.len < 4 { return sd, ERR_MALFORMED; }
    let version, okv = asn1::read_i64(d, f[0]);
    if !okv || version < 1 || version > 5 || f[1].tag != asn1::SET { return sd, ERR_MALFORMED; }
    let enc, oke = asn1::children_of(d, f[2], asn1::SEQUENCE);
    if !oke || enc.len < 1 || enc.len > 2 || enc[0].tag != asn1::OID { return sd, ERR_MALFORMED; }
    sd.content_type = enc[0];
    if enc.len == 2 {
        if enc[1].tag != asn1::ctx(0, true) { return sd, ERR_MALFORMED; }
        let oct, oko = asn1::explicit(d, enc[1]);
        if !oko || oct.tag != asn1::OCTET_STRING { return sd, ERR_MALFORMED; }
        sd.content = oct;
        sd.has_content = true;
    }
    var i = 3;
    if i < f.len && f[i].tag == asn1::ctx(0, true) { sd.certs = f[i]; i += 1; }
    if i < f.len && f[i].tag == asn1::ctx(1, true) { i += 1; }   // crls: not used
    if i != f.len - 1 || f[i].tag != asn1::SET { return sd, ERR_MALFORMED; }
    let sis, oks = asn1::children(d, f[i]);
    if !oks || sis.len > 1 { return sd, ERR_MALFORMED; }
    for s in sis { sd.signer = s; }
    return sd, OK;
}

// The certificates a SignedData carries, DER laid end to end (X.509
// certificates only; other choices are skipped).
fn cms_certs(sd: const SignedData&) -> u8[>..] {
    var out: u8[>..] = [];
    if sd.certs.end == sd.certs.start { return out; }
    let d = sd.der[..];
    let cs, ok = asn1::children(d, sd.certs);
    if !ok { return out; }
    for c in cs {
        if c.tag == asn1::SEQUENCE { out.append(d[c.start..c.end]); }
    }
    return out;
}

// The content (eContent's octets).
fn cms_content(sd: const SignedData&) -> const u8[:] { sd.der[sd.content.off..sd.content.end] }

// Whether a SignedData has a signer.
fn cms_signed(sd: const SignedData&) -> bool { sd.signer.end > sd.signer.start }

// Whether the signer identifier `sid` names certificate c.
fn cms_sid_matches(d: const u8[:], sid: asn1::Tlv, c: const Cert&) -> bool {
    let cd = c.der[..];
    if sid.tag == asn1::SEQUENCE {
        let p, ok = asn1::children(d, sid);
        if !ok || p.len != 2 { return false; }
        return d[p[0].start..p[0].end] == cd[c.issuer.start..c.issuer.end] &&
               d[p[1].start..p[1].end] == cd[c.serial.start..c.serial.end];
    }
    if sid.tag == asn1::ctx(0, false) {
        return c.ski.end > c.ski.start && d[sid.off..sid.end] == cd[c.ski.off..c.ski.end];
    }
    return false;
}

// Checks the signer of a SignedData: finds its certificate among those
// sent, checks the signed attributes and the signature. Returns the
// signer's certificate and OK, or ERR_MALFORMED, ERR_UNKNOWN_ISSUER (no
// certificate sent matches the signer), ERR_UNSUPPORTED_ALGORITHM or
// ERR_BAD_SIGNATURE.
fn cms_verify(sd: const SignedData&, allow_sha1: bool = false) -> Cert, i64 {
    if !cms_signed(sd) || !sd.has_content { return empty_cert(), ERR_MALFORMED; }
    let c, e = cms_verify_over(sd, cms_content(sd), allow_sha1, "");
    return c, e;
}

// cms_verify, the signer's certificate looked for among `more_certs` (DER
// laid end to end) too, after those sent: for a SignedData sent without
// certificates (a time-stamp token whose request had certReq false).
fn cms_verify_with_certs(sd: const SignedData&, more_certs: const u8[:], allow_sha1: bool = false) -> Cert, i64 {
    if !cms_signed(sd) || !sd.has_content { return empty_cert(), ERR_MALFORMED; }
    let c, e = cms_verify_over(sd, cms_content(sd), allow_sha1, more_certs);
    return c, e;
}

// cms_verify for a detached signature (eContent absent, as
// multipart/signed sends it), over `content`: ERR_MALFORMED if the
// SignedData carries content of its own.
fn cms_verify_detached(sd: const SignedData&, content: const u8[:], allow_sha1: bool = false) -> Cert, i64 {
    if !cms_signed(sd) || sd.has_content { return empty_cert(), ERR_MALFORMED; }
    let c, e = cms_verify_over(sd, content, allow_sha1, "");
    return c, e;
}

// The signingTime attribute's time, seconds since 1970, and true; false
// if the signer has none (or there is no signer).
fn cms_signing_time(sd: const SignedData&) -> i64, bool {
    let d = sd.der[..];
    if !cms_signed(sd) { return 0, false; }
    let p, ok = asn1::children_of(d, sd.signer, asn1::SEQUENCE);
    if !ok || p.len < 4 || p[3].tag != asn1::ctx(0, true) { return 0, false; }
    let list, okl = asn1::children(d, p[3]);
    if !okl { return 0, false; }
    for a in list {
        let av, oka = asn1::children_of(d, a, asn1::SEQUENCE);
        if !oka || av.len != 2 || !asn1::oid_is(d, av[0], OID_CMS_SIGNING_TIME) { continue; }
        let vals, oks = asn1::children(d, av[1]);
        if !oks || vals.len != 1 { return 0, false; }
        let t, okt = asn1::read_time(d, vals[0]);
        return t, okt;
    }
    return 0, false;
}

fn cms_verify_over(sd: const SignedData&, content: const u8[:], allow_sha1: bool, more_certs: const u8[:]) -> Cert, i64 {
    let d = sd.der[..];
    let p, ok = asn1::children_of(d, sd.signer, asn1::SEQUENCE);
    if !ok || p.len < 5 || p.len > 7 { return empty_cert(), ERR_MALFORMED; }
    let version, okv = asn1::read_i64(d, p[0]);
    if !okv || (version != 1 && version != 3) { return empty_cert(), ERR_MALFORMED; }
    let sid = p[1];
    let h = cms_digest_of(d, p[2]);
    if h == 0 || (h == 160 && !allow_sha1) { return empty_cert(), ERR_UNSUPPORTED_ALGORITHM; }
    // Signed attributes, which only id-data may do without (RFC 5652 §5.3).
    let data = asn1::oid_is(d, sd.content_type, OID_CMS_DATA);
    let has_attrs = p[3].tag == asn1::ctx(0, true);
    if !has_attrs && !data { return empty_cert(), ERR_MALFORMED; }
    let attrs = p[3];
    let i = if has_attrs { 4 } else { 3 };
    if p.len < i + 2 || p.len > i + 3 || p[i + 1].tag != asn1::OCTET_STRING { return empty_cert(), ERR_MALFORMED; }
    let salg = p[i];
    let sig = d[p[i + 1].off..p[i + 1].end];
    if p.len == i + 3 && p[i + 2].tag != asn1::ctx(1, true) { return empty_cert(), ERR_MALFORMED; }

    // The signed attributes: contentType and messageDigest once each,
    // signingTime at most once.
    if has_attrs {
        let list, okl = asn1::children(d, attrs);
        if !okl { return empty_cert(), ERR_MALFORMED; }
        var seen_ct = false;
        var seen_md = false;
        var seen_st = false;
        for a in list {
            let av, oka = asn1::children_of(d, a, asn1::SEQUENCE);
            if !oka || av.len != 2 || av[0].tag != asn1::OID || av[1].tag != asn1::SET { return empty_cert(), ERR_MALFORMED; }
            let vals, oks = asn1::children(d, av[1]);
            if !oks { return empty_cert(), ERR_MALFORMED; }
            if asn1::oid_is(d, av[0], OID_CMS_CONTENT_TYPE) || asn1::oid_is(d, av[0], OID_CMS_MESSAGE_DIGEST) ||
               asn1::oid_is(d, av[0], OID_CMS_SIGNING_TIME) {
                if vals.len != 1 { return empty_cert(), ERR_MALFORMED; }
            }
            for v in vals {
                if asn1::oid_is(d, av[0], OID_CMS_CONTENT_TYPE) {
                    if seen_ct || v.tag != asn1::OID || d[v.start..v.end] != d[sd.content_type.start..sd.content_type.end] {
                        return empty_cert(), ERR_MALFORMED;
                    }
                    seen_ct = true;
                } else if asn1::oid_is(d, av[0], OID_CMS_MESSAGE_DIGEST) {
                    if seen_md || v.tag != asn1::OCTET_STRING { return empty_cert(), ERR_MALFORMED; }
                    if d[v.off..v.end] != cms_hash(h, content)[..] {
                        return empty_cert(), ERR_BAD_SIGNATURE;
                    }
                    seen_md = true;
                } else if asn1::oid_is(d, av[0], OID_CMS_SIGNING_TIME) {
                    let t, okt = asn1::read_time(d, v);
                    if seen_st || !okt { return empty_cert(), ERR_MALFORMED; }
                    seen_st = true;
                }
            }
        }
        if !seen_ct || !seen_md { return empty_cert(), ERR_MALFORMED; }
    }

    // The signature algorithm: rsaEncryption (PKCS #1 v1.5 with the digest
    // algorithm), Ed25519 with SHA-512 and Ed448 with SHAKE256 (RFC 8419),
    // ML-DSA, or one whose hash is
    // the digest algorithm.
    var alg = SIG_UNKNOWN;
    var salt: i64 = 0;
    let sp, oksp = asn1::children_of(d, salg, asn1::SEQUENCE);
    if !oksp || sp.len < 1 { return empty_cert(), ERR_MALFORMED; }
    if asn1::oid_is(d, sp[0], OID_RSA_ENCRYPTION) && (sp.len == 1 || (sp.len == 2 && asn1::read_null(d, sp[1]))) {
        alg = SIG_RSA_PKCS1;
    } else if h == 160 && sp.len <= 2 && asn1::oid_is(d, sp[0], "1.2.840.113549.1.1.5")
              && (sp.len == 1 || asn1::read_null(d, sp[1])) {
        alg = SIG_RSA_PKCS1;
    } else if h == 160 && sp.len == 1 && asn1::oid_is(d, sp[0], "1.2.840.10045.4.1") {
        alg = SIG_ECDSA;
    } else if sp.len == 1 && asn1::oid_is(d, sp[0], OID_ED25519) {
        if h != 512 { return empty_cert(), ERR_UNSUPPORTED_ALGORITHM; }
        alg = SIG_ED25519;
    } else if sp.len == 1 && asn1::oid_is(d, sp[0], OID_ED448) {
        // RFC 8419: id-shake256-len (512) with signed attributes,
        // id-shake256 without; either is taken, both 64 bytes of SHAKE256.
        if h != CMS_SHAKE256_LEN && h != CMS_SHAKE256 { return empty_cert(), ERR_UNSUPPORTED_ALGORITHM; }
        alg = SIG_ED448;
    } else if sp.len == 1 && mldsa_set_of_oid(d, sp[0]) != 0 {
        // Pure ML-DSA (RFC 9882), parameters absent; any digest but SHA-1.
        if h == 160 { return empty_cert(), ERR_UNSUPPORTED_ALGORITHM; }
        alg = SIG_MLDSA;
        salt = mldsa_set_of_oid(d, sp[0]);       // the set, for verify_with
    } else {
        let a, sh, sl = sig_alg_of(d, salg);
        if a == SIG_UNKNOWN || sh != h { return empty_cert(), ERR_UNSUPPORTED_ALGORITHM; }
        if a != SIG_RSA_PKCS1 && a != SIG_RSA_PSS && a != SIG_ECDSA { return empty_cert(), ERR_UNSUPPORTED_ALGORITHM; }
        alg = a;
        salt = sl;
    }

    // The signer's certificate, among those sent, then the caller's.
    var certs = cms_certs(sd);
    certs.append(more_certs);
    var at = 0;
    while at < certs.len {
        let t, okt = asn1::read(certs, at, certs.len);
        if !okt { return empty_cert(), ERR_MALFORMED; }
        at = t.end;
        let c, e = parse(certs[t.start..t.end]);
        if e != OK || !cms_sid_matches(d, sid, c) { continue; }
        // The signature covers the attributes' DER with the SET OF tag, or
        // without them the content.
        var signed: u8[>..] = [];
        if has_attrs {
            signed.append(d[attrs.start..attrs.end]);
            signed[0] = asn1::SET as! u8;
        } else {
            signed.append(content);
        }
        if alg == SIG_ED25519 || alg == SIG_ED448 { return c, verify_with(c, alg, 0, 0, signed, sig); }
        if alg == SIG_MLDSA { return c, verify_with(c, SIG_MLDSA, salt, 0, signed, sig); }
        let digest = bignum::hash_bits(h, signed);
        let ev = verify_digest(c, alg, h, salt, digest, sig);
        return c, ev;
    }
    return empty_cert(), ERR_UNKNOWN_ISSUER;
}

// cms_parse_signed over BER (cms_der first).
fn cms_parse_signed_ber(ber: const u8[:]) -> SignedData, i64 {
    let der, ok = cms_der(ber);
    if !ok { der.clear(); }
    let sd, e = cms_parse_signed(der);
    return sd, e;
}

// --- BER ------------------------------------------------------------------------

// BER as DER's definite form: indefinite and long-form lengths made
// minimal, and constructed OCTET STRINGs (universal tag 0x24) joined into
// one. Elements already DER are copied as they are; nothing is sorted. A
// constructed string under an IMPLICIT tag cannot be told by its tag and
// stays as it is (cms_octets joins it). False if it does not parse.
fn cms_der(ber: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    let b = ber;
    // The constructed elements open: where each starts in out, where its
    // content starts there, where it ends in b (-1: at its 00 00), the
    // limit its elements must end by, and whether it is an OCTET STRING.
    var tags: i64[>..] = [];
    var hdrs: i64[>..] = [];
    var stops: i64[>..] = [];
    var limits: i64[>..] = [];
    var joins: bool[>..] = [];
    var q = 0;
    var started = false;
    loop {
        // Close those that have ended.
        while tags.len > 0 {
            let k = tags.len - 1;
            if stops[k] < 0 {
                if q + 2 > limits[k] { out.clear(); return out, false; }
                if b[q] != 0 || b[q + 1] != 0 { break; }
                q += 2;
            } else {
                if q > stops[k] { out.clear(); return out, false; }
                if q < stops[k] { break; }
            }
            if !cms_der_close(out, tags[k], hdrs[k], joins[k]) { out.clear(); return out, false; }
            tags.resize(k);
            hdrs.resize(k);
            stops.resize(k);
            limits.resize(k);
            joins.resize(k);
        }
        if tags.len == 0 && started { break; }
        if tags.len > 64 { out.clear(); return out, false; }
        started = true;
        let limit = if tags.len > 0 { limits[tags.len - 1] } else { b.len };
        if q + 2 > limit { out.clear(); return out, false; }
        var p = q + 1;
        if b[q] & 0x1f == 0x1f {
            loop {
                if p >= limit || p - q > 5 { out.clear(); return out, false; }
                let c = b[p];
                p++;
                if c & 0x80 == 0 { break; }
            }
        }
        let tag_end = p;
        if p >= limit { out.clear(); return out, false; }
        let constructed = b[q] & 0x20 != 0;
        let l0 = b[p];
        p++;
        var indefinite = false;
        var len: i64 = 0;
        if l0 == 0x80 {
            if !constructed { out.clear(); return out, false; }
            indefinite = true;
        } else if l0 < 0x80 {
            len = l0;
        } else {
            let nb: i64 = l0 & 0x7f;
            if nb > 8 || p + nb > limit { out.clear(); return out, false; }
            for i in nb {
                if len > 0x7fffffff { out.clear(); return out, false; }
                len = (len << 8) | b[p + i];
            }
            p += nb;
        }
        if !indefinite && len > limit - p { out.clear(); return out, false; }
        if !constructed {
            out.append(b[q..tag_end]);
            cms_put_len(out, len);
            out.append(b[p..p + len]);
            q = p + len;
            continue;
        }
        tags.push(out.len);
        out.append(b[q..tag_end]);
        hdrs.push(out.len);
        stops.push(if indefinite { -1 } else { p + len });
        limits.push(if indefinite { limit } else { p + len });
        joins.push(b[q] == 0x24);
        q = p;
    }
    if q != b.len { out.clear(); return out, false; }
    return out, true;
}

// Ends a constructed element whose content is out[hdr..]: its length put
// before it, or, for an OCTET STRING, its pieces joined into one.
fn cms_der_close(out: u8[>..]&, tag_pos: i64, hdr: i64, join: bool) -> bool {
    var content: u8[>..] = [];
    content.append(out[hdr..]);
    if join {
        let joined, ok = cms_join_octets(content);
        if !ok { return false; }
        out.resize(tag_pos);
        out.push(0x04);
        cms_put_len(out, joined.len);
        out.append(joined);
    } else {
        out.resize(hdr);
        cms_put_len(out, content.len);
        out.append(content);
    }
    return true;
}

fn cms_put_len(out: u8[>..]&, n: i64) {
    if n < 128 { out.push(n as! u8); return; }
    var k = 0;
    var m = n;
    while m > 0 { k++; m >>= 8; }
    out.push((0x80 | k) as! u8);
    var i = k - 1;
    while i >= 0 { out.push(((n >> (8 * i)) & 0xff) as! u8); i--; }
}

// The contents of OCTET STRINGs laid end to end, joined.
fn cms_join_octets(body: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    var r = 0;
    while r < body.len {
        let t, ok = asn1::read(body, r, body.len);
        if !ok || t.tag != asn1::OCTET_STRING { out.clear(); return out, false; }
        out.append(body[t.off..t.end]);
        r = t.end;
    }
    return out, true;
}

// The octets of an OCTET STRING, or of one under an IMPLICIT tag: its
// content if primitive, its pieces joined if constructed.
fn cms_octets(d: const u8[:], t: asn1::Tlv) -> u8[>..], bool {
    if !t.constructed {
        var out: u8[>..] = [];
        out.append(d[t.off..t.end]);
        return out, true;
    }
    let out, ok = cms_join_octets(d[t.off..t.end]);
    return out, ok;
}

// --- Signed attributes and certs-only (SCEP, EST) ---------------------------------

// The value of the signer's signed attribute `oid` (a dotted OID): the one
// value's element, and 1; 0 when the attribute is absent; -1 when it is
// there more than once or with other than one value, or there is no signer.
fn cms_signed_attr(sd: const SignedData&, oid: const u8[:]) -> asn1::Tlv, i64 {
    let d = sd.der[..];
    if !cms_signed(sd) { return cms_no_tlv(), -1; }
    let p, ok = asn1::children_of(d, sd.signer, asn1::SEQUENCE);
    if !ok || p.len < 4 { return cms_no_tlv(), -1; }
    if p[3].tag != asn1::ctx(0, true) { return cms_no_tlv(), 0; }
    let list, okl = asn1::children(d, p[3]);
    if !okl { return cms_no_tlv(), -1; }
    var found = cms_no_tlv();
    var n: i64 = 0;
    for a in list {
        let av, oka = asn1::children_of(d, a, asn1::SEQUENCE);
        if !oka || av.len != 2 || av[1].tag != asn1::SET { return cms_no_tlv(), -1; }
        if !asn1::oid_is(d, av[0], oid) { continue; }
        let vals, oks = asn1::children(d, av[1]);
        if !oks || vals.len != 1 || n > 0 { return cms_no_tlv(), -1; }
        for v in vals { found = v; }
        n = 1;
    }
    return found, n;
}

// A ContentInfo holding a certs-only SignedData (RFC 5652 §5, as RFC 7030
// §4.1.3 and RFC 8894 §3.4 call it; "degenerate" in PKCS #7): no signers,
// id-data without content, the certificates `certs` and the CRLs `crls`
// (DER, each laid end to end; either may be empty).
fn cms_certs_only(certs: const u8[:], crls: const u8[:]) -> u8[>..] {
    var sd: u8[>..] = [];
    asn1::put_i64(sd, 1);
    asn1::put(sd, asn1::SET, "");
    var enc: u8[>..] = [];
    asn1::put_oid(enc, OID_CMS_DATA);
    asn1::put(sd, asn1::SEQUENCE, enc);
    if certs.len > 0 {
        var cset: u8[>..] = [];
        cms_set_of(cset, certs);
        let ct, okct = asn1::parse(cset);
        asn1::put(sd, asn1::ctx(0, true), cset[ct.off..]);
    }
    if crls.len > 0 {
        var lset: u8[>..] = [];
        cms_set_of(lset, crls);
        let lt, oklt = asn1::parse(lset);
        asn1::put(sd, asn1::ctx(1, true), lset[lt.off..]);
    }
    asn1::put(sd, asn1::SET, "");
    var sdq: u8[>..] = [];
    asn1::put(sdq, asn1::SEQUENCE, sd);
    return cms_content_info(sdq);
}

// The CRLs a SignedData carries ([1] crls), DER laid end to end (X.509
// CRLs only; other choices are skipped).
fn cms_crls(sd: const SignedData&) -> u8[>..] {
    var out: u8[>..] = [];
    let d = sd.der[..];
    let top, ok = asn1::parse(d);
    let ci, okc = asn1::children_of(d, top, asn1::SEQUENCE);
    if !ok || !okc || ci.len != 2 { return out; }
    let inner, oki = asn1::explicit(d, ci[1]);
    let f, okf = asn1::children_of(d, inner, asn1::SEQUENCE);
    if !oki || !okf { return out; }
    for x in f {
        if x.tag != asn1::ctx(1, true) { continue; }
        let ls, okl = asn1::children(d, x);
        if !okl { return out; }
        for l in ls {
            if l.tag == asn1::SEQUENCE { out.append(d[l.start..l.end]); }
        }
    }
    return out;
}
