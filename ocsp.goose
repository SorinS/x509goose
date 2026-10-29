// x509.ocsp: the Online Certificate Status Protocol (RFC 6960), as Go's
// x/crypto/ocsp has it: requests for one certificate (made and parsed),
// basic responses (parsed, checked and made) and the unsuccessful status
// responses.
//
// Checking is stricter than Go's in two ways RFC 6960 asks for: the
// response's CertID must name the certificate's issuer (both hashes) and
// serial, and a delegated responder's certificate must carry the
// id-kp-OCSPSigning extended key usage.

namespace x509;

import std;
import os;
import x509;
import keys;
import asn1;
import bignum;
import bignum.hmac;
import verify;

// Certificate status, and the responseStatus of an OCSPResponse.
let OCSP_GOOD: i64 = 0;
let OCSP_REVOKED: i64 = 1;
let OCSP_UNKNOWN: i64 = 2;

let OCSP_SUCCESS: i64 = 0;
let OCSP_MALFORMED_REQUEST: i64 = 1;
let OCSP_INTERNAL_ERROR: i64 = 2;
let OCSP_TRY_LATER: i64 = 3;
let OCSP_SIG_REQUIRED: i64 = 5;
let OCSP_UNAUTHORIZED: i64 = 6;

let OID_OCSP_BASIC: const u8[:] = "1.3.6.1.5.5.7.48.1.1";

// One certificate's CertID: the hash (a bignum.hmac id: SHA-1, -256,
// -384 or -512), the hashes of its issuer's name and key, its serial
// number (INTEGER content).
struct OcspCertId { hash: i64, name_hash: u8[..64], key_hash: u8[..64], serial: u8[..64] }

// A parsed response. Times are seconds since 1970; next_update and
// revoked_at are -1 when absent, reason -1 when not given. The Tlvs point
// into der.
struct OcspResponse {
    response_status: i64,
    status: i64, id: OcspCertId,
    produced_at: i64, this_update: i64, next_update: i64, revoked_at: i64, reason: i64,
    tbs: asn1::Tlv, sig_alg: i64, sig_hash: i64, pss_salt: i64, sig: asn1::Tlv,
    responder_name: asn1::Tlv, responder_key_hash: asn1::Tlv,   // one of them, start == end for the other
    has_cert: bool, cert: asn1::Tlv,                             // the first certificate it carries
    der: u8[>..],
}

fn ocsp_hash_oid(h: i64) -> const u8[:] {
    if h == 160 { "1.3.14.3.2.26" } else { hash_oid(h) }
}

fn ocsp_hash_of(d: const u8[:], alg: asn1::Tlv) -> i64 {
    let ps, ok = asn1::children_of(d, alg, asn1::SEQUENCE);
    if !ok || ps.len < 1 || ps.len > 2 { return 0; }
    if ps.len == 2 && !asn1::read_null(d, ps[1]) { return 0; }
    if asn1::oid_is(d, ps[0], "1.3.14.3.2.26") { return 160; }
    for h in [256, 384, 512] { if asn1::oid_is(d, ps[0], hash_oid(h)) { return h; } }
    return 0;
}

// The CertID of c, issued by issuer, under the hash h.
fn ocsp_cert_id(c: const Cert&, issuer: const Cert&, h: i64 = 160) -> OcspCertId {
    var id = OcspCertId { hash: h, name_hash: [], key_hash: [], serial: [] };
    let d = issuer.der[..];
    id.name_hash.append(bignum::hash_bits(h, d[issuer.subject.start..issuer.subject.end]));
    let kb, ok = key_bytes(d, issuer.key);
    id.key_hash.append(bignum::hash_bits(h, kb));
    id.serial.append(c.der[c.serial.off..c.serial.end]);
    return id;
}

fn ocsp_put_cert_id(out: u8[>..]&, id: const OcspCertId&) {
    var alg: u8[>..] = [];
    asn1::put_oid(alg, ocsp_hash_oid(id.hash));
    asn1::put_null(alg);
    var body: u8[>..] = [];
    asn1::put(body, asn1::SEQUENCE, alg);
    asn1::put_octets(body, id.name_hash);
    asn1::put_octets(body, id.key_hash);
    asn1::put(body, asn1::INTEGER, id.serial);
    asn1::put(out, asn1::SEQUENCE, body);
}

fn ocsp_read_cert_id(d: const u8[:], t: asn1::Tlv) -> OcspCertId, bool {
    var id = OcspCertId { hash: 0, name_hash: [], key_hash: [], serial: [] };
    let fs, ok = asn1::children_of(d, t, asn1::SEQUENCE);
    if !ok || fs.len != 4 || fs[1].tag != asn1::OCTET_STRING || fs[2].tag != asn1::OCTET_STRING ||
       fs[3].tag != asn1::INTEGER || !asn1::int_minimal(d, fs[3]) {
        return id, false;
    }
    id.hash = ocsp_hash_of(d, fs[0]);
    let n = d[fs[1].off..fs[1].end];
    let k = d[fs[2].off..fs[2].end];
    let s = d[fs[3].off..fs[3].end];
    if id.hash == 0 || n.len > 64 || k.len > 64 || s.len > 64 { return id, false; }
    id.name_hash.append(n);
    id.key_hash.append(k);
    id.serial.append(s);
    return id, true;
}

// --- Requests ---------------------------------------------------------------------

// CreateRequest: an unsigned request for c's status, with no extensions.
fn ocsp_create_request(c: const Cert&, issuer: const Cert&, h: i64 = 160) -> u8[>..] {
    let id = ocsp_cert_id(c, issuer, h);
    var cid: u8[>..] = [];
    ocsp_put_cert_id(cid, id);
    var req: u8[>..] = [];
    asn1::put(req, asn1::SEQUENCE, cid);
    var list: u8[>..] = [];
    asn1::put(list, asn1::SEQUENCE, req);
    var tbs: u8[>..] = [];
    asn1::put(tbs, asn1::SEQUENCE, list);
    var out: u8[>..] = [];
    asn1::put(out, asn1::SEQUENCE, tbs);
    return out;
}

// ParseRequest: the first certificate a request asks about; false if it
// is malformed or asks about none.
fn ocsp_parse_request(der: const u8[:]) -> OcspCertId, bool {
    var none = OcspCertId { hash: 0, name_hash: [], key_hash: [], serial: [] };
    let top, ok = asn1::parse(der);
    let parts, okp = asn1::children_of(der, top, asn1::SEQUENCE);
    if !ok || !okp || parts.len < 1 || parts.len > 2 { return none, false; }
    if parts.len == 2 && parts[1].tag != asn1::ctx(0, true) { return none, false; }
    let fs, okt = asn1::children_of(der, parts[0], asn1::SEQUENCE);
    if !okt { return none, false; }
    // [0] version, [1] requestorName, requestList, [2] extensions.
    var i = 0;
    if i < fs.len && fs[i].tag == asn1::ctx(0, true) {
        let v, okv = asn1::explicit(der, fs[i]);
        let n, okn = asn1::read_i64(der, v);
        if !okv || !okn || n != 0 { return none, false; }
        i++;
    }
    if i < fs.len && fs[i].tag == asn1::ctx(1, true) { i++; }
    if i >= fs.len { return none, false; }
    let reqs, okr = asn1::children_of(der, fs[i], asn1::SEQUENCE);
    if !okr || reqs.len == 0 { return none, false; }
    i++;
    if i < fs.len && fs[i].tag == asn1::ctx(2, true) { i++; }
    if i != fs.len { return none, false; }
    let rf, okf = asn1::children_of(der, reqs[0], asn1::SEQUENCE);
    if !okf || rf.len < 1 || rf.len > 2 { return none, false; }
    return ocsp_read_cert_id(der, rf[0]);
}

// --- Responses --------------------------------------------------------------------

fn ocsp_empty_response() -> OcspResponse {
    OcspResponse {
        response_status: -1, status: OCSP_UNKNOWN, id: OcspCertId { hash: 0, name_hash: [], key_hash: [], serial: [] },
        produced_at: 0, this_update: 0, next_update: -1, revoked_at: -1, reason: -1,
        tbs: no_tlv(), sig_alg: SIG_UNKNOWN, sig_hash: 0, pss_salt: 0, sig: no_tlv(),
        responder_name: no_tlv(), responder_key_hash: no_tlv(), has_cert: false, cert: no_tlv(), der: [],
    }
}

fn ocsp_generalized_time(d: const u8[:], t: asn1::Tlv) -> i64, bool {
    if t.tag != asn1::GENERALIZED_TIME { return 0, false; }
    return asn1::read_time(d, t);
}

// One SingleResponse into r; false if malformed.
fn ocsp_read_single(r: OcspResponse&, d: const u8[:], t: asn1::Tlv) -> bool {
    let fs, ok = asn1::children_of(d, t, asn1::SEQUENCE);
    if !ok || fs.len < 3 { return false; }
    let id, okid = ocsp_read_cert_id(d, fs[0]);
    if !okid { return false; }
    r.id = id;
    let st = fs[1];
    r.revoked_at = -1;
    r.reason = -1;
    if st.tag == asn1::ctx(0, false) && asn1::content_len(st) == 0 { r.status = OCSP_GOOD; }
    else if st.tag == asn1::ctx(2, false) && asn1::content_len(st) == 0 { r.status = OCSP_UNKNOWN; }
    else if st.tag == asn1::ctx(1, true) {
        r.status = OCSP_REVOKED;
        let ri, okri = asn1::children(d, st);
        if !okri || ri.len < 1 || ri.len > 2 { return false; }
        let at, okat = ocsp_generalized_time(d, ri[0]);
        if !okat { return false; }
        r.revoked_at = at;
        if ri.len == 2 {
            if ri[1].tag != asn1::ctx(0, true) { return false; }
            let e, oke = asn1::explicit(d, ri[1]);
            let reason, okr = asn1::read_i64(d, e, asn1::ENUMERATED);
            if !oke || !okr || reason < 0 || reason > 10 || reason == 7 { return false; }
            r.reason = reason;
        }
    } else { return false; }
    let tu, oktu = ocsp_generalized_time(d, fs[2]);
    if !oktu { return false; }
    r.this_update = tu;
    r.next_update = -1;
    var i = 3;
    if i < fs.len && fs[i].tag == asn1::ctx(0, true) {
        let e, oke = asn1::explicit(d, fs[i]);
        let nu, oknu = ocsp_generalized_time(d, e);
        if !oke || !oknu { return false; }
        r.next_update = nu;
        i++;
    }
    if i < fs.len && fs[i].tag == asn1::ctx(1, true) { i++; }
    return i == fs.len;
}

// ParseResponse: the response's structure, and its answer for the
// certificate with the serial number (INTEGER content) given, or with no
// serial its only answer. No signature or time is checked here (see
// ocsp_check_response). OK and the response, or ERR_MALFORMED; an
// unsuccessful status parses with OK and response_status set.
fn ocsp_parse_response(der: const u8[:], serial: const u8[:] = "") -> OcspResponse, i64 {
    var r = ocsp_empty_response();
    r.der.append(der);
    let d = r.der[..];
    let top, ok = asn1::parse(d);
    let parts, okp = asn1::children_of(d, top, asn1::SEQUENCE);
    if !ok || !okp || parts.len < 1 || parts.len > 2 { return r, ERR_MALFORMED; }
    let rs, okrs = asn1::read_i64(d, parts[0], asn1::ENUMERATED);
    if !okrs || rs < 0 || rs > 6 || rs == 4 { return r, ERR_MALFORMED; }
    r.response_status = rs;
    if rs != OCSP_SUCCESS { return r, if parts.len == 1 { OK } else { ERR_MALFORMED }; }
    if parts.len != 2 || parts[1].tag != asn1::ctx(0, true) { return r, ERR_MALFORMED; }
    let rb, okrb = asn1::explicit(d, parts[1]);
    let rbf, okrbf = asn1::children_of(d, rb, asn1::SEQUENCE);
    if !okrb || !okrbf || rbf.len != 2 || !asn1::oid_is(d, rbf[0], OID_OCSP_BASIC) || rbf[1].tag != asn1::OCTET_STRING {
        return r, ERR_MALFORMED;
    }
    // BasicOCSPResponse, inside the OCTET STRING.
    let basic, okb = asn1::read(d, rbf[1].off, rbf[1].end);
    let bf, okbf = asn1::children_of(d, basic, asn1::SEQUENCE);
    if !okb || basic.end != rbf[1].end || !okbf || bf.len < 3 || bf.len > 4 || bf[2].tag != asn1::BIT_STRING {
        return r, ERR_MALFORMED;
    }
    r.tbs = bf[0];
    let alg, h, salt = sig_alg_of(d, bf[1]);
    r.sig_alg = alg;
    r.sig_hash = h;
    r.pss_salt = salt;
    r.sig = bf[2];
    if bf.len == 4 {
        if bf[3].tag != asn1::ctx(0, true) { return r, ERR_MALFORMED; }
        let cs, okcs = asn1::explicit(d, bf[3]);
        let certs, okc = asn1::children_of(d, cs, asn1::SEQUENCE);
        if !okcs || !okc { return r, ERR_MALFORMED; }
        if certs.len > 0 { r.has_cert = true; r.cert = certs[0]; }
    }
    // ResponseData: [0] version, responderID, producedAt, responses, [1] extensions.
    let fs, okf = asn1::children_of(d, bf[0], asn1::SEQUENCE);
    if !okf { return r, ERR_MALFORMED; }
    var i = 0;
    if i < fs.len && fs[i].tag == asn1::ctx(0, true) {
        let v, okv = asn1::explicit(d, fs[i]);
        let n, okn = asn1::read_i64(d, v);
        if !okv || !okn || n != 0 { return r, ERR_MALFORMED; }
        i++;
    }
    if i + 2 >= fs.len { return r, ERR_MALFORMED; }
    let rid, okrid = asn1::explicit(d, fs[i]);
    if !okrid { return r, ERR_MALFORMED; }
    if fs[i].tag == asn1::ctx(1, true) && rid.tag == asn1::SEQUENCE { r.responder_name = rid; }
    else if fs[i].tag == asn1::ctx(2, true) && rid.tag == asn1::OCTET_STRING { r.responder_key_hash = rid; }
    else { return r, ERR_MALFORMED; }
    let pa, okpa = ocsp_generalized_time(d, fs[i + 1]);
    if !okpa { return r, ERR_MALFORMED; }
    r.produced_at = pa;
    let singles, oks = asn1::children_of(d, fs[i + 2], asn1::SEQUENCE);
    if !oks || singles.len == 0 { return r, ERR_MALFORMED; }
    i += 3;
    if i < fs.len && fs[i].tag == asn1::ctx(1, true) { i++; }
    if i != fs.len { return r, ERR_MALFORMED; }
    if serial.len == 0 && singles.len != 1 { return r, ERR_MALFORMED; }
    for s in singles {
        if !ocsp_read_single(r, d, s) { return r, ERR_MALFORMED; }
        if serial.len == 0 || r.id.serial == serial { return r, OK; }
    }
    return r, ERR_REVOCATION_UNKNOWN;                       // no answer for that certificate
}

// The responder certificate a response carries, parsed.
fn ocsp_responder_cert(r: const OcspResponse&) -> Cert, i64 {
    if !r.has_cert { return empty_cert(), ERR_MALFORMED; }
    return parse(r.der[r.cert.start..r.cert.end]);
}

fn ocsp_signed_by(r: const OcspResponse&, key_cert: const Cert&) -> i64 {
    let d = r.der[..];
    let sig, ok = key_bytes(d, r.sig);
    if !ok { return ERR_MALFORMED; }
    if r.sig_alg == SIG_UNKNOWN { return ERR_UNSUPPORTED_ALGORITHM; }
    return verify_with(key_cert, r.sig_alg, r.sig_hash, r.pss_salt, d[r.tbs.start..r.tbs.end], sig);
}

// Whether a response's ResponderID names certificate c: its subject
// (byName), or the SHA-1 of its subjectPublicKey (byKey), RFC 6960
// §4.2.1.
fn ocsp_names(r: const OcspResponse&, c: const Cert&) -> bool {
    let d = r.der[..];
    if r.responder_name.end > r.responder_name.start {
        return d[r.responder_name.start..r.responder_name.end] == c.der[c.subject.start..c.subject.end];
    }
    if r.responder_key_hash.end > r.responder_key_hash.start {
        let kb, ok = key_bytes(c.der, c.key);
        return ok && bignum::hash_bits(160, kb)[..] == d[r.responder_key_hash.off..r.responder_key_hash.end];
    }
    return false;
}

// Whether a response vouches for c, issued by issuer, at `now` (0: now):
// a successful response, its CertID naming c and issuer, signed by the
// issuer or by a responder certificate the issuer signed for OCSP
// signing, current (thisUpdate passed, nextUpdate if any not). A
// delegated responder's certificate must itself be valid at `now`, with
// no unknown critical extension, allow digitalSignature if it has
// keyUsage, and be the one the ResponderID names (RFC 6960 §4.2.2.2).
// Then OK for good, ERR_REVOKED, or ERR_REVOCATION_UNKNOWN for unknown.
fn ocsp_check_response(r: const OcspResponse&, c: const Cert&, issuer: const Cert&, now: i64 = 0) -> i64 {
    if r.response_status != OCSP_SUCCESS { return ERR_REVOCATION_UNKNOWN; }
    let want = ocsp_cert_id(c, issuer, r.id.hash);
    if want.name_hash != r.id.name_hash || want.key_hash != r.id.key_hash || want.serial != r.id.serial {
        return ERR_UNKNOWN_ISSUER;
    }
    let t = if now == 0 { time() as i64 } else { now };
    let direct = ocsp_signed_by(r, issuer);
    if direct != OK {
        let rc, e = ocsp_responder_cert(r);
        if e != OK { return direct; }
        if !issued_by(rc, issuer) || check_signature(rc, issuer) != OK { return ERR_UNKNOWN_ISSUER; }
        if !rc.has_ext_key_usage || rc.ext_key_usage & EKU_OCSP_SIGNING == 0 { return ERR_EXTENDED_KEY_USAGE; }
        let ce = check_common(rc, t);
        if ce != OK { return ce; }
        if rc.has_key_usage && rc.key_usage & KU_DIGITAL_SIGNATURE == 0 { return ERR_KEY_USAGE; }
        if !ocsp_names(r, rc) { return ERR_UNKNOWN_ISSUER; }
        let e2 = ocsp_signed_by(r, rc);
        if e2 != OK { return e2; }
    }
    if t < r.this_update { return ERR_NOT_YET_VALID; }
    if r.next_update >= 0 && t >= r.next_update { return ERR_EXPIRED; }
    if r.status == OCSP_REVOKED { return ERR_REVOKED; }
    if r.status == OCSP_UNKNOWN { return ERR_REVOCATION_UNKNOWN; }
    return OK;
}

// What a response says, for ocsp_create_response: status, the
// certificate's serial (INTEGER content), times (next_update -1: none),
// the revocation time and reason (-1: none), the CertID hash, and the
// signature algorithm and hash (0: the key's default).
struct OcspTemplate {
    status: i64, serial: u8[..64],
    this_update: i64, next_update: i64, revoked_at: i64, reason: i64,
    hash: i64, sig_alg: i64, sig_hash: i64,
}

fn ocsp_template(status: i64, serial: const u8[:], this_update: i64) -> OcspTemplate {
    var t = OcspTemplate { status: status, serial: [], this_update: this_update, next_update: -1, revoked_at: -1,
                           reason: -1, hash: 160, sig_alg: 0, sig_hash: 0 };
    t.serial.append(serial);
    return t;
}

fn ocsp_put_gtime(out: u8[>..]&, unix: i64) {
    let days = if unix >= 0 { unix / 86400 } else { (unix - 86399) / 86400 };
    let secs = unix - days * 86400;
    let y, m, dd = asn1::civil_from_days(days);
    var s: u8[>..] = [];
    format_int(s, y, 10, 4, '0');
    format_int(s, m, 10, 2, '0');
    format_int(s, dd, 10, 2, '0');
    format_int(s, secs / 3600, 10, 2, '0');
    format_int(s, secs / 60 % 60, 10, 2, '0');
    format_int(s, secs % 60, 10, 2, '0');
    s.push('Z');
    asn1::put(out, asn1::GENERALIZED_TIME, s);
}

// CreateResponse: a successful basic response about one certificate of
// issuer, signed with key (the issuer's, or a delegated responder's whose
// certificate is responder; its DER goes in when include_cert), named by
// the responder's subject, produced at produced_at. As Go: no nonce, a
// reason of 0 (unspecified) left out.
fn ocsp_create_response(issuer: const Cert&, responder: const Cert&, key: const PrivateKey&, t: const OcspTemplate&,
                        produced_at: i64, include_cert: bool) -> u8[>..], i64 {
    var none: u8[>..] = [];
    var alg = t.sig_alg;
    var h = t.sig_hash;
    if alg == 0 {
        let a, hh = default_sig(key.kind);
        alg = a;
        h = hh;
    }
    if !sig_fits_key(key.kind, alg, h) { return none, ERR_UNSUPPORTED_ALGORITHM; }
    var id = OcspCertId { hash: t.hash, name_hash: [], key_hash: [], serial: [] };
    let d = issuer.der[..];
    id.name_hash.append(bignum::hash_bits(t.hash, d[issuer.subject.start..issuer.subject.end]));
    let kb, okk = key_bytes(d, issuer.key);
    if !okk { return none, ERR_MALFORMED; }
    id.key_hash.append(bignum::hash_bits(t.hash, kb));
    id.serial.append(t.serial);
    var single: u8[>..] = [];
    ocsp_put_cert_id(single, id);
    if t.status == OCSP_GOOD { asn1::put_header(single, asn1::ctx(0, false), 0); }
    else if t.status == OCSP_UNKNOWN { asn1::put_header(single, asn1::ctx(2, false), 0); }
    else {
        var ri: u8[>..] = [];
        ocsp_put_gtime(ri, t.revoked_at);
        if t.reason > 0 {
            var e: u8[>..] = [];
            asn1::put_i64(e, t.reason, asn1::ENUMERATED);
            asn1::put(ri, asn1::ctx(0, true), e);
        }
        asn1::put(single, asn1::ctx(1, true), ri);
    }
    ocsp_put_gtime(single, t.this_update);
    if t.next_update >= 0 {
        var nu: u8[>..] = [];
        ocsp_put_gtime(nu, t.next_update);
        asn1::put(single, asn1::ctx(0, true), nu);
    }
    var singles: u8[>..] = [];
    asn1::put(singles, asn1::SEQUENCE, single);
    var data: u8[>..] = [];
    asn1::put(data, asn1::ctx(1, true), responder.der[responder.subject.start..responder.subject.end]);
    ocsp_put_gtime(data, produced_at);
    asn1::put(data, asn1::SEQUENCE, singles);
    var tbs: u8[>..] = [];
    asn1::put(tbs, asn1::SEQUENCE, data);
    var basic: u8[>..] = [];
    basic.append(tbs);
    basic.append(sig_alg_id(alg, h));
    let sig, oks = sign(key, alg, h, tbs);
    if !oks { return none, ERR_SIGNING; }
    asn1::put_bits(basic, sig);
    if include_cert {
        var certs: u8[>..] = [];
        asn1::put(certs, asn1::SEQUENCE, responder.der);
        asn1::put(basic, asn1::ctx(0, true), certs);
    }
    var basic_der: u8[>..] = [];
    asn1::put(basic_der, asn1::SEQUENCE, basic);
    var rbytes: u8[>..] = [];
    asn1::put_oid(rbytes, OID_OCSP_BASIC);
    asn1::put_octets(rbytes, basic_der);
    var rb: u8[>..] = [];
    asn1::put(rb, asn1::SEQUENCE, rbytes);
    var body: u8[>..] = [];
    asn1::put_i64(body, OCSP_SUCCESS, asn1::ENUMERATED);
    asn1::put(body, asn1::ctx(0, true), rb);
    var out: u8[>..] = [];
    asn1::put(out, asn1::SEQUENCE, body);
    return out, OK;
}

// The unsuccessful responses: a status alone.
fn ocsp_error_response(status: i64) -> u8[>..] {
    assert(status > 0 && status <= 6 && status != 4);
    var body: u8[>..] = [];
    asn1::put_i64(body, status, asn1::ENUMERATED);
    var out: u8[>..] = [];
    asn1::put(out, asn1::SEQUENCE, body);
    return out;
}
