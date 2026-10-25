// x509.crl: certificate revocation lists (RFC 5280 §5). Parsing, the
// checks that make a CRL usable for a certificate (signed by the
// certificate's issuer, whose key usage allows cRLSign; current; in scope
// by its issuingDistributionPoint), and looking a serial number up.
//
// Delta CRLs, indirect CRLs and CRLs split by reason are not supported:
// such a CRL parses with `unsupported` set and is never used, so a
// certificate it would cover gets ERR_REVOCATION_UNKNOWN rather than a
// wrong answer.

namespace x509;

import std;
import x509;
import asn1;

// Revocation reasons (CRLReason).
let REASON_UNSPECIFIED: i64 = 0;
let REASON_KEY_COMPROMISE: i64 = 1;
let REASON_CA_COMPROMISE: i64 = 2;
let REASON_AFFILIATION_CHANGED: i64 = 3;
let REASON_SUPERSEDED: i64 = 4;
let REASON_CESSATION_OF_OPERATION: i64 = 5;
let REASON_CERTIFICATE_HOLD: i64 = 6;
let REASON_REMOVE_FROM_CRL: i64 = 8;
let REASON_PRIVILEGE_WITHDRAWN: i64 = 9;
let REASON_AA_COMPROMISE: i64 = 10;

struct Crl {
    version: i64,
    tbs: asn1::Tlv,
    sig_alg: i64, sig_hash: i64, pss_salt: i64,
    sig: asn1::Tlv,
    issuer: asn1::Tlv,
    this_update: i64, next_update: i64,          // next_update -1: absent
    has_revoked: bool, revoked: asn1::Tlv,       // SEQUENCE OF entries
    crl_number: i64,                             // -1: absent or too big
    only_user: bool, only_ca: bool,              // issuingDistributionPoint scope
    unsupported: bool,                           // delta, indirect, by reason, unknown critical
    der: u8[>..],
}

fn empty_crl() -> Crl {
    Crl {
        version: 1, tbs: no_tlv(), sig_alg: SIG_UNKNOWN, sig_hash: 0, pss_salt: 0, sig: no_tlv(),
        issuer: no_tlv(), this_update: 0, next_update: -1, has_revoked: false, revoked: no_tlv(),
        crl_number: -1, only_user: false, only_ca: false, unsupported: false, der: [],
    }
}

// IssuingDistributionPoint: only the two scope flags are understood; a
// reason subset or an indirect CRL makes it unsupported. (Its
// distributionPoint names which CRL this is, which matters only for
// partitioned CRLs; a CRL that has one is still matched to certificates by
// issuer alone.)
fn parse_idp(c: Crl&, d: const u8[:], t: asn1::Tlv) -> bool {
    let fs, ok = asn1::children_of(d, t, asn1::SEQUENCE);
    if !ok { return false; }
    var last: i64 = -1;
    for f in fs {
        if f.cls != asn1::CLASS_CONTEXT || f.number <= last { return false; }
        last = f.number;
        if f.number == 1 || f.number == 2 || f.number == 4 || f.number == 5 {
            // BOOLEAN DEFAULT FALSE, IMPLICIT: present means TRUE in DER.
            if f.constructed || f.end - f.off != 1 || d[f.off] != 0xff { return false; }
            if f.number == 1 { c.only_user = true; }
            if f.number == 2 { c.only_ca = true; }
            if f.number == 4 { c.unsupported = true; }   // indirectCRL
            if f.number == 5 { c.unsupported = true; }   // onlyContainsAttributeCerts
        } else if f.number == 3 {
            c.unsupported = true;                        // onlySomeReasons
        } else if f.number != 0 {
            return false;
        }
    }
    return true;
}

fn parse_crl(der: const u8[:]) -> Crl, i64 {
    var c = empty_crl();
    c.der.append(der);
    let d = c.der[..];
    let top, okt = asn1::parse(d);
    let parts, okp = asn1::children_of(d, top, asn1::SEQUENCE);
    if !okt || !okp || parts.len != 3 || parts[2].tag != asn1::BIT_STRING { return c, ERR_MALFORMED; }
    c.tbs = parts[0];
    c.sig = parts[2];
    let f, okf = asn1::children_of(d, parts[0], asn1::SEQUENCE);
    if !okf || f.len < 3 { return c, ERR_MALFORMED; }
    var i = 0;
    if f[0].tag == asn1::INTEGER {
        let v, okv = asn1::read_i64(d, f[0]);
        if !okv || v != 1 { return c, ERR_MALFORMED; }   // only v2 is written out
        c.version = 2;
        i = 1;
    }
    if f.len < i + 3 { return c, ERR_MALFORMED; }
    if d[f[i].start..f[i].end] != d[parts[1].start..parts[1].end] { return c, ERR_MALFORMED; }
    let alg, h, salt = sig_alg_of(d, parts[1]);
    c.sig_alg = alg;
    c.sig_hash = h;
    c.pss_salt = salt;
    c.issuer = f[i + 1];
    let tu, oktu = asn1::read_time(d, f[i + 2]);
    if !oktu { return c, ERR_MALFORMED; }
    c.this_update = tu;
    var j = i + 3;
    if j < f.len && (f[j].tag == asn1::UTC_TIME || f[j].tag == asn1::GENERALIZED_TIME) {
        let nu, oknu = asn1::read_time(d, f[j]);
        if !oknu { return c, ERR_MALFORMED; }
        c.next_update = nu;
        j++;
    }
    if j < f.len && f[j].tag == asn1::SEQUENCE {
        let es, oke = asn1::children(d, f[j]);
        if !oke || es.len == 0 { return c, ERR_MALFORMED; }
        for e in es {
            let ef, okef = asn1::children_of(d, e, asn1::SEQUENCE);
            if !okef || ef.len < 2 || ef.len > 3 { return c, ERR_MALFORMED; }
            let serial, oks = asn1::read_int_bytes(d, ef[0]);
            let rd, okrd = asn1::read_time(d, ef[1]);
            if !oks || !okrd { return c, ERR_MALFORMED; }
            if ef.len == 3 {
                if c.version != 2 { return c, ERR_MALFORMED; }
                let exts, okx = asn1::children_of(d, ef[2], asn1::SEQUENCE);
                if !okx || exts.len == 0 { return c, ERR_MALFORMED; }
                for x in exts {
                    let xf, okxf = asn1::children_of(d, x, asn1::SEQUENCE);
                    if !okxf || xf.len < 2 || xf.len > 3 || xf[0].tag != asn1::OID { return c, ERR_MALFORMED; }
                    let critical = xf.len == 3;
                    // reasonCode and invalidityDate are informative;
                    // certificateIssuer belongs to indirect CRLs.
                    if asn1::oid_is(d, xf[0], "2.5.29.29") { c.unsupported = true; }
                    else if critical && !asn1::oid_is(d, xf[0], "2.5.29.21") && !asn1::oid_is(d, xf[0], "2.5.29.24") {
                        c.unsupported = true;
                    }
                }
            }
        }
        c.has_revoked = true;
        c.revoked = f[j];
        j++;
    }
    if j < f.len {
        if f[j].tag != asn1::ctx(0, true) || c.version != 2 || j + 1 != f.len { return c, ERR_MALFORMED; }
        let wrap, okw = asn1::explicit(d, f[j]);
        let exts, okx = asn1::children_of(d, wrap, asn1::SEQUENCE);
        if !okw || !okx || exts.len == 0 { return c, ERR_MALFORMED; }
        for x in exts {
            let xf, okxf = asn1::children_of(d, x, asn1::SEQUENCE);
            if !okxf || xf.len < 2 || xf.len > 3 || xf[0].tag != asn1::OID { return c, ERR_MALFORMED; }
            var critical = false;
            if xf.len == 3 {
                let v, okb = asn1::read_bool(d, xf[1]);
                if !okb || !v { return c, ERR_MALFORMED; }
                critical = true;
            }
            let val = xf[xf.len - 1];
            if val.tag != asn1::OCTET_STRING { return c, ERR_MALFORMED; }
            let inner, oki = asn1::read(d, val.off, val.end);
            if asn1::oid_is(d, xf[0], "2.5.29.20") {
                let num, okn = asn1::read_int_bytes(d, inner);
                if !oki || !okn || num[0] >= 0x80 { return c, ERR_MALFORMED; }
                let v, okv = asn1::read_i64(d, inner);
                if okv { c.crl_number = v; }
            } else if asn1::oid_is(d, xf[0], "2.5.29.28") {
                if !oki || inner.end != val.end || !parse_idp(c, d, inner) { return c, ERR_MALFORMED; }
            } else if asn1::oid_is(d, xf[0], "2.5.29.27") {
                c.unsupported = true;                    // deltaCRLIndicator
            } else if asn1::oid_is(d, xf[0], "2.5.29.35") {
                // authorityKeyIdentifier: informative here.
            } else if critical {
                c.unsupported = true;
            }
        }
    }
    let sigbits, okb = key_bytes(d, c.sig);
    if !okb { return c, ERR_MALFORMED; }
    return c, OK;
}

// Whether the CRL covers c: the same issuer and, when it is scoped, the
// right kind of certificate.
fn crl_covers(crl: const Crl&, c: const Cert&) -> bool {
    if crl.der[crl.issuer.start..crl.issuer.end] != c.der[c.issuer.start..c.issuer.end] { return false; }
    if crl.only_user && c.is_ca { return false; }
    if crl.only_ca && !c.is_ca { return false; }
    return true;
}

// Whether a CRL can be relied on at `now`, signed by `issuer`: OK, or why not.
fn check_crl(crl: const Crl&, issuer: const Cert&, now: i64) -> i64 {
    if crl.unsupported { return ERR_UNKNOWN_CRITICAL_EXTENSION; }
    if crl.der[crl.issuer.start..crl.issuer.end] != issuer.der[issuer.subject.start..issuer.subject.end] {
        return ERR_UNKNOWN_ISSUER;
    }
    if issuer.has_key_usage && issuer.key_usage & KU_CRL_SIGN == 0 { return ERR_KEY_USAGE; }
    if now < crl.this_update { return ERR_NOT_YET_VALID; }
    if crl.next_update >= 0 && now > crl.next_update { return ERR_EXPIRED; }
    if crl.sig_alg == SIG_UNKNOWN { return ERR_UNSUPPORTED_ALGORITHM; }
    let d = crl.der[..];
    let sig, ok = key_bytes(d, crl.sig);
    if !ok { return ERR_MALFORMED; }
    return verify_with(issuer, crl.sig_alg, crl.sig_hash, crl.pss_salt, d[crl.tbs.start..crl.tbs.end], sig);
}

// Whether the CRL lists c's serial number, and the reason given.
// removeFromCRL entries (which belong in delta CRLs) do not count.
fn crl_lookup(crl: const Crl&, c: const Cert&) -> bool, i64 {
    if !crl.has_revoked { return false, -1; }
    let d = crl.der[..];
    let serial = c.der[c.serial.off..c.serial.end];
    let es, ok = asn1::children(d, crl.revoked);
    for e in es {
        let ef, okef = asn1::children(d, e);
        if d[ef[0].off..ef[0].end] != serial { continue; }
        var reason = REASON_UNSPECIFIED;
        if ef.len == 3 {
            let exts, okx = asn1::children(d, ef[2]);
            for x in exts {
                let xf, okxf = asn1::children(d, x);
                if asn1::oid_is(d, xf[0], "2.5.29.21") {
                    let val = xf[xf.len - 1];
                    let inner, oki = asn1::read(d, val.off, val.end);
                    let r, okr = asn1::read_i64(d, inner, asn1::ENUMERATED);
                    if oki && okr { reason = r; }
                }
            }
        }
        if reason == REASON_REMOVE_FROM_CRL { return false, reason; }
        return true, reason;
    }
    return false, -1;
}

// The revocation status of c, issued by `issuer`, from the CRLs given
// (DER, concatenated): OK when a usable CRL covers it and does not list
// it, ERR_REVOKED when one lists it, ERR_REVOCATION_UNKNOWN when no
// usable CRL covers it.
fn revocation_status(c: const Cert&, issuer: const Cert&, crls: const u8[:], now: i64) -> i64 {
    var status = ERR_REVOCATION_UNKNOWN;
    var off = 0;
    while off < crls.len {
        let t, ok = asn1::read(crls, off, crls.len);
        if !ok { break; }
        off = t.end;
        let crl, e = parse_crl(crls[t.start..t.end]);
        if e != OK || !crl_covers(crl, c) || check_crl(crl, issuer, now) != OK { continue; }
        let revoked, reason = crl_lookup(crl, c);
        if revoked { return ERR_REVOKED; }
        status = OK;
    }
    return status;
}
