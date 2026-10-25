// x509.constraints: name constraints (RFC 5280 §4.2.1.10). A CA's
// permitted and excluded subtrees restrict the names of every certificate
// below it: the SAN's dNSName, rfc822Name, URI host, iPAddress and
// directoryName entries, and the subject (with any emailAddress in it).
// A name of a form that has permitted subtrees must fall within one; no
// name may fall within an excluded one. Constraint forms this package
// cannot evaluate (otherName, x400Address, ediPartyName, registeredID)
// fail a certificate only if it has names of that form.

namespace x509;

import std;
import x509;
import asn1;

// GeneralName tags.
let GN_OTHER: u32 = 0;
let GN_EMAIL: u32 = 1;
let GN_DNS: u32 = 2;
let GN_DIRECTORY: u32 = 4;
let GN_URI: u32 = 6;
let GN_IP: u32 = 7;

fn ends_with_nocase(s: const u8[:], suffix: const u8[:]) -> bool {
    s.len >= suffix.len && eq_nocase(s[s.len - suffix.len..], suffix)
}

fn strip_dot(s: const u8[:]) -> const u8[:] {
    if s.len > 0 && s[s.len - 1] == '.' { s[..s.len - 1] } else { s }
}

// A host within a DNS subtree: "example.com" covers itself and every name
// under it, ".example.com" only the names under it, "" everything.
fn dns_within(name0: const u8[:], base0: const u8[:]) -> bool {
    let name = strip_dot(name0);
    let base = strip_dot(base0);
    if base.len == 0 { return true; }
    if base[0] == '.' { return name.len > base.len && ends_with_nocase(name, base); }
    if name.len == base.len { return eq_nocase(name, base); }
    return name.len > base.len && ends_with_nocase(name, base) && name[name.len - base.len - 1] == '.';
}

// A mailbox within an rfc822Name subtree: "user@host" exactly, "host"
// for that host, ".host" for hosts under it.
fn email_within(mail: const u8[:], base: const u8[:]) -> bool {
    var at = -1;
    for i in mail.len { if mail[i] == '@' { at = i; } }
    if at < 0 { return false; }
    let host = mail[at + 1..];
    var base_at = -1;
    for i in base.len { if base[i] == '@' { base_at = i; } }
    if base_at >= 0 {
        return mail[..at] == base[..base_at] && eq_nocase(host, base[base_at + 1..]);
    }
    if base.len > 0 && base[0] == '.' { return dns_within(host, base); }
    return eq_nocase(host, base);
}

// The host of a URI: after "scheme://" and any userinfo, before the port
// or path. Empty when there is none.
fn uri_host(uri: const u8[:]) -> const u8[:] {
    var i = 0;
    while i < uri.len && uri[i] != ':' { i++; }
    if i + 2 >= uri.len || uri[i + 1] != '/' || uri[i + 2] != '/' { return uri[..0]; }
    var start = i + 3;
    var end = start;
    while end < uri.len && uri[end] != '/' && uri[end] != '?' && uri[end] != '#' { end++; }
    for k in start..end { if uri[k] == '@' { start = k + 1; } }
    var colon = end;
    for k in start..end { if uri[k] == ':' { colon = k; } }
    return uri[start..colon];
}

fn uri_within(uri: const u8[:], base: const u8[:]) -> bool {
    let host = uri_host(uri);
    if host.len == 0 { return false; }
    if base.len > 0 && base[0] == '.' { return dns_within(host, base); }
    return eq_nocase(host, base);
}

// An address within an iPAddress subtree: address and mask, same family.
fn ip_within(ip: const u8[:], base: const u8[:]) -> bool {
    if base.len != 2 * ip.len { return false; }
    for i in ip.len {
        let m = base[ip.len + i];
        if ip[i] & m != base[i] & m { return false; }
    }
    return true;
}

// A string as compared in names: decoded, folded to lower case (ASCII),
// with runs of spaces made one and none at the ends (RFC 5280 §7.1's
// matching, short of full Unicode case folding).
fn fold(der: const u8[:], t: asn1::Tlv) -> u8[>..] {
    var out: u8[>..] = [];
    let s, ok = asn1::read_string(der, t);
    if !ok { out.append(der[t.start..t.end]); return out; }
    var space = false;
    for ch in s {
        if ch == ' ' { space = out.len > 0; continue; }
        if space { out.push(' '); space = false; }
        out.push(lower(ch));
    }
    return out;
}

// Whether two RDNs hold the same attributes with matching values.
fn rdn_equal(da: const u8[:], a: asn1::Tlv, db: const u8[:], b: asn1::Tlv) -> bool {
    let xa, oka = asn1::children_of(da, a, asn1::SET);
    let xb, okb = asn1::children_of(db, b, asn1::SET);
    if !oka || !okb || xa.len != xb.len { return false; }
    for p in xa {
        let pa, okp = asn1::children(da, p);
        if !okp || pa.len != 2 { return false; }
        var found = false;
        for q in xb {
            let pb, okq = asn1::children(db, q);
            if okq && pb.len == 2 && da[pa[0].start..pa[0].end] == db[pb[0].start..pb[0].end]
                && fold(da, pa[1]) == fold(db, pb[1]) {
                found = true;
            }
        }
        if !found { return false; }
    }
    return true;
}

// A Name within a directoryName subtree: the subtree's RDNs begin it.
fn dn_within(dn: const u8[:], name: asn1::Tlv, db: const u8[:], base: asn1::Tlv) -> bool {
    let rn, okn = asn1::children_of(dn, name, asn1::SEQUENCE);
    let rb, okb = asn1::children_of(db, base, asn1::SEQUENCE);
    if !okn || !okb || rb.len > rn.len { return false; }
    for i in rb.len { if !rdn_equal(dn, rn[i], db, rb[i]) { return false; } }
    return true;
}

// Whether one name of form `kind` (content at nd[t]) is within the
// subtree base (at cd[b]).
fn within(kind: u32, nd: const u8[:], t: asn1::Tlv, cd: const u8[:], b: asn1::Tlv) -> bool {
    if kind == GN_DIRECTORY {
        let inner, ok = asn1::explicit(cd, b);
        return ok && dn_within(nd, t, cd, inner);
    }
    let name = nd[t.off..t.end];
    let base = cd[b.off..b.end];
    if kind == GN_DNS { return dns_within(name, base); }
    if kind == GN_EMAIL { return email_within(name, base); }
    if kind == GN_URI { return uri_within(name, base); }
    if kind == GN_IP { return ip_within(name, base); }
    return false;
}

// Checks one name against a CA's constraints: OK, or ERR_NAME_CONSTRAINTS.
fn check_name(ca: const Cert&, kind: u32, nd: const u8[:], t: asn1::Tlv) -> i64 {
    let cd = ca.der[..];
    let parts, ok = asn1::children(cd, ca.name_constraints);
    var permitted_of_kind = false;
    var permitted = false;
    for part in parts {
        let subs, oks = asn1::children(cd, part);
        for s in subs {
            let base, okb = asn1::children(cd, s);
            let b = base[0];
            if b.number != kind { continue; }
            let hit = within(kind, nd, t, cd, b);
            if part.number == 1 && hit { return ERR_NAME_CONSTRAINTS; }
            if part.number == 0 {
                permitted_of_kind = true;
                if hit { permitted = true; }
            }
        }
    }
    if permitted_of_kind && !permitted { return ERR_NAME_CONSTRAINTS; }
    // A form the package cannot evaluate, constrained: refuse the name.
    if kind != GN_DNS && kind != GN_EMAIL && kind != GN_URI && kind != GN_IP && kind != GN_DIRECTORY {
        for part in parts {
            let subs, oks = asn1::children(cd, part);
            for s in subs {
                let base, okb = asn1::children(cd, s);
                if base[0].number == kind { return ERR_NAME_CONSTRAINTS; }
            }
        }
    }
    return OK;
}

// Checks every name of c against the constraints of ca.
fn check_name_constraints(ca: const Cert&, c: const Cert&) -> i64 {
    if !ca.has_name_constraints { return OK; }
    let d = c.der[..];
    // The subject, if not empty, as a directoryName; its emailAddress
    // attributes as rfc822Names.
    let rdns, okr = asn1::children(d, c.subject);
    if rdns.len > 0 {
        let e = check_name(ca, GN_DIRECTORY, d, c.subject);
        if e != OK { return e; }
        for rdn in rdns {
            let atvs, oka = asn1::children(d, rdn);
            for atv in atvs {
                let p, okp = asn1::children(d, atv);
                if okp && p.len == 2 && asn1::oid_is(d, p[0], "1.2.840.113549.1.9.1") {
                    let e2 = check_name(ca, GN_EMAIL, d, p[1]);
                    if e2 != OK { return e2; }
                }
            }
        }
    }
    if c.has_san {
        let ns, okn = asn1::children(d, c.san);
        for n in ns {
            if n.number == GN_DIRECTORY {
                let inner, oki = asn1::explicit(d, n);
                if !oki { return ERR_MALFORMED; }
                let e = check_name(ca, GN_DIRECTORY, d, inner);
                if e != OK { return e; }
            } else {
                let e = check_name(ca, n.number, d, n);
                if e != OK { return e; }
            }
        }
    }
    return OK;
}
