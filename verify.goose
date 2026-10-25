// x509.verify: certification path validation for TLS servers (RFC 5280
// §6, as a server's chain needs it): path building, then the checks that
// need the whole path (name constraints, policies, revocation).

namespace x509;

import std;
import x509;
import asn1;
import constraints;
import policy;
import crl;

// Checks that apply to any certificate on a path: dates and extensions.
fn check_common(c: const Cert&, now: i64) -> i64 {
    if c.unknown_critical { return ERR_UNKNOWN_CRITICAL_EXTENSION; }
    if now < c.not_before { return ERR_NOT_YET_VALID; }
    if now > c.not_after { return ERR_EXPIRED; }
    return OK;
}

// Checks on a certificate that issues the one below it, `below` CA
// certificates (not counting the leaf) further down the path.
fn check_issuer(c: const Cert&, now: i64, below: i64) -> i64 {
    let e = check_common(c, now);
    if e != OK { return e; }
    if !c.has_basic_constraints || !c.is_ca { return ERR_NOT_CA; }
    if c.path_len >= 0 && below > c.path_len { return ERR_PATH_LENGTH; }
    if c.has_key_usage && c.key_usage & KU_KEY_CERT_SIGN == 0 { return ERR_KEY_USAGE; }
    // A CA restricted by extended key usage must allow server
    // authentication (as Go, Chrome and Firefox require).
    if c.has_ext_key_usage && c.ext_key_usage & (EKU_SERVER_AUTH | EKU_ANY) == 0 { return ERR_EXTENDED_KEY_USAGE; }
    return OK;
}

// The certificate at `off` in a concatenation, and the offset after it.
fn cert_at(list: const u8[:], off: i64) -> Cert, i64 {
    let t, ok = asn1::read(list, off, list.len);
    if !ok { return empty_cert(), -1; }
    let c, e = parse(list[t.start..t.end]);
    if e != OK { return c, -1; }
    return c, t.end;
}

let MAX_DEPTH: i64 = 8;

// The checks that need the whole path, given top-down as `chain` (n
// certificates, the leaf last) under `root`: name constraints, policies,
// and revocation as the options ask.
fn check_path(root: const Cert&, chain: const u8[:], n: i64, crls: const u8[:], now: i64,
              opts: const Options&) -> i64 {
    // Name constraints: each CA's, the root's included, bind every
    // certificate below it, except self-issued intermediates.
    var off = 0;
    for i in -1..n - 1 {
        var ca = empty_cert();
        if i < 0 { ca = copy(root); } else { let c, next = cert_at(chain, off); ca = copy(c); off = next; }
        if !ca.has_name_constraints { continue; }
        var off2 = off;
        for j in i + 1..n {
            let below, next2 = cert_at(chain, off2);
            off2 = next2;
            if j < n - 1 && self_issued(below) { continue; }
            let e = check_name_constraints(ca, below);
            if e != OK { return e; }
        }
    }
    let pe = check_policies(chain, n, opts);
    if pe != OK { return pe; }
    if opts.crl_check != CRL_NONE {
        var issuer = copy(root);
        var off3 = 0;
        for i in n {
            let c, next = cert_at(chain, off3);
            off3 = next;
            if i == n - 1 || opts.crl_check == CRL_ALL {
                let re = revocation_status(c, issuer, crls, now);
                if re != OK { return re; }
            }
            issuer = copy(c);
        }
    }
    return OK;
}

// Validates a TLS server certificate with default options and no CRLs:
// see verify_chain_with.
fn verify_chain(leaf_der: const u8[:], intermediates: const u8[:], roots: const u8[:], now: i64,
                host: const u8[:]) -> i64 {
    let opts = options();
    return verify_chain_with(leaf_der, intermediates, roots, "", now, host, opts);
}

// Validates a TLS server certificate: a path from `leaf` through any of
// `intermediates` to one of `roots` (each DER certificates concatenated),
// every link signed by the next, all of them valid at `now` (seconds since
// 1970), the CAs allowed to issue, the leaf allowed for server
// authentication and valid for `host` (no check when host is empty), every
// name within the name constraints above it, an acceptable policy when the
// path or the options require one, and, when the options ask, a usable
// CRL among `crls` (DER CRLs concatenated) that does not list the
// certificates checked. The roots' own signatures and dates are not
// checked, only their keys and constraints, as trust anchors are. Returns
// OK or the error of the path that came closest.
fn verify_chain_with(leaf_der: const u8[:], intermediates: const u8[:], roots: const u8[:],
                     crls: const u8[:], now: i64, host: const u8[:], opts: const Options&) -> i64 {
    let leaf, e = parse(leaf_der);
    if e != OK { return e; }
    let le = check_common(leaf, now);
    if le != OK { return le; }
    if leaf.has_ext_key_usage && leaf.ext_key_usage & (EKU_SERVER_AUTH | EKU_ANY) == 0 { return ERR_EXTENDED_KEY_USAGE; }
    if leaf.has_key_usage && leaf.key_usage & (KU_DIGITAL_SIGNATURE | KU_KEY_ENCIPHERMENT | KU_KEY_AGREEMENT) == 0 {
        return ERR_KEY_USAGE;
    }
    if host.len > 0 && !matches_host(leaf, host) { return ERR_HOSTNAME; }
    // The leaf itself trusted, as a pinned certificate.
    var r = 0;
    while r < roots.len {
        let t, okr = asn1::read(roots, r, roots.len);
        if !okr { break; }
        if roots[t.start..t.end] == leaf_der { return OK; }
        r = t.end;
    }
    // Depth-first search. path[i] is the offset in `intermediates` of the
    // i-th certificate above the leaf; tried[i] is where the search for
    // the next one up resumes.
    var path: i64[>..<] = [];
    var tried: i64[>..<] = [0];
    var best = ERR_UNKNOWN_ISSUER;
    loop {
        let depth = path.len;
        // The certificate at the top of the path so far.
        var top = empty_cert();
        if depth == 0 {
            top = copy(leaf);
        } else {
            let c, n = cert_at(intermediates, path[depth - 1]);
            top = copy(c);
        }
        // A root that issued it ends the search, if the whole path holds.
        var ro = 0;
        while ro < roots.len {
            let root, next = cert_at(roots, ro);
            if next < 0 { break; }
            ro = next;
            if !issued_by(top, root) { continue; }
            let ce = check_issuer(root, now, depth);
            // A root without basicConstraints is accepted if it is
            // self-issued (a v1 root); otherwise roots are held to the
            // same rules as any CA.
            let ok_root = ce == OK || (ce == ERR_NOT_CA && !root.has_basic_constraints && self_issued(root));
            if !ok_root { best = ce; continue; }
            let se = check_signature(top, root);
            if se != OK { best = se; continue; }
            var chain: u8[>..] = [];
            var k = depth;
            while k > 0 {
                k--;
                let t, okc = asn1::read(intermediates, path[k], intermediates.len);
                chain.append(intermediates[t.start..t.end]);
            }
            chain.append(leaf_der);
            let pe = check_path(root, chain, depth + 1, crls, now, opts);
            if pe == OK { return OK; }
            best = pe;
        }
        // Otherwise an intermediate that issued it, not already on the path.
        var found = false;
        if depth < MAX_DEPTH {
            var io = tried[depth];
            while io < intermediates.len {
                let cand, next = cert_at(intermediates, io);
                if next < 0 { return ERR_MALFORMED; }
                let here = io;
                io = next;
                var on_path = false;
                for p in path { if p == here { on_path = true; } }
                if on_path || !issued_by(top, cand) { continue; }
                let ce = check_issuer(cand, now, depth);
                if ce != OK { best = ce; continue; }
                let se = check_signature(top, cand);
                if se != OK { best = se; continue; }
                tried[depth] = io;
                path.push(here);
                tried.push(0);
                found = true;
                break;
            }
        } else {
            best = ERR_CHAIN_TOO_LONG;
        }
        if found { continue; }
        // A dead end: back up one level.
        if path.len == 0 { return best; }
        let dropped = path.pop();
        let t = tried.pop();
    }
}
