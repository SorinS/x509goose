// x509.verify: certification path validation for TLS servers and clients
// (RFC 5280 §6, as their chains need it): path building over pools of
// intermediates and roots, then the checks that need the whole path (name
// constraints, policies, revocation).

namespace x509;

import std;
import x509;
import asn1;
import constraints;
import policy;
import crl;
import pool;

// Checks that apply to any certificate on a path: dates and extensions.
fn check_common(c: const Cert&, now: i64) -> i64 {
    if c.unknown_critical { return ERR_UNKNOWN_CRITICAL_EXTENSION; }
    if now < c.not_before { return ERR_NOT_YET_VALID; }
    if now > c.not_after { return ERR_EXPIRED; }
    return OK;
}

// Of the usages wanted (EKU_* masks, any one of which will do), those a
// certificate's extended key usage allows: all of them if it has none or
// allows any usage, or if EKU_ANY is wanted. A path is good for the
// usages that survive every certificate on it.
fn eku_surviving(c: const Cert&, wanted: u32) -> u32 {
    if wanted & EKU_ANY != 0 || !c.has_ext_key_usage || c.ext_key_usage & EKU_ANY != 0 { return wanted; }
    return wanted & c.ext_key_usage;
}

// Checks on a certificate that issues the one below it, `below`
// non-self-issued CA certificates (not counting the leaf) further down the
// path (RFC 5280 §4.2.1.9), for the extended key usages that survive the
// path below it.
fn check_issuer(c: const Cert&, now: i64, below: i64, wanted: u32) -> i64 {
    let e = check_common(c, now);
    if e != OK { return e; }
    if !c.has_basic_constraints || !c.is_ca { return ERR_NOT_CA; }
    if c.path_len >= 0 && below > c.path_len { return ERR_PATH_LENGTH; }
    if c.has_key_usage && c.key_usage & KU_KEY_CERT_SIGN == 0 { return ERR_KEY_USAGE; }
    // A CA restricted by extended key usage must allow a usage wanted that
    // the path below allows too (as Go, Chrome and Firefox require).
    if eku_surviving(c, wanted) == 0 { return ERR_EXTENDED_KEY_USAGE; }
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

// Signature checks one path search may make, as Go's
// maxChainSignatureChecks: certificates sent to be verified must not
// buy unbounded work.
let MAX_SIGNATURE_CHECKS: i64 = 100;

// Whether two certificates are one as far as a path goes: subject, key
// and subjectAltName (Go's alreadyInChain). Coming back to either only
// makes a loop, or the permutations of copies of one CA.
fn same_identity(a: const Cert&, b: const Cert&) -> bool {
    a.der[a.subject.start..a.subject.end] == b.der[b.subject.start..b.subject.end]
        && a.der[a.spki.start..a.spki.end] == b.der[b.spki.start..b.spki.end]
        && a.has_san == b.has_san && a.der[a.san.start..a.san.end] == b.der[b.san.start..b.san.end]
}

// The error to report of two met in a path search, each with how close
// its path came (verify_pools); of equals, the later.
fn closer(best: i64, best_rank: i64, e: i64, rank: i64) -> i64, i64 {
    if rank >= best_rank { return e, rank; }
    return best, best_rank;
}

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

// Validates a TLS server certificate: see verify_pools, with the
// intermediates and roots as DER certificates concatenated. A malformed
// intermediate is ERR_MALFORMED; roots that do not parse are left out.
fn verify_chain_with(leaf_der: const u8[:], intermediates: const u8[:], roots: const u8[:],
                     crls: const u8[:], now: i64, host: const u8[:], opts: const Options&) -> i64 {
    let inters, oki = pool_of(intermediates);
    if !oki { return ERR_MALFORMED; }
    var rp = new_pool();
    let okr = pool_add_concatenated(rp, roots);
    return verify_pools(leaf_der, inters, rp, crls, now, host, opts);
}

// Validates a TLS server certificate with default options and no CRLs
// against a pool of roots (the system's, say): see verify_pools.
fn verify_with_roots(leaf_der: const u8[:], intermediates: const u8[:], roots: const CertPool&, now: i64,
                     host: const u8[:]) -> i64 {
    let inters, oki = pool_of(intermediates);
    if !oki { return ERR_MALFORMED; }
    let opts = options();
    return verify_pools(leaf_der, inters, roots, "", now, host, opts);
}

// Validates a TLS server certificate with default options and no CRLs
// against the system's roots (system_roots), loaded the first time; false
// in `found` if there are none, when the result is ERR_UNKNOWN_ISSUER.
fn verify_with_system_roots(leaf_der: const u8[:], intermediates: const u8[:], now: i64,
                            host: const u8[:]) -> i64, bool {
    load_system_roots_once();
    let e = verify_with_roots(leaf_der, intermediates, SYSTEM_ROOTS, now, host);
    return e, SYSTEM_ROOTS_OK;
}

// Validates a TLS client certificate against a pool of roots: as
// verify_with_roots, for client authentication and without a host name.
fn verify_client_with_roots(leaf_der: const u8[:], intermediates: const u8[:], roots: const CertPool&,
                            now: i64) -> i64 {
    let inters, oki = pool_of(intermediates);
    if !oki { return ERR_MALFORMED; }
    var opts = options();
    opts.key_usages = EKU_CLIENT_AUTH;
    return verify_pools(leaf_der, inters, roots, "", now, "", opts);
}

// The same against the system's roots; false in `found` if there are none.
fn verify_client_with_system_roots(leaf_der: const u8[:], intermediates: const u8[:], now: i64) -> i64, bool {
    load_system_roots_once();
    let e = verify_client_with_roots(leaf_der, intermediates, SYSTEM_ROOTS, now);
    return e, SYSTEM_ROOTS_OK;
}

// Validates a TLS server certificate (Go's Certificate.Verify): a path from
// `leaf` through any of `intermediates` to one of `roots`, every link
// signed by the next, all of them valid at `now` (seconds since 1970), the
// CAs allowed to issue, one of the options' extended key usages (server
// authentication by default) allowed by the leaf and every CA above it,
// the leaf valid for `host` (no check when host is empty), every name within the
// name constraints above it, an acceptable policy when the path or the
// options require one, and, when the options ask, a usable CRL among
// `crls` (DER CRLs concatenated) that does not list the certificates
// checked. The roots' own signatures and dates are not checked, only
// their keys and constraints, as trust anchors are. Issuers are looked up
// by name in the pools, those with the matching key identifier first.
// Returns OK or the error of the path that came closest: the longest
// path whose signatures verified, and at its top a failed check on the
// whole path before an issuer that is not a CA (or is expired, and so
// on), and that before a bad signature, likely just another CA of the
// same name.
fn verify_pools(leaf_der: const u8[:], intermediates: const CertPool&, roots: const CertPool&,
                crls: const u8[:], now: i64, host: const u8[:], opts: const Options&) -> i64 {
    let leaf, e = parse(leaf_der);
    if e != OK { return e; }
    let le = check_common(leaf, now);
    if le != OK { return le; }
    let leaf_usages = eku_surviving(leaf, opts.key_usages);
    if leaf_usages == 0 { return ERR_EXTENDED_KEY_USAGE; }
    if leaf.has_key_usage && leaf.key_usage & (KU_DIGITAL_SIGNATURE | KU_KEY_ENCIPHERMENT | KU_KEY_AGREEMENT) == 0 {
        return ERR_KEY_USAGE;
    }
    if host.len > 0 && !matches_host(leaf, host) { return ERR_HOSTNAME; }
    // The leaf itself trusted, as a pinned certificate.
    if pool_contains(roots, leaf_der) { return OK; }
    // Depth-first search. path[i] is the index in `intermediates` of the
    // i-th certificate above the leaf; tried[i] is how many of the
    // candidates for the next one up have been tried.
    var path:  i64[>..<] = [];
    var tried: i64[>..<] = [0];
    var best = ERR_UNKNOWN_ISSUER;
    var best_rank = -1;
    var sigs = 0;
    loop {
        let depth = path.len;
        // The certificate at the top of the path so far.
        var top = empty_cert();
        if depth == 0 { top = copy(leaf); } else { top = pool_cert(intermediates, path[depth - 1]); }
        // The usages wanted that the path so far allows, and its
        // intermediates that count against a path length constraint: not
        // the self-issued ones (a CA's key rollover, say).
        var usages = leaf_usages;
        var below = 0;
        for p in path {
            let pc = pool_cert(intermediates, p);
            usages = eku_surviving(pc, usages);
            if !self_issued(pc) { below++; }
        }
        // A root that issued it ends the search, if the whole path holds;
        // tried once per certificate on the path.
        if tried[depth] == 0 {
            for ri in pool_issuers(roots, top) {
                let root = pool_cert(roots, ri);
                let ce = check_issuer(root, now, below, usages);
                // A root without basicConstraints is accepted if it is
                // self-issued (a v1 root); otherwise roots are held to the
                // same rules as any CA.
                let ok_root = ce == OK || (ce == ERR_NOT_CA && !root.has_basic_constraints && self_issued(root));
                if !ok_root { best, best_rank = closer(best, best_rank, ce, 3 * depth + 1); continue; }
                if sigs == MAX_SIGNATURE_CHECKS { return ERR_TOO_MANY_SIGNATURES; }
                sigs++;
                let se = check_signature(top, root);
                if se != OK { best, best_rank = closer(best, best_rank, se, 3 * depth); continue; }
                var chain: u8[>..] = [];
                var k = depth;
                while k > 0 {
                    k--;
                    chain.append(pool_der(intermediates, path[k]));
                }
                chain.append(leaf_der);
                let pe = check_path(root, chain, depth + 1, crls, now, opts);
                if pe == OK { return OK; }
                best, best_rank = closer(best, best_rank, pe, 3 * depth + 2);
            }
        }
        // Otherwise an intermediate that issued it, not already on the path.
        var found = false;
        if depth < MAX_DEPTH {
            let cands = pool_issuers(intermediates, top);
            var ci = tried[depth];
            while ci < cands.len {
                let here = cands[ci];
                ci++;
                let cand = pool_cert(intermediates, here);
                var on_path = same_identity(cand, leaf);
                for p in path {
                    if on_path { break; }
                    if p == here { on_path = true; continue; }
                    let pc = pool_cert(intermediates, p);
                    on_path = same_identity(cand, pc);
                }
                if on_path { continue; }
                let ce = check_issuer(cand, now, below, usages);
                if ce != OK { best, best_rank = closer(best, best_rank, ce, 3 * depth + 1); continue; }
                if sigs == MAX_SIGNATURE_CHECKS { return ERR_TOO_MANY_SIGNATURES; }
                sigs++;
                let se = check_signature(top, cand);
                if se != OK { best, best_rank = closer(best, best_rank, se, 3 * depth); continue; }
                path.push(here);
                tried.push(0);
                found = true;
                break;
            }
            tried[depth] = ::max(ci, 1);
        } else {
            best, best_rank = closer(best, best_rank, ERR_CHAIN_TOO_LONG, 3 * depth + 1);
        }
        if found { continue; }
        // A dead end: back up one level.
        if path.len == 0 { return best; }
        let dropped = path.pop();
        let t = tried.pop();
    }
}
