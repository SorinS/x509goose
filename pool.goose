// x509.pool: sets of certificates, as Go's x509.CertPool, indexed by
// subject and subject key identifier so that path building looks up the
// possible issuers of a certificate instead of trying every one; loading
// them from PEM or DER files, from a directory, and from the system's
// root store (SystemCertPool).
//
// A pool keeps the DER of its certificates back to back, each once (a
// certificate added again is ignored), with an index entry each: where it
// is, and hashes of its subject, its key identifier and its whole DER.

namespace x509;

import std;
import os;
import x509;
import asn1;

let POOL_MAX: i64 = 4096;

struct CertPool {
    n: i64,
    start: u32[..4096], end: u32[..4096],   // the certificate's bytes in der
    subject: u32[..4096],                   // hash of the subject Name's DER
    key_id: u32[..4096],                    // hash of the subjectKeyIdentifier, 0 without one
    whole: u32[..4096],                     // hash of the certificate's DER
    der: u8[>..],
}

fn new_pool() -> CertPool {
    CertPool { n: 0, start: [], end: [], subject: [], key_id: [], whole: [], der: [] }
}

fn pool_hash(b: const u8[:]) -> u32 { hash(b) as! u32 }

fn pool_len(p: const CertPool&) -> i64 { p.n }

// The DER of the i-th certificate, in the order they were added.
fn pool_der(p: const CertPool&, i: i64) -> u8[>..] {
    var out: u8[>..] = [];
    out.append(p.der[(p.start[i] as i64)..(p.end[i] as i64)]);
    return out;
}

// The i-th certificate, parsed.
fn pool_cert(p: const CertPool&, i: i64) -> Cert {
    let c, e = parse(p.der[(p.start[i] as i64)..(p.end[i] as i64)]);
    assert(e == OK);
    return c;
}

// The index of a certificate in the pool, or -1.
fn pool_find(p: const CertPool&, der: const u8[:]) -> i64 {
    let h = pool_hash(der);
    for i in p.n {
        if p.whole[i] == h && p.der[(p.start[i] as i64)..(p.end[i] as i64)] == der { return i; }
    }
    return -1;
}

fn pool_contains(p: const CertPool&, der: const u8[:]) -> bool { pool_find(p, der) >= 0 }

// Adds a parsed certificate (AddCert); true if it is in the pool
// afterwards, false if the pool is full.
fn pool_add_cert(p: CertPool&, c: const Cert&) -> bool {
    let d = c.der[..];
    if pool_contains(p, d) { return true; }
    if p.n == POOL_MAX || p.der.len + d.len > 0xffffffff { return false; }
    p.start.push(p.der.len as! u32);
    p.der.append(d);
    p.end.push(p.der.len as! u32);
    p.subject.push(pool_hash(d[c.subject.start..c.subject.end]));
    p.key_id.push(if c.ski.end > c.ski.start { pool_hash(d[c.ski.off..c.ski.end]) } else { 0 });
    p.whole.push(pool_hash(d));
    p.n++;
    return true;
}

// Adds a certificate given as DER; false if it does not parse or the pool
// is full.
fn pool_add(p: CertPool&, der: const u8[:]) -> bool {
    let c, e = parse(der);
    if e != OK { return false; }
    return pool_add_cert(p, c);
}

// Adds every certificate of a concatenation of DER certificates (the form
// the rest of this package takes lists in); false if one is malformed.
fn pool_add_concatenated(p: CertPool&, list: const u8[:]) -> bool {
    var off = 0;
    while off < list.len {
        let t, ok = asn1::read(list, off, list.len);
        if !ok || !pool_add(p, list[t.start..t.end]) { return false; }
        off = t.end;
    }
    return true;
}

// A pool of a concatenation of DER certificates; false if one is malformed.
fn pool_of(list: const u8[:]) -> CertPool, bool {
    var p = new_pool();
    let ok = pool_add_concatenated(p, list);
    return p, ok;
}

// The certificates of a pool, DER concatenated.
fn pool_concatenated(p: const CertPool&) -> u8[>..] {
    var out: u8[>..] = [];
    for i in p.n { out.append(p.der[(p.start[i] as i64)..(p.end[i] as i64)]); }
    return out;
}

// Adds the CERTIFICATE blocks of a PEM text (AppendCertsFromPEM), skipping
// any that do not parse; how many were new to the pool.
fn pool_append_pem(p: CertPool&, text: const u8[:]) -> i64 {
    let ders, ok = asn1::pem_decode(text, "CERTIFICATE");
    var added = 0;
    for d in ders {
        let before = p.n;
        if pool_add(p, d) && p.n > before { added++; }
    }
    return added;
}

fn looks_pem(b: const u8[:]) -> bool {
    let tag = "-----BEGIN";
    if b.len < tag.len { return false; }
    for i in 0..b.len - tag.len + 1 {
        if b[i..i + tag.len] == tag { return true; }
    }
    return false;
}

// Adds the certificates of a file, PEM (any number) or a single DER
// certificate; how many were new, or -1 if the file cannot be read.
fn pool_add_file(p: CertPool&, path: const u8[:]) -> i64 {
    var b: u8[>..] = [];
    if !read_file(path, b) { return -1; }
    if looks_pem(b) { return pool_append_pem(p, b); }
    let before = p.n;
    let ok = pool_add(p, b);
    return p.n - before;
}

fn join_path(dir: const u8[:], name: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    out.append(dir);
    if dir.len > 0 && dir[dir.len - 1] != '/' { out.push('/'); }
    out.append(name);
    return out;
}

// Adds the certificates of every file in a directory (not its
// subdirectories), as openssl's and Go's certificate directories hold
// them: PEM or DER, hashed names or any others, files that hold no
// certificate skipped. A certificate reached under two names (the
// c_rehash links) is added once. How many were new, or -1 if the
// directory cannot be read.
fn pool_add_dir(p: CertPool&, dir: const u8[:]) -> i64 {
    var names: u8[>..] = [];
    if !list_dir(dir, names) { return -1; }
    var added = 0;
    for name in split(names, '\n') {
        if name.len == 0 { continue; }
        let path = join_path(dir, name);
        if !file_exists(path) { continue; }
        let n = pool_add_file(p, path);
        if n > 0 { added += n; }
    }
    return added;
}

// The possible issuers of c in the pool: those whose subject is c's issuer,
// those whose key identifier matches c's authority key identifier first
// (as Go orders them).
fn pool_issuers(p: const CertPool&, c: const Cert&) -> i64[>..] {
    var out: i64[>..] = [];
    let d = c.der[..];
    let name = d[c.issuer.start..c.issuer.end];
    let h = pool_hash(name);
    let has_aki = c.aki.end > c.aki.start;
    let aki = d[c.aki.off..c.aki.end];
    let hk = if has_aki { pool_hash(aki) } else { 0 };
    for pass in 2 {
        for i in p.n {
            if p.subject[i] != h { continue; }
            let cand = pool_cert(p, i);
            if cand.der[cand.subject.start..cand.subject.end] != name { continue; }
            let key_match = has_aki && p.key_id[i] == hk && cand.der[cand.ski.off..cand.ski.end] == aki;
            if (pass == 0) == key_match { out.push(i); }
        }
    }
    return out;
}

// --- The system's roots ------------------------------------------------------

// Where the systems keep their bundles and directories, as Go looks for
// them (crypto/x509's root_linux.go and root_bsd.go; macOS keeps its
// roots in /etc/ssl/cert.pem too). The first bundle that can be read is
// used.
let ROOT_FILES = [
    "/etc/ssl/certs/ca-certificates.crt",                // Debian, Ubuntu, Gentoo, Arch
    "/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora, RHEL 6
    "/etc/ssl/ca-bundle.pem",                            // openSUSE
    "/etc/pki/tls/cacert.pem",                           // OpenELEC
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS, RHEL 7
    "/etc/ssl/cert.pem",                                 // Alpine, macOS, OpenBSD
    "/usr/local/etc/ssl/cert.pem",                       // FreeBSD
    "/usr/local/share/certs/ca-root-nss.crt",            // DragonFly
    "/etc/openssl/certs/ca-certificates.crt",            // NetBSD
];

let ROOT_DIRS = [
    "/etc/ssl/certs",                // SLES10, SLES11
    "/etc/pki/tls/certs",            // Fedora, RHEL
    "/usr/local/share/certs",        // FreeBSD
    "/etc/openssl/certs",            // NetBSD
];

// Loads the system's roots, as Go's SystemCertPool on Unix: the file named
// by $SSL_CERT_FILE, else the first bundle of ROOT_FILES that can be read;
// then every directory of $SSL_CERT_DIR (separated by ':'), else of
// ROOT_DIRS. False if no certificate was found. (Windows keeps its roots
// in the system's certificate store, which this does not read.)
fn load_system_roots() -> CertPool, bool {
    var p = new_pool();
    var file: u8[>..] = [];
    if env("SSL_CERT_FILE", file) {
        let n = pool_add_file(p, file);
    } else {
        for f in ROOT_FILES {
            if pool_add_file(p, f) >= 0 { break; }
        }
    }
    var dirs: u8[>..] = [];
    if env("SSL_CERT_DIR", dirs) {
        for d in split(dirs, ':') {
            if d.len > 0 { let n = pool_add_dir(p, d); }
        }
    } else {
        for d in ROOT_DIRS { let n = pool_add_dir(p, d); }
    }
    return p, p.n > 0;
}

var SYSTEM_ROOTS_LOADED = false;
var SYSTEM_ROOTS_OK = false;
var SYSTEM_ROOTS = CertPool { n: 0, start: [], end: [], subject: [], key_id: [], whole: [], der: [] };

// The system's roots (SystemCertPool): loaded the first time, then a copy
// of what was loaded, which the caller may add to.
fn system_roots() -> CertPool, bool {
    load_system_roots_once();
    return copy(SYSTEM_ROOTS), SYSTEM_ROOTS_OK;
}

fn load_system_roots_once() {
    if SYSTEM_ROOTS_LOADED { return; }
    let p, ok = load_system_roots();
    SYSTEM_ROOTS = copy(p);
    SYSTEM_ROOTS_OK = ok;
    SYSTEM_ROOTS_LOADED = true;
}
