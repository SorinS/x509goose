// x509.pool: adding certificates once, from DER, PEM, files and a
// directory (vectors/rootdir, scripts/make_rootdir.py: PEM and DER files,
// a c_rehash link, a file with junk, one without certificates, and a
// subdirectory left alone); looking up issuers, those with the matching key
// identifier first; path validation over pools, also with two roots of one
// name; and the system's roots, which must load and validate a path
// wherever they come from.
import std;
import os;
import x509 from "..";
import asn1 from "../../asn1goose.git";
import bignum from "../../bigmongoose.git";
import x509.pool;
import x509.verify;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        assert(ok);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

fn cert_der(name: const u8[:]) -> u8[>..] {
    for line in split(embed_file("vectors/certs.txt"), '\n') {
        let w = words(line);
        if w.len == 3 && w[0] == "cert" && w[1] == name { return unhex(w[2]); }
    }
    assert(false);
    var none: u8[>..] = [];
    return none;
}

let NOW: i64 = 1793000000;

fn main() {
    // Adding.
    var p = x509::new_pool();
    check("empty", x509::pool_len(p) == 0 && !x509::pool_contains(p, cert_der("root_rsa")));
    check("add", x509::pool_add(p, cert_der("root_rsa")) && x509::pool_len(p) == 1);
    check("add again", x509::pool_add(p, cert_der("root_rsa")) && x509::pool_len(p) == 1);
    check("contains", x509::pool_contains(p, cert_der("root_rsa")) && !x509::pool_contains(p, cert_der("root_p384")));
    check("junk refused", !x509::pool_add(p, "not DER") && x509::pool_len(p) == 1);
    check("der back", x509::pool_der(p, 0) == cert_der("root_rsa"));
    var pem: u8[>..] = [];
    asn1::pem_encode(pem, "CERTIFICATE", cert_der("root_p384"));
    asn1::pem_encode(pem, "CERTIFICATE", cert_der("root_rsa"));
    asn1::pem_encode(pem, "PRIVATE KEY", "skipped");
    check("pem: one new", x509::pool_append_pem(p, pem) == 1 && x509::pool_len(p) == 2);
    var cat: u8[>..] = [];
    cat.append(cert_der("root_ed"));
    cat.append(cert_der("root_rsa"));
    check("concatenated", x509::pool_add_concatenated(p, cat) && x509::pool_len(p) == 3);
    check("concatenated back", x509::pool_concatenated(p).len == cert_der("root_rsa").len + cert_der("root_p384").len +
                                                               cert_der("root_ed").len);

    // Files and a directory.
    var d = x509::new_pool();
    check("missing file", x509::pool_add_file(d, "vectors/rootdir/none.pem") == -1);
    check("missing directory", x509::pool_add_dir(d, "vectors/no_such_dir") == -1);
    check("der file", x509::pool_add_file(d, "vectors/rootdir/p384.der") == 1);
    check("directory", x509::pool_add_dir(d, "vectors/rootdir") == 2 && x509::pool_len(d) == 3);
    check("directory has both roots of one name", x509::pool_contains(d, cert_der("root_rsa")) &&
          x509::pool_contains(d, cert_der("root_rsa_other")));
    check("subdirectory not read", !x509::pool_contains(d, cert_der("root_ed")));
    check("directory again: nothing new", x509::pool_add_dir(d, "vectors/rootdir/") == 0);
    check("text file: nothing", x509::pool_add_file(d, "vectors/rootdir/readme.txt") == 0);

    // Issuers: both roots named like int_ec's issuer, the one with
    // int_ec's authority key identifier first though it was added last.
    let int_ec, e1 = x509::parse(cert_der("int_ec"));
    let iss = x509::pool_issuers(d, int_ec);
    check("two issuers by name", iss.len == 2);
    check("key identifier first", iss.len == 2 && x509::pool_der(d, iss[0]) == cert_der("root_rsa"));
    let leaf_ed, e2 = x509::parse(cert_der("leaf_ed"));
    var inters = x509::new_pool();
    check("intermediates", x509::pool_add(inters, cert_der("int_ec")) && x509::pool_add(inters, cert_der("int_pss")));
    check("no issuer", x509::pool_issuers(inters, int_ec).len == 0);

    // Paths over pools.
    let opts = x509::options();
    check("path via the directory's roots",
          x509::verify_pools(cert_der("leaf_ec"), inters, d, "", NOW, "example.com", opts) == x509::OK);
    check("pss path", x509::verify_pools(cert_der("leaf_pss"), inters, d, "", NOW, "example.com", opts) == x509::OK);
    check("ed root not in the directory",
          x509::verify_pools(cert_der("leaf_ed"), inters, d, "", NOW, "", opts) == x509::ERR_UNKNOWN_ISSUER);
    var other = x509::new_pool();
    check("other root", x509::pool_add(other, cert_der("root_rsa_other")));
    check("same name, other key", x509::verify_pools(cert_der("leaf_ec"), inters, other, "", NOW, "", opts) ==
                                  x509::ERR_BAD_SIGNATURE);
    check("verify_with_roots", x509::verify_with_roots(cert_der("leaf_ec"), cert_der("int_ec"), d, NOW, "example.com") ==
                               x509::OK);
    var pinned = x509::new_pool();
    check("pinned leaf", x509::pool_add(pinned, cert_der("leaf_ec")) &&
          x509::verify_pools(cert_der("leaf_ec"), inters, pinned, "", NOW, "example.com", opts) == x509::OK);

    // The system's roots: loaded once, a copy each time.
    let sys, oks = x509::system_roots();
    check("system roots", oks && x509::pool_len(sys) > 0);
    var mine, okm = x509::system_roots();
    check("system roots: a copy", okm && x509::pool_add(mine, cert_der("root_p384")) &&
          x509::pool_len(mine) == x509::pool_len(sys) + 1);
    let again, oka = x509::system_roots();
    check("system roots unchanged", x509::pool_len(again) == x509::pool_len(sys));
    var any_parse = true;
    for i in x509::pool_len(sys) {
        let c = x509::pool_cert(sys, i);
        if c.der.len == 0 { any_parse = false; }
    }
    check("system roots parse", any_parse);
    print("pool: ", checks, " checks, ", failures, " failed");
    if failures > 0 { exit(1); }
}
