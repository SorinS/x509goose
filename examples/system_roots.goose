// The operating system's trusted roots, as a TLS client uses them: load
// the store (found as Go finds it on Unix: $SSL_CERT_FILE and
// $SSL_CERT_DIR, else the usual bundle files and directories), count and
// list a few, and add a private root of your own to a copy of it. Also
// loading roots from a file and a directory of your own. Reads local
// files only; where no store is found it says so and still succeeds.
//
//   goose examples/system_roots.goose -- [DIR]
import std;
import os;
import x509 from "..";
import bignum from "SorinS/bigmongoose@v0.7.0";
import asn1 from "SorinS/asn1goose@v0.7.0";
import x509.keys;
import x509.create;
import x509.pool;
import x509.verify;

let DAY: i64 = 86400;

fn main() {
    let now = time() as i64;

    // A private root and a server certificate under it, for the checks.
    let rk = x509::generate_key(x509::KEY_EC_P256);
    var rt, okr = x509::template("CN=Example Private Root,O=Example", now - DAY, now + 365 * DAY);
    rt.is_ca = true;
    rt.key_usage = x509::KU_KEY_CERT_SIGN;
    let root, er = x509::create_certificate(rt, x509::marshal_public_key(rk), "", rk);
    let lk = x509::generate_key(x509::KEY_EC_P256);
    var lt, okl = x509::template("CN=intranet.example.com", now - 60, now + 30 * DAY);
    x509::add_dns(lt.san, "intranet.example.com");
    let leaf, el = x509::create_certificate(lt, x509::marshal_public_key(lk), root, rk);
    guard okr && okl && er == x509::OK && el == x509::OK else { print("system_roots: making the test PKI"); exit(1); }

    // The system's store: loaded once per process, a copy each call.
    var sys, ok = x509::system_roots();
    if !ok || x509::pool_len(sys) == 0 {
        print("no system root store found (set SSL_CERT_FILE or SSL_CERT_DIR)");
    } else {
        print(x509::pool_len(sys), " system roots; the first few:");
        for i in min(3, x509::pool_len(sys)) {
            let c = x509::pool_cert(sys, i);
            print("  ", x509::subject_text(c));
        }
        // Our private root is not among them, so our server is unknown...
        let e = x509::verify_with_system_roots(leaf, "", now, "intranet.example.com");
        print("intranet.example.com against the system roots: ", x509::error_text(e));
        guard e == x509::ERR_UNKNOWN_ISSUER else { print("system_roots: unexpected result"); exit(1); }
    }
    // ...until we add it to our copy (the shared store is left alone).
    let n = x509::pool_len(sys);
    x509::pool_add(sys, root);
    let e2 = x509::verify_with_roots(leaf, "", sys, now, "intranet.example.com");
    print("with the private root added: ", x509::error_text(e2));
    var again, ok2 = x509::system_roots();
    guard e2 == x509::OK && x509::pool_len(sys) == n + 1 && x509::pool_len(again) == n else {
        print("system_roots: adding to a copy failed");
        exit(1);
    }

    // Roots of your own from disk: a PEM (or DER) file, or a directory of
    // them as c_rehash leaves it; each returns how many were new.
    let a = args();
    if a.len > 1 {
        var pem: u8[>..] = [];
        asn1::pem_encode(pem, "CERTIFICATE", root);
        let file = str(a[1], "/private-root.pem");
        guard write_file(file, pem) else { print("system_roots: cannot write ", file); exit(1); }
        var mine = x509::new_pool();
        let from_file = x509::pool_add_file(mine, file);
        let from_dir = x509::pool_add_dir(mine, a[1]);        // private-root.pem again is not new
        print("from ", file, ": ", from_file, " new; from ", a[1], ": ", from_dir, " new");
        guard from_file == 1 && from_dir >= 0 &&
              x509::verify_with_roots(leaf, "", mine, now, "intranet.example.com") == x509::OK else {
            print("system_roots: loading from disk failed");
            exit(1);
        }
    }
}
