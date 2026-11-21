// Prints the system's roots as x509.pool loads them, for
// scripts/check_roots.py: "ok <0|1> <count>", then the SHA-256 of each
// certificate's DER, one a line.
//
//   goose tools/roots.goose
import std;
import os;
import x509 from "..";
import entropy from "SorinS/entropygoose@v0.9.1";
import bignum from "SorinS/bigmongoose@v0.9.1";
import asn1 from "SorinS/asn1goose@v0.9.1";
import bignum.hmac;
import x509.pool;

fn main() {
    let p, ok = x509::load_system_roots();
    print("ok ", if ok { 1 } else { 0 }, " ", x509::pool_len(p));
    for i in x509::pool_len(p) {
        var line: u8[>..] = [];
        for b in bignum::hash_bits(256, x509::pool_der(p, i)) { format_uint(line, b, 16, 2, '0'); }
        print(line);
    }
}
