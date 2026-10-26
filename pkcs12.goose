// x509.pkcs12: decoding PKCS #12 files (.p12, .pfx; RFC 7292) into their
// private keys and certificates, as Go's x/crypto/pkcs12 does, and more:
//
// - the integrity MAC: HMAC over SHA-1 (Go's only one), SHA-224, -256,
//   -384 or -512, keyed by the PKCS #12 KDF from the password;
// - the PKCS #12 PBEs Go reads: pbeWithSHAAnd3-KeyTripleDES-CBC and
//   pbeWithSHAAnd40BitRC2-CBC, plus 128-bit RC2 and 2-key 3DES;
// - PBES2 (RFC 8018) with PBKDF2 over HMAC-SHA-1/224/256/384/512 and
//   AES-128/192/256-CBC, which openssl 3 writes by default and Go's
//   x/crypto/pkcs12 refuses;
// - unencrypted bags.
//
// The password is UTF-8. The PKCS #12 KDF takes it as a NUL-terminated
// BMPString (UTF-16, so characters past U+FFFF are refused, as Go does);
// PBES2 takes the UTF-8 bytes.

namespace x509;

import std;
import x509;
import asn1;
import bignum;
import bignum.ct;
import bignum.hmac;
import bignum.kdf;
import bignum.aes;
import bignum.des;
import bignum.rc2;
import bignum.modes;

let OID_PKCS7_DATA: const u8[:] = "1.2.840.113549.1.7.1";
let OID_PKCS7_ENCRYPTED: const u8[:] = "1.2.840.113549.1.7.6";
let OID_KEY_BAG: const u8[:] = "1.2.840.113549.1.12.10.1.1";
let OID_SHROUDED_KEY_BAG: const u8[:] = "1.2.840.113549.1.12.10.1.2";
let OID_CERT_BAG: const u8[:] = "1.2.840.113549.1.12.10.1.3";
let OID_X509_CERT: const u8[:] = "1.2.840.113549.1.9.22.1";

// The password as a NUL-terminated BMPString; false for invalid UTF-8 or
// a character past U+FFFF.
fn bmp_password(pw: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if !asn1::utf8_valid(pw) { return out, false; }
    var i = 0;
    while i < pw.len {
        let c: u32 = pw[i];
        var cp: u32 = 0;
        var n = 1;
        if c < 0x80 { cp = c; }
        else if c < 0xe0 { cp = (c & 0x1f) << 6 | ((pw[i + 1] as u32) & 0x3f); n = 2; }
        else if c < 0xf0 { cp = (c & 0x0f) << 12 | ((pw[i + 1] as u32) & 0x3f) << 6 | ((pw[i + 2] as u32) & 0x3f); n = 3; }
        else { return out, false; }
        out.push((cp >> 8) as! u8);
        out.push(cp as! u8);
        i += n;
    }
    out.push(0);
    out.push(0);
    return out, true;
}

// The PKCS #12 KDF (RFC 7292 Appendix B.2): n bytes for purpose id (1 a
// key, 2 an IV, 3 a MAC key) from the BMP password and salt, over hash h.
fn pkcs12_kdf(h: i64, id: u8, password: const u8[:], salt: const u8[:], iterations: i64, n: i64) -> u8[>..] {
    let v = bignum::hash_block(h);
    let u = bignum::hash_len(h);
    var d: u8[>..] = [];
    d.resize(v, id);
    var ib: u8[>..] = [];
    if salt.len > 0 { for k in v * ((salt.len + v - 1) / v) { ib.push(salt[k % salt.len]); } }
    if password.len > 0 { for k in v * ((password.len + v - 1) / v) { ib.push(password[k % password.len]); } }
    var out: u8[>..] = [];
    while out.len < n {
        var a = bignum::hash2(h, d, ib);
        for r in iterations - 1 {
            let next = bignum::hash_bits(h, a);
            a = copy(next);
        }
        out.append(a);
        // I_j += B + 1 for each v-byte block, B = A repeated to v bytes.
        var j = 0;
        while j < ib.len {
            var carry: u32 = 1;
            var k = v;
            while k > 0 {
                k--;
                let t = ib[j + k] as u32 + a[k % u] as u32 + carry;
                ib[j + k] = t as! u8;
                carry = t >> 8;
            }
            j += v;
        }
    }
    out.resize(n, 0);
    return out;
}

// salt and iterations of a PKCS #12 PBE or MAC: SEQUENCE { salt, iterations }.
fn pkcs12_pbe_params(d: const u8[:], t: asn1::Tlv) -> u8[>..], i64, bool {
    var none: u8[>..] = [];
    let ps, ok = asn1::children_of(d, t, asn1::SEQUENCE);
    if !ok || ps.len != 2 { return none, 0, false; }
    let salt, oks = asn1::read_octets(d, ps[0]);
    let it, oki = asn1::read_i64(d, ps[1]);
    if !oks || !oki || it < 1 || it > 10000000 { return none, 0, false; }
    return salt, it, true;
}

// The MAC's digest AlgorithmIdentifier: SHA-1 or SHA-2, NULL or no
// parameters.
fn pkcs12_digest_alg(d: const u8[:], t: asn1::Tlv) -> i64 {
    let p, ok = asn1::children_of(d, t, asn1::SEQUENCE);
    if !ok || p.len < 1 || p.len > 2 || (p.len == 2 && !asn1::read_null(d, p[1])) { return 0; }
    if asn1::oid_is(d, p[0], "1.3.14.3.2.26") { return 160; }
    if asn1::oid_is(d, p[0], "2.16.840.1.101.3.4.2.4") { return 224; }
    return hash_of_oid(d, p[0]);
}

fn pkcs12_hmac_hash(d: const u8[:], t: asn1::Tlv) -> i64 {
    let ps, ok = asn1::children_of(d, t, asn1::SEQUENCE);
    if !ok || ps.len < 1 || ps.len > 2 { return 0; }
    if asn1::oid_is(d, ps[0], "1.2.840.113549.2.7") { return 160; }
    if asn1::oid_is(d, ps[0], "1.2.840.113549.2.8") { return 224; }
    if asn1::oid_is(d, ps[0], "1.2.840.113549.2.9") { return 256; }
    if asn1::oid_is(d, ps[0], "1.2.840.113549.2.10") { return 384; }
    if asn1::oid_is(d, ps[0], "1.2.840.113549.2.11") { return 512; }
    return 0;
}

// Decrypts data under the AlgorithmIdentifier alg; the plaintext, or
// ERR_BAD_SIGNATURE for a wrong password (bad padding),
// ERR_UNSUPPORTED_ALGORITHM, ERR_MALFORMED.
fn pkcs12_decrypt(d: const u8[:], alg: asn1::Tlv, data: const u8[:], password: const u8[:]) -> u8[>..], i64 {
    var none: u8[>..] = [];
    let a, ok = asn1::children_of(d, alg, asn1::SEQUENCE);
    if !ok || a.len != 2 { return none, ERR_MALFORMED; }
    var buf: u8[>..] = [];
    buf.append(data);
    if asn1::oid_is(d, a[0], "1.2.840.113549.1.5.13") {
        // PBES2: SEQUENCE { keyDerivationFunc (PBKDF2), encryptionScheme }.
        let p2, okp = asn1::children_of(d, a[1], asn1::SEQUENCE);
        if !okp || p2.len != 2 { return none, ERR_MALFORMED; }
        let kdf, okk = asn1::children_of(d, p2[0], asn1::SEQUENCE);
        if !okk || kdf.len != 2 || !asn1::oid_is(d, kdf[0], "1.2.840.113549.1.5.12") { return none, ERR_UNSUPPORTED_ALGORITHM; }
        let kp, okkp = asn1::children_of(d, kdf[1], asn1::SEQUENCE);
        if !okkp || kp.len < 2 { return none, ERR_MALFORMED; }
        let salt, oks = asn1::read_octets(d, kp[0]);
        let it, oki = asn1::read_i64(d, kp[1]);
        if !oks || !oki || it < 1 || it > 10000000 { return none, ERR_MALFORMED; }
        var prf = 160;
        var keylen: i64 = -1;
        var i = 2;
        if i < kp.len && kp[i].tag == asn1::INTEGER {
            let kl, okl = asn1::read_i64(d, kp[i]);
            if !okl { return none, ERR_MALFORMED; }
            keylen = kl;
            i++;
        }
        if i < kp.len { prf = pkcs12_hmac_hash(d, kp[i]); i++; }
        if prf == 0 || i != kp.len { return none, ERR_UNSUPPORTED_ALGORITHM; }
        let es, oke = asn1::children_of(d, p2[1], asn1::SEQUENCE);
        if !oke || es.len != 2 { return none, ERR_MALFORMED; }
        var klen = 0;
        if asn1::oid_is(d, es[0], "2.16.840.1.101.3.4.1.2") { klen = 16; }
        else if asn1::oid_is(d, es[0], "2.16.840.1.101.3.4.1.22") { klen = 24; }
        else if asn1::oid_is(d, es[0], "2.16.840.1.101.3.4.1.42") { klen = 32; }
        else { return none, ERR_UNSUPPORTED_ALGORITHM; }
        let iv, okiv = asn1::read_octets(d, es[1]);
        if !okiv || iv.len != 16 || (keylen >= 0 && keylen != klen) || buf.len % 16 != 0 || buf.len == 0 { return none, ERR_MALFORMED; }
        let key = bignum::pbkdf2(prf, password, salt, it, klen);
        let c = bignum::aes_init(key);
        bignum::cbc_decrypt(c, iv, buf);
        let pt, okpad = bignum::pkcs7_unpad(buf, 16);
        return pt, if okpad { OK } else { ERR_BAD_SIGNATURE };
    }
    // The PKCS #12 PBEs, keyed by the KDF over SHA-1.
    let salt, it, okp = pkcs12_pbe_params(d, a[1]);
    if !okp { return none, ERR_MALFORMED; }
    let bmp, okb = bmp_password(password);
    if !okb { return none, ERR_MALFORMED; }
    if buf.len % 8 != 0 || buf.len == 0 { return none, ERR_MALFORMED; }
    let iv = pkcs12_kdf(160, 2, bmp, salt, it, 8);
    if asn1::oid_is(d, a[0], "1.2.840.113549.1.12.1.3") || asn1::oid_is(d, a[0], "1.2.840.113549.1.12.1.4") {
        let three = asn1::oid_is(d, a[0], "1.2.840.113549.1.12.1.3");
        var key = pkcs12_kdf(160, 1, bmp, salt, it, if three { 24 } else { 16 });
        if !three { for k in 8 { key.push(key[k]); } }             // 2-key: K1 K2 K1
        let c = bignum::des3_init(key);
        bignum::cbc_decrypt(c, iv, buf);
    } else if asn1::oid_is(d, a[0], "1.2.840.113549.1.12.1.6") || asn1::oid_is(d, a[0], "1.2.840.113549.1.12.1.5") {
        let bits = if asn1::oid_is(d, a[0], "1.2.840.113549.1.12.1.6") { 40 } else { 128 };
        let key = pkcs12_kdf(160, 1, bmp, salt, it, bits / 8);
        let c = bignum::rc2_init(key, bits);
        bignum::cbc_decrypt(c, iv, buf);
    } else {
        return none, ERR_UNSUPPORTED_ALGORITHM;
    }
    let pt, okpad = bignum::pkcs7_unpad(buf, 8);
    return pt, if okpad { OK } else { ERR_BAD_SIGNATURE };
}

// The bags of one SafeContents into key and certs; false-like errors as
// pkcs12_decrypt.
fn pkcs12_bags(sc: const u8[:], password: const u8[:], key: u8[>..]&, nkeys: i64&, certs: u8[>..]&) -> i64 {
    let top, ok = asn1::parse(sc);
    let bags, okb = asn1::children_of(sc, top, asn1::SEQUENCE);
    if !ok || !okb { return ERR_MALFORMED; }
    for b in bags {
        let f, okf = asn1::children_of(sc, b, asn1::SEQUENCE);
        if !okf || f.len < 2 || f.len > 3 || f[1].tag != asn1::ctx(0, true) { return ERR_MALFORMED; }
        let v, okv = asn1::explicit(sc, f[1]);
        if !okv { return ERR_MALFORMED; }
        if asn1::oid_is(sc, f[0], OID_KEY_BAG) {
            key.clear();
            key.append(sc[v.start..v.end]);
            nkeys++;
        } else if asn1::oid_is(sc, f[0], OID_SHROUDED_KEY_BAG) {
            // EncryptedPrivateKeyInfo: SEQUENCE { algorithm, encryptedData }.
            let e, oke = asn1::children_of(sc, v, asn1::SEQUENCE);
            if !oke || e.len != 2 || e[1].tag != asn1::OCTET_STRING { return ERR_MALFORMED; }
            let pt, err = pkcs12_decrypt(sc, e[0], sc[e[1].off..e[1].end], password);
            if err != OK { return err; }
            let pk, okpk = asn1::parse(pt);
            if !okpk || pk.tag != asn1::SEQUENCE { return ERR_BAD_SIGNATURE; }
            key.clear();
            key.append(pt);
            nkeys++;
        } else if asn1::oid_is(sc, f[0], OID_CERT_BAG) {
            let cb, okc = asn1::children_of(sc, v, asn1::SEQUENCE);
            if !okc || cb.len != 2 || cb[1].tag != asn1::ctx(0, true) { return ERR_MALFORMED; }
            if !asn1::oid_is(sc, cb[0], OID_X509_CERT) { continue; }          // SDSI and others: skipped
            let cv, okcv = asn1::explicit(sc, cb[1]);
            if !okcv || cv.tag != asn1::OCTET_STRING { return ERR_MALFORMED; }
            certs.append(sc[cv.off..cv.end]);
        }
        // CRL, secret and nested bags are skipped, as Go does.
    }
    return OK;
}

// Decode: the private key (PKCS #8 PrivateKeyInfo DER, for
// parse_private_key; empty if the file has none) and the certificates
// (DER concatenated, in the file's order). OK, or ERR_MALFORMED,
// ERR_UNSUPPORTED_ALGORITHM, ERR_BAD_SIGNATURE for a wrong password (a
// MAC or padding that does not check out). A file with several keys is
// refused (ERR_MALFORMED), as in Go.
fn pkcs12_decode(pfx: const u8[:], password: const u8[:]) -> u8[>..], u8[>..], i64 {
    var key: u8[>..] = [];
    var certs: u8[>..] = [];
    let top, ok = asn1::parse(pfx);
    let p, okp = asn1::children_of(pfx, top, asn1::SEQUENCE);
    if !ok || !okp || p.len < 2 || p.len > 3 { return key, certs, ERR_MALFORMED; }
    let ver, okv = asn1::read_i64(pfx, p[0]);
    if !okv || ver != 3 { return key, certs, ERR_MALFORMED; }
    // authSafe: id-data with the AuthenticatedSafe in an OCTET STRING.
    let ci, okci = asn1::children_of(pfx, p[1], asn1::SEQUENCE);
    if !okci || ci.len != 2 || !asn1::oid_is(pfx, ci[0], OID_PKCS7_DATA) || ci[1].tag != asn1::ctx(0, true) {
        return key, certs, ERR_UNSUPPORTED_ALGORITHM;               // public-key integrity mode
    }
    let os, okos = asn1::explicit(pfx, ci[1]);
    if !okos || os.tag != asn1::OCTET_STRING { return key, certs, ERR_MALFORMED; }
    let auth_safe = pfx[os.off..os.end];
    if p.len == 3 {
        // MacData: SEQUENCE { DigestInfo, macSalt, iterations DEFAULT 1 }.
        let md, okmd = asn1::children_of(pfx, p[2], asn1::SEQUENCE);
        if !okmd || md.len < 2 || md.len > 3 { return key, certs, ERR_MALFORMED; }
        let di, okdi = asn1::children_of(pfx, md[0], asn1::SEQUENCE);
        if !okdi || di.len != 2 || di[1].tag != asn1::OCTET_STRING { return key, certs, ERR_MALFORMED; }
        let h = pkcs12_digest_alg(pfx, di[0]);
        let salt, oks = asn1::read_octets(pfx, md[1]);
        var it: i64 = 1;
        if md.len == 3 {
            let n, okn = asn1::read_i64(pfx, md[2]);
            if !okn || n < 1 || n > 10000000 { return key, certs, ERR_MALFORMED; }
            it = n;
        }
        if h == 0 || !oks { return key, certs, ERR_UNSUPPORTED_ALGORITHM; }
        let bmp, okb = bmp_password(password);
        if !okb { return key, certs, ERR_MALFORMED; }
        let mk = pkcs12_kdf(h, 3, bmp, salt, it, bignum::hash_len(h));
        let mac = bignum::hmac(h, mk, auth_safe);
        if bignum::ct_eq_bytes(mac, pfx[di[1].off..di[1].end]) == 0 { return key, certs, ERR_BAD_SIGNATURE; }
    }
    let at, oka = asn1::parse(auth_safe);
    let infos, oki = asn1::children_of(auth_safe, at, asn1::SEQUENCE);
    if !oka || !oki { return key, certs, ERR_MALFORMED; }
    var nkeys = 0;
    for info in infos {
        let f, okf = asn1::children_of(auth_safe, info, asn1::SEQUENCE);
        if !okf || f.len != 2 || f[1].tag != asn1::ctx(0, true) { return key, certs, ERR_MALFORMED; }
        let inner, okin = asn1::explicit(auth_safe, f[1]);
        if !okin { return key, certs, ERR_MALFORMED; }
        if asn1::oid_is(auth_safe, f[0], OID_PKCS7_DATA) {
            if inner.tag != asn1::OCTET_STRING { return key, certs, ERR_MALFORMED; }
            let e = pkcs12_bags(auth_safe[inner.off..inner.end], password, key, nkeys, certs);
            if e != OK { return key, certs, e; }
        } else if asn1::oid_is(auth_safe, f[0], OID_PKCS7_ENCRYPTED) {
            // EncryptedData: SEQUENCE { version, EncryptedContentInfo {
            // contentType, algorithm, [0] IMPLICIT encryptedContent } }.
            let ed, oked = asn1::children_of(auth_safe, inner, asn1::SEQUENCE);
            if !oked || ed.len != 2 { return key, certs, ERR_MALFORMED; }
            let eci, okeci = asn1::children_of(auth_safe, ed[1], asn1::SEQUENCE);
            if !okeci || eci.len != 3 || eci[2].tag != asn1::ctx(0, false) { return key, certs, ERR_MALFORMED; }
            let pt, err = pkcs12_decrypt(auth_safe, eci[1], auth_safe[eci[2].off..eci[2].end], password);
            if err != OK { return key, certs, err; }
            let e = pkcs12_bags(pt, password, key, nkeys, certs);
            if e != OK { return key, certs, e; }
        } else {
            return key, certs, ERR_UNSUPPORTED_ALGORITHM;           // enveloped data
        }
    }
    if nkeys > 1 { return key, certs, ERR_MALFORMED; }
    return key, certs, OK;
}
