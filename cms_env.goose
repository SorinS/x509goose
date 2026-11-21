// x509.cms_env: CMS EnvelopedData (RFC 5652 §6) and AuthEnvelopedData
// (RFC 5083), as S/MIME (RFC 8551) encrypts a message to the
// certificates of its recipients.
//
// Made: a fresh content-encryption key, the content under it by AES-CBC
// (128 or 256; EnvelopedData) or AES-GCM (RFC 5084: a 12-byte nonce and a
// 16-byte tag; AuthEnvelopedData without authenticated attributes), and
// for each recipient a RecipientInfo that carries the key:
//
//   - an RSA certificate: KeyTransRecipientInfo, RSAES-OAEP with SHA-256
//     and MGF1-SHA-256 (RFC 8017, RFC 4055), or RSAES-PKCS1-v1_5 when
//     asked (what openssl sends by default);
//   - an EC certificate (P-256, P-384, P-521, brainpoolP256r1, P384r1,
//     P512r1): KeyAgreeRecipientInfo, ephemeral-static ECDH (RFC 5753),
//     the X9.63 KDF over SHA-256, -384 or -512 as the curve
//     (dhSinglePass-stdDH-sha256kdf-scheme and so on; openssl's default
//     is the SHA-1 one, which is read too), the key wrapped by AES key
//     wrap (RFC 3394) of the content key's size;
//   - an X448 certificate: KeyAgreeRecipientInfo by RFC 8418, the
//     originator's ephemeral key under id-X448, the X9.63 KDF over
//     SHA-512 (dhSinglePass-stdDH-sha512kdf-scheme), or HKDF-SHA512
//     (dhSinglePass-stdDH-hkdf-sha512-scheme) when asked, then AES key
//     wrap as for EC;
//   - an ML-KEM certificate (ML-KEM-512, -768, -1024; RFC 9935):
//     KEMRecipientInfo (RFC 9629) in an OtherRecipientInfo (id-ori-kem),
//     ML-KEM by RFC 9936: the shared secret through HKDF-SHA256 with
//     CMSORIforKEMOtherInfo as its info into a key-encryption key of the
//     content key's size, which AES-key-wraps it; a ukm when asked.
//
// Recipients are named by issuer and serial number, or by subject key
// identifier when asked. The EnvelopedData is version 0 when every
// RecipientInfo is version 0, 3 with an ML-KEM one, else 2;
// AuthEnvelopedData is version 0.
//
// Read: BER or DER (cms_der). The RecipientInfo for a given certificate,
// by issuer and serial or by key identifier, is found among those sent;
// key transport by OAEP (SHA-1, -256, -384 or -512, the label empty) or
// PKCS #1 v1.5, which is decrypted as Go's DecryptPKCS1v15SessionKey does
// (a malformed block gives a random key of the right length, not an
// error, so no padding oracle: the content then fails to decrypt); key
// agreement by ECDH or X448 with any of the X9.63 KDFs above or RFC
// 8418's HKDF ones (SHA-256, -384, -512: the ukm the salt), with or
// without a ukm;
// KEMRecipientInfo by ML-KEM with HKDF-SHA256, -384 or -512, with or
// without a ukm (other OtherRecipientInfo types are skipped).
// The content: AES-128, -192 or -256 in CBC (PKCS #7 padding, checked in
// constant time) or GCM (16-byte tags); cms_decrypt_legacy also takes
// DES-EDE3-CBC and single DES-CBC, as SCEP servers still send them (RFC
// 8894 §3.5.2), and cms_encrypt makes DES-EDE3-CBC when asked. Errors: ERR_MALFORMED,
// ERR_UNSUPPORTED_ALGORITHM, ERR_CMS_NOT_RECIPIENT (no RecipientInfo for
// the certificate) and ERR_CMS_DECRYPT (the key does not decrypt it, or
// the content does not: one error for every way, as much as can be).

namespace x509;

import std;
import x509;
import keys;
import cms;
import asn1;
import bignum;
import bignum.rsa;
import bignum.ec;
import bignum.x448;
import bignum.mlkem;
import bignum.aes;
import bignum.des;
import bignum.modes;
import bignum.gcm;
import bignum.keywrap;
import bignum.hmac;
import entropy;

let OID_CMS_ENVELOPED_DATA:      const u8[:] = "1.2.840.113549.1.7.3";
let OID_CMS_AUTH_ENVELOPED_DATA: const u8[:] = "1.2.840.113549.1.9.16.1.23";
let OID_RSAES_OAEP:              const u8[:] = "1.2.840.113549.1.1.7";
let OID_MGF1:                    const u8[:] = "1.2.840.113549.1.1.8";
let OID_P_SPECIFIED:             const u8[:] = "1.2.840.113549.1.1.9";
let OID_EC_PUBLIC_KEY:           const u8[:] = "1.2.840.10045.2.1";
let OID_ECDH_SHA1KDF:            const u8[:] = "1.3.133.16.840.63.0.2";
let OID_ECDH_SHA256KDF:          const u8[:] = "1.3.132.1.11.1";
let OID_ECDH_SHA384KDF:          const u8[:] = "1.3.132.1.11.2";
let OID_ECDH_SHA512KDF:          const u8[:] = "1.3.132.1.11.3";
let OID_ORI_KEM:                 const u8[:] = "1.2.840.113549.1.9.16.13.3";   // id-ori-kem (RFC 9629)
let OID_HKDF_SHA256:             const u8[:] = "1.2.840.113549.1.9.16.3.28";   // id-alg-hkdf-with-sha256 (RFC 8619)
let OID_HKDF_SHA384:             const u8[:] = "1.2.840.113549.1.9.16.3.29";
let OID_HKDF_SHA512:             const u8[:] = "1.2.840.113549.1.9.16.3.30";
let OID_X448:                    const u8[:] = "1.3.101.111";
let OID_ECDH_HKDF_SHA256:        const u8[:] = "1.2.840.113549.1.9.16.3.19";   // dhSinglePass-stdDH-hkdf-sha256-scheme (RFC 8418)
let OID_ECDH_HKDF_SHA384:        const u8[:] = "1.2.840.113549.1.9.16.3.20";
let OID_ECDH_HKDF_SHA512:        const u8[:] = "1.2.840.113549.1.9.16.3.21";

// Content-encryption algorithms.
let CMS_AES128_CBC: i64 = 1;
let CMS_AES192_CBC: i64 = 2;    // read only
let CMS_AES256_CBC: i64 = 3;
let CMS_AES128_GCM: i64 = 4;
let CMS_AES192_GCM: i64 = 5;    // read only
let CMS_AES256_GCM: i64 = 6;
let CMS_DES3_CBC:   i64 = 7;    // DES-EDE3-CBC: for SCEP servers without AES only; read by cms_decrypt_legacy
let CMS_DES_CBC:    i64 = 8;    // single DES-CBC: read only, by cms_decrypt_legacy

// Its errors are x509's, ERR_CMS_NOT_RECIPIENT and ERR_CMS_DECRYPT among them.
fn cms_error_text(e: i64) -> const u8[:] {
    return error_text(e);
}

// How cms_encrypt encrypts.
struct CmsEncryptOptions {
    cipher:    i64      = CMS_AES256_CBC, // CMS_AES128_CBC, CMS_AES256_CBC, CMS_AES128_GCM, CMS_AES256_GCM or CMS_DES3_CBC
    rsa_pkcs1: bool     = false,          // RSAES-PKCS1-v1_5 for RSA recipients in place of OAEP
    by_key_id: bool     = false,          // recipients named by subject key identifier, when they have one
    kem_ukm:   u8[..64] = [],             // user keying material for ML-KEM recipients (RFC 9629's ukm); none if empty
    x448_hkdf: bool     = false,          // HKDF-SHA512 for X448 recipients in place of the X9.63 KDF (RFC 8418)
    any_usage: bool     = false,          // encrypt to an RSA key whose key usage leaves out keyEncipherment (a SCEP CA's, RFC 8894 §2.2)
}

fn cms_cipher_oid(c: i64) -> const u8[:] {
    if c == CMS_AES128_CBC { return "2.16.840.1.101.3.4.1.2"; }
    if c == CMS_AES192_CBC { return "2.16.840.1.101.3.4.1.22"; }
    if c == CMS_AES256_CBC { return "2.16.840.1.101.3.4.1.42"; }
    if c == CMS_AES128_GCM { return "2.16.840.1.101.3.4.1.6"; }
    if c == CMS_AES192_GCM { return "2.16.840.1.101.3.4.1.26"; }
    if c == CMS_DES3_CBC { return "1.2.840.113549.3.7"; }
    if c == CMS_DES_CBC { return "1.3.14.3.2.7"; }
    return "2.16.840.1.101.3.4.1.46";
}

// The cipher a content-encryption OID names, or 0.
fn cms_cipher_of(d: const u8[:], t: asn1::Tlv) -> i64 {
    for c in [CMS_AES128_CBC, CMS_AES192_CBC, CMS_AES256_CBC, CMS_AES128_GCM, CMS_AES192_GCM, CMS_AES256_GCM] {
        if asn1::oid_is(d, t, cms_cipher_oid(c)) { return c; }
    }
    return 0;
}

fn cms_cipher_key_len(c: i64) -> i64 {
    if c == CMS_AES128_CBC || c == CMS_AES128_GCM { return 16; }
    if c == CMS_AES192_CBC || c == CMS_AES192_GCM { return 24; }
    if c == CMS_AES256_CBC || c == CMS_AES256_GCM { return 32; }
    if c == CMS_DES3_CBC { return 24; }
    if c == CMS_DES_CBC { return 8; }
    return 0;
}

// The block size of a CBC cipher: 8 for DES and DES-EDE3, else 16.
fn cms_cipher_block(c: i64) -> i64 { if c == CMS_DES3_CBC || c == CMS_DES_CBC { 8 } else { 16 } }

fn cms_cipher_gcm(c: i64) -> bool { c == CMS_AES128_GCM || c == CMS_AES192_GCM || c == CMS_AES256_GCM }

// The AES key wrap OID for a key-encryption key of n bytes (RFC 3565).
fn cms_wrap_oid(n: i64) -> const u8[:] {
    if n == 16 { return "2.16.840.1.101.3.4.1.5"; }
    if n == 24 { return "2.16.840.1.101.3.4.1.25"; }
    return "2.16.840.1.101.3.4.1.45";
}

// The key-encryption key length an AES key wrap AlgorithmIdentifier
// names (parameters absent), or 0.
fn cms_wrap_len_of(d: const u8[:], t: asn1::Tlv) -> i64 {
    let p, ok = asn1::children_of(d, t, asn1::SEQUENCE);
    if !ok || p.len != 1 { return 0; }
    for n in [16, 24, 32] { if asn1::oid_is(d, p[0], cms_wrap_oid(n)) { return n; } }
    return 0;
}

// The hash of an ECDH key agreement scheme OID (RFC 5753 §7.1.4), or 0,
// and whether the KDF is HKDF (RFC 8418 §2.2) rather than ANSI X9.63's.
fn cms_kdf_hash_of(d: const u8[:], t: asn1::Tlv) -> i64, bool {
    if asn1::oid_is(d, t, OID_ECDH_SHA1KDF) { return 160, false; }
    if asn1::oid_is(d, t, OID_ECDH_SHA256KDF) { return 256, false; }
    if asn1::oid_is(d, t, OID_ECDH_SHA384KDF) { return 384, false; }
    if asn1::oid_is(d, t, OID_ECDH_SHA512KDF) { return 512, false; }
    if asn1::oid_is(d, t, OID_ECDH_HKDF_SHA256) { return 256, true; }
    if asn1::oid_is(d, t, OID_ECDH_HKDF_SHA384) { return 384, true; }
    if asn1::oid_is(d, t, OID_ECDH_HKDF_SHA512) { return 512, true; }
    return 0, false;
}

// The key-encryption key of key agreement: X9.63's KDF over z and the
// shared info, or HKDF with the ukm as its salt (none without one).
fn cms_kari_kek(h: i64, hkdf: bool, z: const u8[:], ukm: const u8[:], info: const u8[:], n: i64) -> u8[>..] {
    if hkdf { return bignum::hkdf(h, ukm, z, info, n); }
    return cms_x963_kdf(h, z, info, n);
}

// The ANSI X9.63 KDF (SEC 1 §3.6.1): n bytes of
// H(z || counter || shared_info), the counter 32 bits from 1.
fn cms_x963_kdf(h: i64, z: const u8[:], shared_info: const u8[:], n: i64) -> u8[>..] {
    var out:     u8[>..] = [];
    var counter: i64     = 1;
    while out.len < n {
        var zc: u8[>..] = [];
        zc.append(z);
        for i in 4 { zc.push(((counter >> (24 - 8 * i)) & 0xff) as! u8); }
        out.append(bignum::hash2(h, zc, shared_info));
        counter++;
    }
    out.resize(n);
    return out;
}

// ECC-CMS-SharedInfo (RFC 5753 §7.2): the key wrap's AlgorithmIdentifier
// (as sent), the ukm if there is one, and the key-encryption key's length
// in bits.
fn cms_shared_info(wrap_alg: const u8[:], ukm: const u8[:], has_ukm: bool, kek_len: i64) -> u8[>..] {
    var body: u8[>..] = [];
    body.append(wrap_alg);
    if has_ukm {
        var u: u8[>..] = [];
        asn1::put_octets(u, ukm);
        asn1::put(body, asn1::ctx(0, true), u);
    }
    var bits: u8[4] = [0; 4];
    let nbits = kek_len * 8;
    for i in 4 { bits[i] = ((nbits >> (24 - 8 * i)) & 0xff) as! u8; }
    var s: u8[>..] = [];
    asn1::put_octets(s, bits);
    asn1::put(body, asn1::ctx(2, true), s);
    var out: u8[>..] = [];
    asn1::put(out, asn1::SEQUENCE, body);
    return out;
}

// The hash of an HKDF AlgorithmIdentifier (RFC 8619, parameters absent),
// or 0.
fn cms_hkdf_hash_of(d: const u8[:], t: asn1::Tlv) -> i64 {
    let p, ok = asn1::children_of(d, t, asn1::SEQUENCE);
    if !ok || p.len != 1 { return 0; }
    if asn1::oid_is(d, p[0], OID_HKDF_SHA256) { return 256; }
    if asn1::oid_is(d, p[0], OID_HKDF_SHA384) { return 384; }
    if asn1::oid_is(d, p[0], OID_HKDF_SHA512) { return 512; }
    return 0;
}

// CMSORIforKEMOtherInfo (RFC 9629 §5), the KDF's info: the key wrap's
// AlgorithmIdentifier (as sent), the key-encryption key's length in
// bytes, and the ukm if there is one.
fn cms_kem_other_info(wrap_alg: const u8[:], kek_len: i64, ukm: const u8[:], has_ukm: bool) -> u8[>..] {
    var body: u8[>..] = [];
    body.append(wrap_alg);
    asn1::put_i64(body, kek_len);
    if has_ukm {
        var u: u8[>..] = [];
        asn1::put_octets(u, ukm);
        asn1::put(body, asn1::ctx(0, true), u);
    }
    var out: u8[>..] = [];
    asn1::put(out, asn1::SEQUENCE, body);
    return out;
}

// A ContentInfo of the given type around a structure's DER.
fn cms_wrap(oid: const u8[:], inner: const u8[:]) -> u8[>..] {
    var body: u8[>..] = [];
    asn1::put_oid(body, oid);
    asn1::put(body, asn1::ctx(0, true), inner);
    var out: u8[>..] = [];
    asn1::put(out, asn1::SEQUENCE, body);
    return out;
}

// The content type (a dotted OID) of a ContentInfo, BER or DER: what it
// holds (OID_CMS_SIGNED_DATA, OID_CMS_ENVELOPED_DATA, ...); empty if it
// does not parse.
fn cms_content_type(ber: const u8[:]) -> u8[>..] {
    var none: u8[>..] = [];
    let d, ok = cms_der(ber);
    if !ok { return none; }
    let top, okt = asn1::parse(d);
    let ci, okc = asn1::children_of(d, top, asn1::SEQUENCE);
    if !okt || !okc || ci.len < 1 || ci[0].tag != asn1::OID { return none; }
    let s, oks = asn1::read_oid(d, ci[0]);
    if !oks { return none; }
    return s;
}

// --- Encrypting ---------------------------------------------------------------

// The recipient identifier: issuer and serial (version 0 for key
// transport), or the key identifier when asked and the certificate has
// one ([0], primitive for key transport, a RecipientKeyIdentifier for key
// agreement). Whether it is the key identifier.
fn cms_put_rid(out: u8[>..]&, rc: const Cert&, by_key_id: bool, agree: bool) -> bool {
    let d = rc.der[..];
    if by_key_id && rc.ski.end > rc.ski.start {
        let ski = d[rc.ski.off..rc.ski.end];
        if agree {
            var rk: u8[>..] = [];
            asn1::put_octets(rk, ski);
            asn1::put(out, asn1::ctx(0, true), rk);
        } else {
            asn1::put(out, asn1::ctx(0, false), ski);
        }
        return true;
    }
    var ias: u8[>..] = [];
    ias.append(d[rc.issuer.start..rc.issuer.end]);
    ias.append(d[rc.serial.start..rc.serial.end]);
    asn1::put(out, asn1::SEQUENCE, ias);
    return false;
}

// The AlgorithmIdentifier of a SHA-2 hash, its parameters absent.
fn cms_hash_alg_id(out: u8[>..]&, h: i64) {
    var b: u8[>..] = [];
    asn1::put_oid(b, hash_oid(h));
    asn1::put(out, asn1::SEQUENCE, b);
}

// A RecipientInfo for certificate rc carrying cek, appended to out, and
// the EnvelopedData version it asks for (RFC 5652 §6.1): 0, 2 (key
// agreement, or a key identifier) or 3 (an OtherRecipientInfo).
// ERR_KEY_USAGE when the certificate's key usage forbids it,
// ERR_UNSUPPORTED_ALGORITHM for a key that cannot encrypt.
fn cms_recipient_info(out: u8[>..]&, rc: const Cert&, cek: const u8[:], o: const CmsEncryptOptions&) -> i64, i64 {
    let d = rc.der[..];
    let kb, okk = key_bytes(d, rc.key);
    if !okk { return 0, ERR_MALFORMED; }
    if is_mlkem(rc.key_type) {
        // KEMRecipientInfo (RFC 9629) in an OtherRecipientInfo, ML-KEM by
        // RFC 9936: HKDF-SHA256 and AES key wrap of the content key's size
        // (as openssl does), the ukm when one is given.
        if rc.has_key_usage && rc.key_usage & KU_KEY_ENCIPHERMENT == 0 { return 0, ERR_KEY_USAGE; }
        let n = mlkem_k(rc.key_type);
        let ss, kemct, oke = bignum::mlkem_encaps(n, kb);
        if !oke { return 0, ERR_MALFORMED; }
        var wrap: u8[>..] = [];
        var wb:   u8[>..] = [];
        asn1::put_oid(wb, cms_wrap_oid(cek.len));
        asn1::put(wrap, asn1::SEQUENCE, wb);
        let has_ukm = o.kem_ukm.len > 0;
        let kek = bignum::hkdf(256, "", ss, cms_kem_other_info(wrap, cek.len, o.kem_ukm, has_ukm), cek.len);
        let ek, okw = bignum::aes_key_wrap(kek, cek);
        assert(okw);
        var kri: u8[>..] = [];
        asn1::put_i64(kri, 0);
        let kid = cms_put_rid(kri, rc, o.by_key_id, false);
        var kem: u8[>..] = [];
        asn1::put_oid(kem, mlkem_oid(n));
        asn1::put(kri, asn1::SEQUENCE, kem);
        asn1::put_octets(kri, kemct);
        var kdf: u8[>..] = [];
        asn1::put_oid(kdf, OID_HKDF_SHA256);
        asn1::put(kri, asn1::SEQUENCE, kdf);
        asn1::put_i64(kri, cek.len);
        if has_ukm {
            var u: u8[>..] = [];
            asn1::put_octets(u, o.kem_ukm);
            asn1::put(kri, asn1::ctx(0, true), u);
        }
        kri.append(wrap);
        asn1::put_octets(kri, ek);
        var ori: u8[>..] = [];
        asn1::put_oid(ori, OID_ORI_KEM);
        asn1::put(ori, asn1::SEQUENCE, kri);
        asn1::put(out, asn1::ctx(4, true), ori);
        return 3, OK;
    }
    if rc.key_type == KEY_RSA {
        if rc.has_key_usage && rc.key_usage & KU_KEY_ENCIPHERMENT == 0 && !o.any_usage { return 0, ERR_KEY_USAGE; }
        let pub, okp = rsa_public_key(rc);
        if !okp || bignum::rsa_oaep_max(pub, 256) < cek.len { return 0, ERR_UNSUPPORTED_ALGORITHM; }
        var ri:  u8[>..] = [];
        var rid: u8[>..] = [];
        let v2 = cms_put_rid(rid, rc, o.by_key_id, false);
        asn1::put_i64(ri, if v2 { 2 } else { 0 });
        ri.append(rid);
        var alg: u8[>..] = [];
        if o.rsa_pkcs1 {
            asn1::put_oid(alg, OID_RSA_ENCRYPTION);
            asn1::put_null(alg);
        } else {
            // RSAES-OAEP-params: SHA-256, MGF1 with SHA-256, the label empty
            // (the default pSourceAlgorithm, left out).
            asn1::put_oid(alg, OID_RSAES_OAEP);
            var params: u8[>..] = [];
            var hid:    u8[>..] = [];
            cms_hash_alg_id(hid, 256);
            asn1::put(params, asn1::ctx(0, true), hid);
            var mgf: u8[>..] = [];
            asn1::put_oid(mgf, OID_MGF1);
            mgf.append(hid);
            var mgfs: u8[>..] = [];
            asn1::put(mgfs, asn1::SEQUENCE, mgf);
            asn1::put(params, asn1::ctx(1, true), mgfs);
            asn1::put(alg, asn1::SEQUENCE, params);
        }
        asn1::put(ri, asn1::SEQUENCE, alg);
        let ek = if o.rsa_pkcs1 { bignum::rsa_encrypt_pkcs1(pub, cek) } else { bignum::rsa_encrypt_oaep(pub, cek, "", 256) };
        asn1::put_octets(ri, ek);
        asn1::put(out, asn1::SEQUENCE, ri);
        return if v2 { 2 } else { 0 }, OK;
    }
    let x448 = rc.key_type == KEY_X448;
    if (is_ec(rc.key_type) && rc.key_type != KEY_EC_P224) || x448 {
        if rc.has_key_usage && rc.key_usage & KU_KEY_AGREEMENT == 0 { return 0, ERR_KEY_USAGE; }
        let h = if x448 { 512 } else { ec_hash_of_key(rc.key_type) };
        let hkdf = x448 && o.x448_hkdf;
        var epk: u8[>..] = [];
        var z:   u8[>..] = [];
        if x448 {
            if kb.len != 56 { return 0, ERR_MALFORMED; }
            let esk, xpk = bignum::x448_keypair();
            let zx, okz = bignum::x448_shared(esk, kb);
            if !okz { return 0, ERR_MALFORMED; }
            epk.append(xpk);
            z.append(zx);
        } else {
            let curve = curve_of_key(rc.key_type);
            let esk, ecpk = bignum::ec_keypair(curve);
            let ze, okz = bignum::ecdh_shared(curve, esk, kb);
            if !okz { return 0, ERR_MALFORMED; }
            epk.append(ecpk);
            z.append(ze);
        }
        var wrap: u8[>..] = [];
        var wb:   u8[>..] = [];
        asn1::put_oid(wb, cms_wrap_oid(cek.len));
        asn1::put(wrap, asn1::SEQUENCE, wb);
        let kek = cms_kari_kek(h, hkdf, z, "", cms_shared_info(wrap, "", false, cek.len), cek.len);
        let ek, okw = bignum::aes_key_wrap(kek, cek);
        assert(okw);
        var kari: u8[>..] = [];
        asn1::put_i64(kari, 3);
        // originator [0]: originatorKey [1], id-ecPublicKey without the
        // curve (as openssl writes it; the recipient knows it) and the
        // point, or id-X448 (parameters absent) and its 56 bytes.
        var opk:  u8[>..] = [];
        var ealg: u8[>..] = [];
        asn1::put_oid(ealg, if x448 { OID_X448 } else { OID_EC_PUBLIC_KEY });
        asn1::put(opk, asn1::SEQUENCE, ealg);
        asn1::put_bits(opk, epk);
        var orig: u8[>..] = [];
        asn1::put(orig, asn1::ctx(1, true), opk);
        asn1::put(kari, asn1::ctx(0, true), orig);
        var kea: u8[>..] = [];
        asn1::put_oid(kea, if hkdf { OID_ECDH_HKDF_SHA512 } else if h == 384 { OID_ECDH_SHA384KDF }
                           else if h == 512 { OID_ECDH_SHA512KDF } else { OID_ECDH_SHA256KDF });
        kea.append(wrap);
        asn1::put(kari, asn1::SEQUENCE, kea);
        var rek: u8[>..] = [];
        let v = cms_put_rid(rek, rc, o.by_key_id, true);
        asn1::put_octets(rek, ek);
        var reks: u8[>..] = [];
        asn1::put(reks, asn1::SEQUENCE, rek);
        asn1::put(kari, asn1::SEQUENCE, reks);
        asn1::put(out, asn1::ctx(1, true), kari);
        return 2, OK;
    }
    return 0, ERR_UNSUPPORTED_ALGORITHM;
}

// A ContentInfo holding `content` (of type content_type, a dotted OID)
// encrypted to each of `recipients` (certificates, DER laid end to end):
// an EnvelopedData for a CBC cipher, an AuthEnvelopedData for GCM. Returns
// it and OK, or ERR_MALFORMED (a certificate that does not parse, or
// none), ERR_KEY_USAGE or ERR_UNSUPPORTED_ALGORITHM (a recipient's key
// cannot be encrypted to).
fn cms_encrypt(content_type: const u8[:], content: const u8[:], recipients: const u8[:],
               o: const CmsEncryptOptions&) -> u8[>..], i64 {
    var out: u8[>..] = [];
    let c = o.cipher;
    if c != CMS_AES128_CBC && c != CMS_AES256_CBC && c != CMS_AES128_GCM && c != CMS_AES256_GCM && c != CMS_DES3_CBC {
        return out, ERR_UNSUPPORTED_ALGORITHM;
    }
    var cek: u8[>..] = [];
    cek.resize(cms_cipher_key_len(c), 0);
    entropy::random_bytes(cek);
    var ris:     u8[>..] = [];
    var version: i64     = 0;
    var n = 0;
    var at = 0;
    while at < recipients.len {
        let t, okt = asn1::read(recipients, at, recipients.len);
        if !okt { return out, ERR_MALFORMED; }
        at = t.end;
        let rc, e = parse(recipients[t.start..t.end]);
        if e != OK { return out, e; }
        let v, er = cms_recipient_info(ris, rc, cek, o);
        if er != OK { return out, er; }
        if v > version { version = v; }
        n++;
    }
    if n == 0 { return out, ERR_MALFORMED; }
    var body: u8[>..] = [];
    let gcm = cms_cipher_gcm(c);
    asn1::put_i64(body, if gcm { 0 } else { version });
    cms_set_of(body, ris);
    var eci: u8[>..] = [];
    asn1::put_oid(eci, content_type);
    var alg: u8[>..] = [];
    asn1::put_oid(alg, cms_cipher_oid(c));
    var ct:  u8[>..] = [];
    var tag: u8[>..] = [];
    if gcm {
        // GCMParameters: the nonce and the tag length, 16 (as openssl writes).
        var nonce: u8[12] = [0; 12];
        entropy::random_bytes(nonce);
        var gp: u8[>..] = [];
        asn1::put_octets(gp, nonce);
        asn1::put_i64(gp, 16);
        asn1::put(alg, asn1::SEQUENCE, gp);
        let sealed = bignum::aes_gcm_seal(cek, nonce, "", content);
        ct.append(sealed[..sealed.len - 16]);
        tag.append(sealed[sealed.len - 16..]);
    } else if c == CMS_DES3_CBC {
        var iv: u8[8] = [0; 8];
        entropy::random_bytes(iv);
        asn1::put_octets(alg, iv);
        ct = bignum::pkcs7_pad(content, 8);
        let k = bignum::des3_init(cek);
        bignum::cbc_encrypt(k, iv, ct);
    } else {
        var iv: u8[16] = [0; 16];
        entropy::random_bytes(iv);
        asn1::put_octets(alg, iv);
        ct = bignum::pkcs7_pad(content, 16);
        let k = bignum::aes_init(cek);
        bignum::cbc_encrypt(k, iv, ct);
    }
    asn1::put(eci, asn1::SEQUENCE, alg);
    asn1::put(eci, asn1::ctx(0, false), ct);
    asn1::put(body, asn1::SEQUENCE, eci);
    if gcm { asn1::put_octets(body, tag); }
    var sq: u8[>..] = [];
    asn1::put(sq, asn1::SEQUENCE, body);
    return cms_wrap(if gcm { OID_CMS_AUTH_ENVELOPED_DATA } else { OID_CMS_ENVELOPED_DATA }, sq), OK;
}

// --- Decrypting ---------------------------------------------------------------

// The hash of RSAES-OAEP-params (RFC 8017 A.2.1): 160 when absent (every
// default), the hash with MGF1 over the same hash and an empty label, or
// 0 for anything else.
fn cms_oaep_hash(d: const u8[:], sp: const asn1::Tlv[:]) -> i64 {
    if sp.len == 1 { return 160; }
    if sp.len != 2 { return 0; }
    let f, ok = asn1::children_of(d, sp[1], asn1::SEQUENCE);
    if !ok { return 0; }
    var h:    i64 = 160;
    var mh:   i64 = 160;
    var last: i64 = -1;
    for x in f {
        if x.cls != asn1::CLASS_CONTEXT || !x.constructed || x.number <= last { return 0; }
        last = x.number;
        let inner, oki = asn1::explicit(d, x);
        if !oki { return 0; }
        if x.number == 0 {
            h = cms_digest_of(d, inner);
        } else if x.number == 1 {
            let m, okm = asn1::children_of(d, inner, asn1::SEQUENCE);
            if !okm || m.len != 2 || !asn1::oid_is(d, m[0], OID_MGF1) { return 0; }
            mh = cms_digest_of(d, m[1]);
        } else if x.number == 2 {
            let s, oks = asn1::children_of(d, inner, asn1::SEQUENCE);
            if !oks || s.len < 1 || s.len > 2 || !asn1::oid_is(d, s[0], OID_P_SPECIFIED) { return 0; }
            if s.len == 2 && (s[1].tag != asn1::OCTET_STRING || asn1::content_len(s[1]) != 0) { return 0; }
        } else {
            return 0;
        }
    }
    if h == 0 || mh != h { return 0; }
    return h;
}

// Whether a KeyAgreeRecipientIdentifier names certificate c.
fn cms_kari_rid_matches(d: const u8[:], rid: asn1::Tlv, c: const Cert&) -> bool {
    if rid.tag == asn1::SEQUENCE { return cms_sid_matches(d, rid, c); }
    if rid.tag != asn1::ctx(0, true) { return false; }
    let p, ok = asn1::children(d, rid);
    if !ok || p.len < 1 || p[0].tag != asn1::OCTET_STRING { return false; }
    let cd = c.der[..];
    return c.ski.end > c.ski.start && d[p[0].off..p[0].end] == cd[c.ski.off..c.ski.end];
}

// The content-encryption key (kl bytes) from the RecipientInfo for cert,
// decrypted with key.
fn cms_recover_cek(d: const u8[:], ris: asn1::Tlv, key: const PrivateKey&, cert: const Cert&,
                   kl: i64) -> u8[>..], i64 {
    var none: u8[>..] = [];
    let list, ok = asn1::children(d, ris);
    if !ok { return none, ERR_MALFORMED; }
    for r in list {
        if r.tag == asn1::SEQUENCE {
            // KeyTransRecipientInfo: version, rid, algorithm, encryptedKey.
            let p, okp = asn1::children(d, r);
            if !okp || p.len != 4 || p[3].tag != asn1::OCTET_STRING { return none, ERR_MALFORMED; }
            if !cms_sid_matches(d, p[1], cert) { continue; }
            if key.kind != KEY_RSA { return none, ERR_CMS_DECRYPT; }
            let ek = d[p[3].off..p[3].end];
            let sp, oks = asn1::children_of(d, p[2], asn1::SEQUENCE);
            if !oks || sp.len < 1 { return none, ERR_MALFORMED; }
            if asn1::oid_is(d, sp[0], OID_RSA_ENCRYPTION) && (sp.len == 1 || (sp.len == 2 && asn1::read_null(d, sp[1]))) {
                // A random key unless the block holds one of kl bytes.
                var cek: u8[>..] = [];
                cek.resize(kl, 0);
                entropy::random_bytes(cek);
                if !bignum::rsa_decrypt_pkcs1_session_key(key.rsa, ek, cek) { return none, ERR_CMS_DECRYPT; }
                return cek, OK;
            }
            if asn1::oid_is(d, sp[0], OID_RSAES_OAEP) {
                let h = cms_oaep_hash(d, sp);
                if h == 0 { return none, ERR_UNSUPPORTED_ALGORITHM; }
                let cek, okc = bignum::rsa_decrypt_oaep(key.rsa, ek, "", h);
                if !okc || cek.len != kl { return none, ERR_CMS_DECRYPT; }
                return cek, OK;
            }
            return none, ERR_UNSUPPORTED_ALGORITHM;
        }
        if r.tag == asn1::ctx(4, true) {
            // OtherRecipientInfo: a KEMRecipientInfo (RFC 9629) is the one read.
            let ori, oko = asn1::children(d, r);
            if !oko || ori.len != 2 || ori[0].tag != asn1::OID { return none, ERR_MALFORMED; }
            if !asn1::oid_is(d, ori[0], OID_ORI_KEM) { continue; }
            let cek, ek = cms_kem_cek(d, ori[1], key, cert, kl);
            if ek == ERR_CMS_NOT_RECIPIENT { continue; }
            return cek, ek;
        }
        if r.tag != asn1::ctx(1, true) { continue; }   // kekri, pwri: not for a certificate
        // KeyAgreeRecipientInfo: version, originator, ukm?, algorithm, recipientEncryptedKeys.
        let p, okp = asn1::children(d, r);
        if !okp || p.len < 4 || p.len > 5 || p[1].tag != asn1::ctx(0, true) { return none, ERR_MALFORMED; }
        let has_ukm = p.len == 5;
        if has_ukm && p[2].tag != asn1::ctx(1, true) { return none, ERR_MALFORMED; }
        let reks, okr = asn1::children_of(d, p[p.len - 1], asn1::SEQUENCE);
        if !okr { return none, ERR_MALFORMED; }
        var found = false;
        var ek = asn1::Tlv { tag: 0, cls: 0, constructed: false, number: 0, start: 0, off: 0, end: 0 };
        for rek in reks {
            let q, okq = asn1::children_of(d, rek, asn1::SEQUENCE);
            if !okq || q.len != 2 || q[1].tag != asn1::OCTET_STRING { return none, ERR_MALFORMED; }
            if !found && cms_kari_rid_matches(d, q[0], cert) { found = true; ek = q[1]; }
        }
        if !found { continue; }
        let x448 = key.kind == KEY_X448;
        if (!is_ec(key.kind) || key.kind == KEY_EC_P224) && !x448 { return none, ERR_CMS_DECRYPT; }
        // The originator's ephemeral key: originatorKey [1] only.
        let orig, oko = asn1::explicit(d, p[1]);
        if !oko || orig.tag != asn1::ctx(1, true) { return none, ERR_UNSUPPORTED_ALGORITHM; }
        let ok2, oko2 = asn1::children(d, orig);
        if !oko2 || ok2.len != 2 { return none, ERR_MALFORMED; }
        let oa, okoa = asn1::children_of(d, ok2[0], asn1::SEQUENCE);
        if !okoa || oa.len < 1 || oa.len > 2 { return none, ERR_UNSUPPORTED_ALGORITHM; }
        if x448 {
            if oa.len != 1 || !asn1::oid_is(d, oa[0], OID_X448) { return none, ERR_CMS_DECRYPT; }
        } else {
            if !asn1::oid_is(d, oa[0], OID_EC_PUBLIC_KEY) { return none, ERR_UNSUPPORTED_ALGORITHM; }
            if oa.len == 2 && !asn1::read_null(d, oa[1]) && !asn1::oid_is(d, oa[1], curve_oid(key.kind)) {
                return none, ERR_CMS_DECRYPT;
            }
        }
        let epk, oke = key_bytes(d, ok2[1]);
        if !oke { return none, ERR_MALFORMED; }
        var ukm: u8[>..] = [];
        if has_ukm {
            let u, oku = asn1::explicit(d, p[2]);
            if !oku || u.tag != asn1::OCTET_STRING { return none, ERR_MALFORMED; }
            ukm.append(d[u.off..u.end]);
        }
        let kea, okk = asn1::children_of(d, p[p.len - 2], asn1::SEQUENCE);
        if !okk || kea.len != 2 { return none, ERR_MALFORMED; }
        let h, hkdf = cms_kdf_hash_of(d, kea[0]);
        let kek_len = cms_wrap_len_of(d, kea[1]);
        if h == 0 || kek_len == 0 { return none, ERR_UNSUPPORTED_ALGORITHM; }
        var z: u8[>..] = [];
        if x448 {
            if epk.len != 56 { return none, ERR_CMS_DECRYPT; }
            let zx, okz = bignum::x448_shared(key.key448, epk);
            if !okz { return none, ERR_CMS_DECRYPT; }
            z.append(zx);
        } else {
            let curve = curve_of_key(key.kind);
            let ze, okz = bignum::ecdh_shared(curve, key.ec_sk, epk);
            if !okz { return none, ERR_CMS_DECRYPT; }
            z.append(ze);
        }
        let info = cms_shared_info(d[kea[1].start..kea[1].end], ukm, has_ukm, kek_len);
        let kek = cms_kari_kek(h, hkdf, z, ukm, info, kek_len);
        let cek, okw = bignum::aes_key_unwrap(kek, d[ek.off..ek.end]);
        if !okw || cek.len != kl { return none, ERR_CMS_DECRYPT; }
        return cek, OK;
    }
    return none, ERR_CMS_NOT_RECIPIENT;
}

// The content-encryption key (kl bytes) from a KEMRecipientInfo, or
// ERR_CMS_NOT_RECIPIENT when it is not for cert.
fn cms_kem_cek(d: const u8[:], t: asn1::Tlv, key: const PrivateKey&, cert: const Cert&, kl: i64) -> u8[>..], i64 {
    var none: u8[>..] = [];
    // version, rid, kem, kemct, kdf, kekLength, [0] ukm?, wrap, encryptedKey.
    let p, ok = asn1::children_of(d, t, asn1::SEQUENCE);
    if !ok || p.len < 8 || p.len > 9 { return none, ERR_MALFORMED; }
    let version, okv = asn1::read_i64(d, p[0]);
    if !okv || version != 0 || p[3].tag != asn1::OCTET_STRING || p[p.len - 1].tag != asn1::OCTET_STRING {
        return none, ERR_MALFORMED;
    }
    let has_ukm = p.len == 9;
    if has_ukm && p[6].tag != asn1::ctx(0, true) { return none, ERR_MALFORMED; }
    if !cms_sid_matches(d, p[1], cert) { return none, ERR_CMS_NOT_RECIPIENT; }
    if !is_mlkem(key.kind) || key.kind != cert.key_type { return none, ERR_CMS_DECRYPT; }
    let n = mlkem_k(key.kind);
    let kem, okk = asn1::children_of(d, p[2], asn1::SEQUENCE);
    if !okk || kem.len != 1 || mlkem_k_of_oid(d, kem[0]) != n { return none, ERR_UNSUPPORTED_ALGORITHM; }
    let h = cms_hkdf_hash_of(d, p[4]);
    let kek_len, okl = asn1::read_i64(d, p[5]);
    let wrap = p[p.len - 2];
    let wl = cms_wrap_len_of(d, wrap);
    if h == 0 || wl == 0 { return none, ERR_UNSUPPORTED_ALGORITHM; }
    if !okl || kek_len != wl { return none, ERR_MALFORMED; }
    var ukm: u8[>..] = [];
    if has_ukm {
        let u, oku = asn1::explicit(d, p[6]);
        if !oku || u.tag != asn1::OCTET_STRING { return none, ERR_MALFORMED; }
        ukm.append(d[u.off..u.end]);
    }
    // Decapsulation never fails on a wrong ciphertext (implicit rejection):
    // the wrong key fails the key unwrap.
    let ss, okd = bignum::mlkem_decaps_dk(n, key.kem_dk, d[p[3].off..p[3].end]);
    if !okd { return none, ERR_CMS_DECRYPT; }
    let kek = bignum::hkdf(h, "", ss, cms_kem_other_info(d[wrap.start..wrap.end], kek_len, ukm, has_ukm), kek_len);
    let cek, okw = bignum::aes_key_unwrap(kek, d[p[p.len - 1].off..p[p.len - 1].end]);
    if !okw || cek.len != kl { return none, ERR_CMS_DECRYPT; }
    return cek, OK;
}

// Decrypts a ContentInfo holding an EnvelopedData or AuthEnvelopedData
// (BER or DER) with `key`, whose certificate is `cert`. Returns the
// content, its type (a dotted OID) and OK; or ERR_MALFORMED,
// ERR_UNSUPPORTED_ALGORITHM, ERR_CMS_NOT_RECIPIENT or ERR_CMS_DECRYPT.
fn cms_decrypt(ber: const u8[:], key: const PrivateKey&, cert: const Cert&) -> u8[>..], u8[>..], i64 {
    let pt, ctype, e = cms_decrypt_with(ber, key, cert, false);
    return pt, ctype, e;
}

// cms_decrypt that also takes content under DES-EDE3-CBC or single
// DES-CBC (what SCEP servers built on Go's pkcs7 send by default). Only for
// protocols that still need them: neither is fit to keep a secret.
fn cms_decrypt_legacy(ber: const u8[:], key: const PrivateKey&, cert: const Cert&) -> u8[>..], u8[>..], i64 {
    let pt, ctype, e = cms_decrypt_with(ber, key, cert, true);
    return pt, ctype, e;
}

fn cms_decrypt_with(ber: const u8[:], key: const PrivateKey&, cert: const Cert&, legacy: bool) -> u8[>..], u8[>..], i64 {
    var none:  u8[>..] = [];
    var none2: u8[>..] = [];
    let d, okd = cms_der(ber);
    if !okd { return none, none2, ERR_MALFORMED; }
    let top, ok = asn1::parse(d);
    let ci, okc = asn1::children_of(d, top, asn1::SEQUENCE);
    if !ok || !okc || ci.len != 2 || ci[1].tag != asn1::ctx(0, true) { return none, none2, ERR_MALFORMED; }
    let auth = asn1::oid_is(d, ci[0], OID_CMS_AUTH_ENVELOPED_DATA);
    if !auth && !asn1::oid_is(d, ci[0], OID_CMS_ENVELOPED_DATA) { return none, none2, ERR_MALFORMED; }
    let inner, oki = asn1::explicit(d, ci[1]);
    if !oki { return none, none2, ERR_MALFORMED; }
    let f, okf = asn1::children_of(d, inner, asn1::SEQUENCE);
    if !okf || f.len < 3 { return none, none2, ERR_MALFORMED; }
    let version, okv = asn1::read_i64(d, f[0]);
    if !okv || version < 0 || version > 4 { return none, none2, ERR_MALFORMED; }
    var i = 1;
    if f[i].tag == asn1::ctx(0, true) { i++; }                 // originatorInfo: not used
    if i + 1 >= f.len || f[i].tag != asn1::SET { return none, none2, ERR_MALFORMED; }
    let ris = f[i];
    let eci = f[i + 1];
    i += 2;
    // AuthEnvelopedData: [1] authAttrs?, mac, [2] unauthAttrs?.
    var has_aa = false;
    var aa = eci;
    var mac = eci;
    if auth {
        if i < f.len && f[i].tag == asn1::ctx(1, true) { has_aa = true; aa = f[i]; i++; }
        if i >= f.len || f[i].tag != asn1::OCTET_STRING { return none, none2, ERR_MALFORMED; }
        mac = f[i];
        i++;
        if i < f.len && f[i].tag == asn1::ctx(2, true) { i++; }
    } else if i < f.len && f[i].tag == asn1::ctx(1, true) {
        i++;                                                    // unprotectedAttrs
    }
    if i != f.len { return none, none2, ERR_MALFORMED; }

    // EncryptedContentInfo: the type, the algorithm, [0] the ciphertext.
    let e, oke = asn1::children_of(d, eci, asn1::SEQUENCE);
    if !oke || e.len != 3 || e[0].tag != asn1::OID || e[2].number != 0 || e[2].cls != asn1::CLASS_CONTEXT {
        return none, none2, ERR_MALFORMED;          // no ciphertext: detached, not handled
    }
    let ctype, okt = asn1::read_oid(d, e[0]);
    if !okt { return none, none2, ERR_MALFORMED; }
    let alg, oka = asn1::children_of(d, e[1], asn1::SEQUENCE);
    if !oka || alg.len != 2 { return none, none2, ERR_MALFORMED; }
    var cipher = cms_cipher_of(d, alg[0]);
    if cipher == 0 && legacy && asn1::oid_is(d, alg[0], cms_cipher_oid(CMS_DES3_CBC)) { cipher = CMS_DES3_CBC; }
    if cipher == 0 && legacy && asn1::oid_is(d, alg[0], cms_cipher_oid(CMS_DES_CBC)) { cipher = CMS_DES_CBC; }
    if cipher == 0 || cms_cipher_gcm(cipher) != auth { return none, none2, ERR_UNSUPPORTED_ALGORITHM; }
    let ct, okct = cms_octets(d, e[2]);
    if !okct { return none, none2, ERR_MALFORMED; }

    let cek, er = cms_recover_cek(d, ris, key, cert, cms_cipher_key_len(cipher));
    if er != OK { return none, none2, er; }

    if auth {
        // GCMParameters: the nonce, the tag length (12 by default; 16 only here).
        let gp, okg = asn1::children_of(d, alg[1], asn1::SEQUENCE);
        if !okg || gp.len < 1 || gp.len > 2 || gp[0].tag != asn1::OCTET_STRING || asn1::content_len(gp[0]) == 0 {
            return none, none2, ERR_MALFORMED;
        }
        var icv: i64 = 12;
        if gp.len == 2 {
            let v, okiv = asn1::read_i64(d, gp[1]);
            if !okiv { return none, none2, ERR_MALFORMED; }
            icv = v;
        }
        if icv != 16 || asn1::content_len(mac) != 16 { return none, none2, ERR_UNSUPPORTED_ALGORITHM; }
        // The authenticated attributes, if any, are the additional data,
        // DER with the SET OF tag (RFC 5083 §2.2).
        var aad: u8[>..] = [];
        if has_aa {
            aad.append(d[aa.start..aa.end]);
            aad[0] = asn1::SET as! u8;
        }
        var sealed: u8[>..] = [];
        sealed.append(ct);
        sealed.append(d[mac.off..mac.end]);
        let pt, okp = bignum::aes_gcm_open(cek, d[gp[0].off..gp[0].end], aad, sealed);
        if !okp { return none, none2, ERR_CMS_DECRYPT; }
        return pt, ctype, OK;
    }
    let bs = cms_cipher_block(cipher);
    if alg[1].tag != asn1::OCTET_STRING || asn1::content_len(alg[1]) != bs { return none, none2, ERR_MALFORMED; }
    if ct.len == 0 || ct.len % bs != 0 { return none, none2, ERR_CMS_DECRYPT; }
    var buf: u8[>..] = [];
    buf.append(ct);
    let iv = d[alg[1].off..alg[1].end];
    if cipher == CMS_DES3_CBC {
        let k = bignum::des3_init(cek);
        bignum::cbc_decrypt(k, iv, buf);
    } else if cipher == CMS_DES_CBC {
        let k = bignum::des_init(cek);
        bignum::cbc_decrypt(k, iv, buf);
    } else {
        let k = bignum::aes_init(cek);
        bignum::cbc_decrypt(k, iv, buf);
    }
    let pt, okp = bignum::pkcs7_unpad(buf, bs);
    if !okp { return none, none2, ERR_CMS_DECRYPT; }
    return pt, ctype, OK;
}
