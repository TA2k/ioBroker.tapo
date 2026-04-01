"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = __importDefault(require("crypto"));
const elliptic_1 = require("elliptic");
const bn_js_1 = __importDefault(require("bn.js"));
// --- Curve setup ---
const p256 = new elliptic_1.ec('p256');
const p384 = new elliptic_1.ec('p384');
// SPAKE2+ M and N points (RFC 9382, Appendix M)
// P-256
const M_P256 = Buffer.from('02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f', 'hex');
const N_P256 = Buffer.from('03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49', 'hex');
// P-384
const M_P384 = Buffer.from('030ff0895ae5ebf6187080a82d82b42e2765e3b2f8749c7e05eba366434b363d3dc36f15314739074d2eb8613fceec2853', 'hex');
const N_P384 = Buffer.from('02c72cf2e390853a1c1c4ad816a62fd15824f56078918f43f922ca21518f9c543bb252c5490214cf9aa3f0baab4b665c10', 'hex');
const CIPHER_PARAMS = {
    aes_128_ccm: {
        keySalt: Buffer.from('tp-kdf-salt-aes128-key'),
        keyInfo: Buffer.from('tp-kdf-info-aes128-key'),
        nonceSalt: Buffer.from('tp-kdf-salt-aes128-iv'),
        nonceInfo: Buffer.from('tp-kdf-info-aes128-iv'),
        keyLen: 16,
        algorithm: 'aes-128-ccm',
    },
    aes_256_ccm: {
        keySalt: Buffer.from('tp-kdf-salt-aes256-key'),
        keyInfo: Buffer.from('tp-kdf-info-aes256-key'),
        nonceSalt: Buffer.from('tp-kdf-salt-aes256-iv'),
        nonceInfo: Buffer.from('tp-kdf-info-aes256-iv'),
        keyLen: 32,
        algorithm: 'aes-256-ccm',
    },
    chacha20_poly1305: {
        keySalt: Buffer.from('tp-kdf-salt-chacha20-key'),
        keyInfo: Buffer.from('tp-kdf-info-chacha20-key'),
        nonceSalt: Buffer.from('tp-kdf-salt-chacha20-iv'),
        nonceInfo: Buffer.from('tp-kdf-info-chacha20-iv'),
        keyLen: 32,
        algorithm: 'chacha20-poly1305',
    },
};
function getSuiteConfig(suiteType) {
    const useSha512 = [2, 4, 5, 7, 9].includes(suiteType);
    const useCmac = [8, 9].includes(suiteType);
    const useP384 = [3, 4].includes(suiteType);
    return {
        hashAlgo: useSha512 ? 'sha512' : 'sha256',
        digestLen: useSha512 ? 64 : 32,
        macType: useCmac ? 'cmac' : 'hmac',
        macLen: useCmac ? 16 : (useSha512 ? 64 : 32),
        curve: useP384 ? p384 : p256,
        mPoint: useP384 ? M_P384 : M_P256,
        nPoint: useP384 ? N_P384 : N_P256,
    };
}
// Supported cipher_suites and encryptions to offer
const ALL_CIPHER_SUITES = [1, 2, 3, 4, 5, 6, 7, 8, 9];
const ALL_ENCRYPTIONS = ['aes_128_ccm', 'aes_256_ccm', 'chacha20_poly1305'];
const TAG_LEN = 16;
const NONCE_LEN = 12;
const PAKE_CONTEXT_TAG = Buffer.from('PAKE V1');
// --- Helper functions ---
function len8le(data) {
    const prefix = Buffer.alloc(8);
    prefix.writeBigUInt64LE(BigInt(data.length));
    return Buffer.concat([prefix, data]);
}
function encodeW(w) {
    const hex = w.toString(16);
    const padded = hex.length % 2 !== 0 ? '0' + hex : hex;
    const buf = Buffer.from(padded, 'hex');
    if (buf[0] & 0x80) {
        return Buffer.concat([Buffer.from([0x00]), buf]);
    }
    return buf;
}
function pointToUncompressed(point) {
    return Buffer.from(point.encode('array', false));
}
function hkdfExpand(label, prk, length, hashAlgo) {
    const salt = Buffer.alloc(length, 0);
    return Buffer.from(crypto_1.default.hkdfSync(hashAlgo, prk, salt, label, length));
}
function hkdfDerive(ikm, salt, info, length, hashAlgo) {
    return Buffer.from(crypto_1.default.hkdfSync(hashAlgo, ikm, salt, info, length));
}
/** CMAC-AES-128 */
function cmacAes128(key, data) {
    // AES-128-CBC-MAC with subkey derivation (CMAC/OMAC1)
    const cipher0 = crypto_1.default.createCipheriv('aes-128-ecb', key, null);
    cipher0.setAutoPadding(false);
    const L = cipher0.update(Buffer.alloc(16, 0));
    // Derive subkeys K1, K2
    const Rb = Buffer.from('00000000000000000000000000000087', 'hex');
    function dbl(buf) {
        const shifted = Buffer.alloc(16);
        let carry = 0;
        for (let i = 15; i >= 0; i--) {
            const val = (buf[i] << 1) | carry;
            shifted[i] = val & 0xff;
            carry = buf[i] >> 7;
        }
        if (buf[0] & 0x80) {
            for (let i = 0; i < 16; i++)
                shifted[i] ^= Rb[i];
        }
        return shifted;
    }
    const K1 = dbl(L);
    const K2 = dbl(K1);
    // Process message
    const n = data.length === 0 ? 1 : Math.ceil(data.length / 16);
    const lastComplete = data.length > 0 && data.length % 16 === 0;
    const padded = Buffer.alloc(n * 16, 0);
    data.copy(padded);
    if (!lastComplete) {
        if (data.length > 0) {
            padded[data.length] = 0x80;
        }
        else {
            padded[0] = 0x80;
        }
    }
    // XOR last block with K1 or K2
    const lastBlockStart = (n - 1) * 16;
    const subkey = lastComplete ? K1 : K2;
    for (let i = 0; i < 16; i++) {
        padded[lastBlockStart + i] ^= subkey[i];
    }
    // CBC-MAC
    let x = Buffer.alloc(16, 0);
    for (let i = 0; i < n; i++) {
        const block = padded.subarray(i * 16, (i + 1) * 16);
        const xored = Buffer.alloc(16);
        for (let j = 0; j < 16; j++)
            xored[j] = x[j] ^ block[j];
        const c = crypto_1.default.createCipheriv('aes-128-ecb', key, null);
        c.setAutoPadding(false);
        x = c.update(xored);
    }
    return x;
}
// --- Credential resolution ---
/** Unix MD5-crypt ($1$) */
function md5Crypt(password, prefix) {
    // Extract salt from prefix like "$1$salt$"
    const parts = prefix.split('$').filter(Boolean);
    if (parts.length < 2 || parts[0] !== '1')
        return null;
    const salt = parts[1].substring(0, 8);
    // Standard MD5-crypt algorithm (glibc/FreeBSD)
    const pw = Buffer.from(password);
    const sl = Buffer.from(salt);
    const magic = Buffer.from('$1$');
    // Step 1: altHash = MD5(pw + salt + pw)
    const alt = crypto_1.default.createHash('md5').update(pw).update(sl).update(pw).digest();
    // Step 2: ctx = MD5(pw + magic + salt + alt[0..pwlen] + ...)
    const ctx = crypto_1.default.createHash('md5');
    ctx.update(pw);
    ctx.update(magic);
    ctx.update(sl);
    for (let i = pw.length; i > 0; i -= 16) {
        ctx.update(alt.subarray(0, Math.min(i, 16)));
    }
    // Bit-length encoding of password length
    for (let i = pw.length; i > 0; i >>= 1) {
        if (i & 1) {
            ctx.update(Buffer.from([0]));
        }
        else {
            ctx.update(pw.subarray(0, 1));
        }
    }
    let result = ctx.digest();
    // 1000 rounds
    for (let i = 0; i < 1000; i++) {
        const c = crypto_1.default.createHash('md5');
        if (i & 1)
            c.update(pw);
        else
            c.update(result);
        if (i % 3)
            c.update(sl);
        if (i % 7)
            c.update(pw);
        if (i & 1)
            c.update(result);
        else
            c.update(pw);
        result = c.digest();
    }
    // Custom base64 encoding
    const b64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    function to64(v, n) {
        let s = '';
        for (let i = 0; i < n; i++) {
            s += b64[v & 0x3f];
            v >>= 6;
        }
        return s;
    }
    let encoded = '';
    encoded += to64((result[0] << 16) | (result[6] << 8) | result[12], 4);
    encoded += to64((result[1] << 16) | (result[7] << 8) | result[13], 4);
    encoded += to64((result[2] << 16) | (result[8] << 8) | result[14], 4);
    encoded += to64((result[3] << 16) | (result[9] << 8) | result[15], 4);
    encoded += to64((result[4] << 16) | (result[10] << 8) | result[5], 4);
    encoded += to64(result[11], 2);
    return `$1$${salt}$${encoded}`;
}
/** Unix SHA-256-crypt ($5$) */
function sha256Crypt(password, prefix, rounds) {
    const parts = prefix.split('$').filter(Boolean);
    if (parts.length < 2 || parts[0] !== '5')
        return null;
    const salt = parts[1].substring(0, 16);
    const r = rounds || 5000;
    const pw = Buffer.from(password);
    const sl = Buffer.from(salt);
    // Step 1: B = SHA256(pw + salt + pw)
    const B = crypto_1.default.createHash('sha256').update(pw).update(sl).update(pw).digest();
    // Step 2: A = SHA256(pw + salt + B[0..pwlen])
    const ctxA = crypto_1.default.createHash('sha256');
    ctxA.update(pw).update(sl);
    for (let i = pw.length; i > 0; i -= 32) {
        ctxA.update(B.subarray(0, Math.min(i, 32)));
    }
    for (let i = pw.length; i > 0; i >>= 1) {
        if (i & 1)
            ctxA.update(B);
        else
            ctxA.update(pw);
    }
    const A = ctxA.digest();
    // Step 3: DP = SHA256(pw repeated pw.length times)
    const ctxDP = crypto_1.default.createHash('sha256');
    for (let i = 0; i < pw.length; i++)
        ctxDP.update(pw);
    const DP = ctxDP.digest();
    const P = Buffer.alloc(pw.length);
    for (let i = 0; i < pw.length; i++)
        P[i] = DP[i % 32];
    // Step 4: DS = SHA256(salt repeated 16+A[0] times)
    const ctxDS = crypto_1.default.createHash('sha256');
    for (let i = 0; i < 16 + A[0]; i++)
        ctxDS.update(sl);
    const DS = ctxDS.digest();
    const S = Buffer.alloc(sl.length);
    for (let i = 0; i < sl.length; i++)
        S[i] = DS[i % 32];
    // Rounds
    let C = A;
    for (let i = 0; i < r; i++) {
        const ctx = crypto_1.default.createHash('sha256');
        if (i & 1)
            ctx.update(P);
        else
            ctx.update(C);
        if (i % 3)
            ctx.update(S);
        if (i % 7)
            ctx.update(P);
        if (i & 1)
            ctx.update(C);
        else
            ctx.update(P);
        C = ctx.digest();
    }
    // Custom base64
    const b64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    function to64(v, n) {
        let s = '';
        for (let i = 0; i < n; i++) {
            s += b64[v & 0x3f];
            v >>= 6;
        }
        return s;
    }
    let encoded = '';
    encoded += to64((C[0] << 16) | (C[10] << 8) | C[20], 4);
    encoded += to64((C[21] << 16) | (C[1] << 8) | C[11], 4);
    encoded += to64((C[12] << 16) | (C[22] << 8) | C[2], 4);
    encoded += to64((C[3] << 16) | (C[13] << 8) | C[23], 4);
    encoded += to64((C[24] << 16) | (C[4] << 8) | C[14], 4);
    encoded += to64((C[15] << 16) | (C[25] << 8) | C[5], 4);
    encoded += to64((C[6] << 16) | (C[16] << 8) | C[26], 4);
    encoded += to64((C[27] << 16) | (C[7] << 8) | C[17], 4);
    encoded += to64((C[18] << 16) | (C[28] << 8) | C[8], 4);
    encoded += to64((C[9] << 16) | (C[19] << 8) | C[29], 4);
    encoded += to64((C[30] << 16) | (C[31] << 8), 3);
    const roundsStr = r !== 5000 ? `rounds=${r}$` : '';
    return `$5$${roundsStr}${salt}$${encoded}`;
}
/** Resolve extra_crypt credentials */
function resolveCredential(log, password, email, mac, extraCrypt) {
    if (!extraCrypt)
        return password;
    const cryptType = (extraCrypt.type || '').toLowerCase();
    const params = extraCrypt.params || {};
    if (cryptType === 'password_shadow') {
        const passwdId = parseInt(params.passwd_id || '0', 10);
        const prefix = String(params.passwd_prefix || '');
        if (passwdId === 1) {
            // MD5-crypt
            const result = md5Crypt(password, prefix);
            if (result) {
                log.debug('TPAP extra_crypt passwd_id=1: md5_crypt');
                return result;
            }
            log.error('TPAP md5_crypt failed, falling back to raw password');
            return password;
        }
        if (passwdId === 2) {
            // SHA-1 of raw password
            log.debug('TPAP extra_crypt passwd_id=2: sha1(password)');
            return crypto_1.default.createHash('sha1').update(password).digest('hex');
        }
        if (passwdId === 3) {
            // SHA-1(MD5(password) + "_" + MAC_WITH_COLONS)
            const macNoColon = mac.replace(/[:\-]/g, '').toUpperCase();
            const macFormatted = macNoColon.match(/.{2}/g).join(':');
            const md5pw = crypto_1.default.createHash('md5').update(password).digest('hex');
            const result = crypto_1.default.createHash('sha1').update(md5pw + '_' + macFormatted).digest('hex');
            log.debug('TPAP extra_crypt passwd_id=3: sha1(md5(pw)+"_"+MAC)');
            return result;
        }
        if (passwdId === 5) {
            // SHA-256-crypt
            const rounds = params.passwd_rounds ? parseInt(params.passwd_rounds, 10) : undefined;
            const result = sha256Crypt(password, prefix, rounds);
            if (result) {
                log.debug('TPAP extra_crypt passwd_id=5: sha256_crypt');
                return result;
            }
            log.error('TPAP sha256_crypt failed, falling back to raw password');
            return password;
        }
        log.error(`TPAP unsupported passwd_id=${passwdId}`);
        return password;
    }
    if (cryptType === 'password_authkey') {
        // XOR-based key derivation
        const tmpkey = String(params.authkey_tmpkey || '');
        const dictionary = String(params.authkey_dictionary || '');
        if (tmpkey && dictionary) {
            const maxLen = Math.max(tmpkey.length, password.length);
            let result = '';
            for (let i = 0; i < maxLen; i++) {
                const a = i < password.length ? password.charCodeAt(i) : 0xbb;
                const b = i < tmpkey.length ? tmpkey.charCodeAt(i) : 0xbb;
                const xored = a ^ b;
                result += dictionary[xored % dictionary.length];
            }
            log.debug('TPAP extra_crypt password_authkey: XOR derivation');
            return result;
        }
        log.error('TPAP password_authkey missing tmpkey/dictionary');
        return password;
    }
    if (cryptType === 'password_sha_with_salt') {
        // SHA256(name + base64decode(sha_salt) + password)
        const shaName = parseInt(params.sha_name || '0', 10);
        const name = shaName === 0 ? 'admin' : 'user';
        const shaSalt = params.sha_salt ? Buffer.from(params.sha_salt, 'base64') : Buffer.alloc(0);
        const result = crypto_1.default.createHash('sha256')
            .update(name)
            .update(shaSalt)
            .update(password)
            .digest('hex');
        log.debug(`TPAP extra_crypt password_sha_with_salt: SHA256(${name}+salt+pw)`);
        return result;
    }
    log.error(`TPAP unsupported extra_crypt type: ${cryptType}`);
    return password;
}
// --- Main class ---
class TpapCipher {
    log;
    ip;
    email;
    password;
    mac;
    key;
    baseNonce;
    sequence;
    stok;
    cipherAlgorithm = 'aes-128-ccm';
    tagLen = TAG_LEN;
    constructor(log, ip, email, password, mac = '') {
        this.log = log;
        this.ip = ip;
        this.email = email;
        this.password = password;
        this.mac = mac;
    }
    get sessionUrl() {
        return `http://${this.ip}/stok=${this.stok}/ds`;
    }
    get isReady() {
        return !!this.key && !!this.baseNonce && !!this.stok;
    }
    /** Full SPAKE2+ handshake: register → share → derive keys */
    async handshake() {
        const axios = (await import('axios')).default;
        const baseUrl = `http://${this.ip}`;
        const headers = {
            'Content-Type': 'application/json; charset=UTF-8',
            Accept: 'application/json',
            Connection: 'Keep-Alive',
        };
        // Username for register: md5("admin")
        const authUsername = crypto_1.default.createHash('md5').update('admin').digest('hex');
        const userRandom = crypto_1.default.randomBytes(32);
        // Step 1: pake_register — offer all suites and encryptions
        this.log.debug(`TPAP register to ${this.ip} with username hash ${authUsername}`);
        const registerPayload = {
            method: 'login',
            params: {
                sub_method: 'pake_register',
                username: authUsername,
                user_random: userRandom.toString('base64'),
                cipher_suites: ALL_CIPHER_SUITES,
                encryption: ALL_ENCRYPTIONS,
                passcode_type: 'default_userpw',
                stok: null,
            },
        };
        const r1 = await axios.post(baseUrl, registerPayload, { headers, timeout: 5000 });
        if (r1.data.error_code !== 0) {
            throw new Error(`TPAP register failed: error_code=${r1.data.error_code}`);
        }
        const regResult = r1.data.result;
        const devRandom = Buffer.from(regResult.dev_random, 'base64');
        const devSalt = Buffer.from(regResult.dev_salt, 'base64');
        const devShareBytes = Buffer.from(regResult.dev_share, 'base64');
        const iterations = regResult.iterations;
        const extraCrypt = regResult.extra_crypt;
        const negotiatedSuite = regResult.cipher_suites || 1;
        const negotiatedEncryption = regResult.encryption || 'aes_128_ccm';
        this.log.debug(`TPAP register ok: suite=${negotiatedSuite}, encryption=${negotiatedEncryption}, iterations=${iterations}`);
        // Get suite and cipher config
        const suite = getSuiteConfig(negotiatedSuite);
        const cipherParams = CIPHER_PARAMS[negotiatedEncryption];
        if (!cipherParams) {
            throw new Error(`TPAP unsupported encryption: ${negotiatedEncryption}`);
        }
        this.cipherAlgorithm = cipherParams.algorithm;
        // ChaCha20-Poly1305 uses fixed 16-byte tag
        this.tagLen = TAG_LEN;
        // Resolve credentials
        const credential = resolveCredential(this.log, this.password, this.email, this.mac, extraCrypt);
        // PBKDF2: derive key material
        const hashLen = suite.digestLen;
        const idLen = hashLen + 8; // 40 for sha256, 72 for sha512
        const derived = crypto_1.default.pbkdf2Sync(Buffer.from(credential), devSalt, iterations, idLen * 2, suite.hashAlgo);
        const aBytes = derived.subarray(0, idLen);
        const bBytes = derived.subarray(idLen, idLen * 2);
        const ec = suite.curve;
        const order = ec.n;
        const gPoint = ec.g;
        const mPoint = ec.keyFromPublic(suite.mPoint).getPublic();
        const nPoint = ec.keyFromPublic(suite.nPoint).getPublic();
        const aValue = new bn_js_1.default(aBytes.toString('hex'), 16);
        const bValue = new bn_js_1.default(bBytes.toString('hex'), 16);
        const w0 = aValue.umod(order);
        const w1 = bValue.umod(order);
        // Random scalar x in [1, order-1]
        let x;
        do {
            const rnd = crypto_1.default.randomBytes(48);
            x = new bn_js_1.default(rnd.toString('hex'), 16).umod(order);
        } while (x.isZero());
        // Client share L = x*G + w0*M
        const L = gPoint.mul(x).add(mPoint.mul(w0));
        const lEncoded = pointToUncompressed(L);
        // Parse device share R
        const rPoint = ec.keyFromPublic(devShareBytes).getPublic();
        const rEncoded = pointToUncompressed(rPoint);
        // R' = R - w0*N, Z = x*R', V = w1*R'
        const rPrime = rPoint.add(nPoint.mul(w0).neg());
        const zEncoded = pointToUncompressed(rPrime.mul(x));
        const vEncoded = pointToUncompressed(rPrime.mul(w1));
        // Context hash
        const contextHash = crypto_1.default.createHash(suite.hashAlgo)
            .update(Buffer.concat([PAKE_CONTEXT_TAG, userRandom, devRandom]))
            .digest();
        const mEncoded = pointToUncompressed(mPoint);
        const nEncoded = pointToUncompressed(nPoint);
        const wEncoded = encodeW(w0);
        // Build transcript
        const transcript = Buffer.concat([
            len8le(contextHash),
            len8le(Buffer.alloc(0)),
            len8le(Buffer.alloc(0)),
            len8le(mEncoded),
            len8le(nEncoded),
            len8le(lEncoded),
            len8le(rEncoded),
            len8le(zEncoded),
            len8le(vEncoded),
            len8le(wEncoded),
        ]);
        const transcriptHash = crypto_1.default.createHash(suite.hashAlgo).update(transcript).digest();
        // Confirmation keys
        const macLen = suite.macLen;
        const confirmationKeys = hkdfExpand('ConfirmationKeys', transcriptHash, macLen * 2, suite.hashAlgo);
        const keyConfirmA = confirmationKeys.subarray(0, macLen);
        const keyConfirmB = confirmationKeys.subarray(macLen, macLen * 2);
        // SharedKey
        const sharedKey = hkdfExpand('SharedKey', transcriptHash, suite.digestLen, suite.hashAlgo);
        // Compute confirmation values
        let userConfirm;
        let expectedDevConfirm;
        if (suite.macType === 'cmac') {
            userConfirm = cmacAes128(keyConfirmA, rEncoded);
            expectedDevConfirm = cmacAes128(keyConfirmB, lEncoded);
        }
        else {
            userConfirm = crypto_1.default.createHmac(suite.hashAlgo, keyConfirmA).update(rEncoded).digest();
            expectedDevConfirm = crypto_1.default.createHmac(suite.hashAlgo, keyConfirmB).update(lEncoded).digest();
        }
        // Step 2: pake_share
        this.log.debug(`TPAP pake_share to ${this.ip}`);
        const sharePayload = {
            method: 'login',
            params: {
                sub_method: 'pake_share',
                user_share: lEncoded.toString('base64'),
                user_confirm: userConfirm.toString('base64'),
            },
        };
        const r2 = await axios.post(baseUrl, sharePayload, { headers, timeout: 5000 });
        if (r2.data.error_code !== 0) {
            throw new Error(`TPAP pake_share failed: error_code=${r2.data.error_code}`);
        }
        const shareResult = r2.data.result;
        // Verify device confirm
        const devConfirm = Buffer.from(shareResult.dev_confirm, 'base64');
        if (!devConfirm.equals(expectedDevConfirm)) {
            throw new Error('TPAP device confirmation mismatch');
        }
        this.log.debug('TPAP device confirmation verified');
        // Extract session
        this.stok = String(shareResult.sessionId || shareResult.stok || '');
        const startSeq = parseInt(shareResult.start_seq, 10);
        this.sequence = startSeq;
        // Derive session cipher keys
        this.key = hkdfDerive(sharedKey, cipherParams.keySalt, cipherParams.keyInfo, cipherParams.keyLen, suite.hashAlgo);
        this.baseNonce = hkdfDerive(sharedKey, cipherParams.nonceSalt, cipherParams.nonceInfo, NONCE_LEN, suite.hashAlgo);
        this.log.info(`TPAP handshake successful for ${this.ip} (suite=${negotiatedSuite}, cipher=${negotiatedEncryption})`);
    }
    nonceFromBase(seq) {
        const nonce = Buffer.from(this.baseNonce);
        nonce.writeUInt32BE(seq, nonce.length - 4);
        return nonce;
    }
    encrypt(payload) {
        const seq = this.sequence;
        const nonce = this.nonceFromBase(seq);
        const plaintext = Buffer.from(payload, 'utf-8');
        let encrypted;
        let tag;
        if (this.cipherAlgorithm === 'chacha20-poly1305') {
            const cipher = crypto_1.default.createCipheriv('chacha20-poly1305', this.key, nonce, { authTagLength: this.tagLen });
            encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
            tag = cipher.getAuthTag();
        }
        else {
            // AES-CCM
            const cipher = crypto_1.default.createCipheriv(this.cipherAlgorithm, this.key, nonce, { authTagLength: this.tagLen });
            encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
            tag = cipher.getAuthTag();
        }
        const seqBuf = Buffer.alloc(4);
        seqBuf.writeUInt32BE(seq);
        this.sequence = seq + 1;
        return { data: Buffer.concat([seqBuf, encrypted, tag]), seq };
    }
    decrypt(data) {
        if (data.length < 4 + this.tagLen) {
            throw new Error('TPAP response too short');
        }
        const responseSeq = data.readUInt32BE(0);
        const nonce = this.nonceFromBase(responseSeq);
        const ciphertextWithTag = data.subarray(4);
        const ciphertext = ciphertextWithTag.subarray(0, ciphertextWithTag.length - this.tagLen);
        const tag = ciphertextWithTag.subarray(ciphertextWithTag.length - this.tagLen);
        let decrypted;
        if (this.cipherAlgorithm === 'chacha20-poly1305') {
            const decipher = crypto_1.default.createDecipheriv('chacha20-poly1305', this.key, nonce, { authTagLength: this.tagLen });
            decipher.setAuthTag(tag);
            decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        }
        else {
            const decipher = crypto_1.default.createDecipheriv(this.cipherAlgorithm, this.key, nonce, { authTagLength: this.tagLen });
            decipher.setAuthTag(tag);
            decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        }
        return decrypted.toString('utf-8');
    }
}
exports.default = TpapCipher;
//# sourceMappingURL=tpapCipher.js.map