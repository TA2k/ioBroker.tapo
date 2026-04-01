"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = __importDefault(require("crypto"));
const elliptic_1 = require("elliptic");
const bn_js_1 = __importDefault(require("bn.js"));
const curve = new elliptic_1.ec('p256');
// SPAKE2+ M and N points for P-256 (RFC 9382, Appendix M)
const M_COMPRESSED = Buffer.from('02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f', 'hex');
const N_COMPRESSED = Buffer.from('03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49', 'hex');
const M_POINT = curve.keyFromPublic(M_COMPRESSED).getPublic();
const N_POINT = curve.keyFromPublic(N_COMPRESSED).getPublic();
const G_POINT = curve.g;
const ORDER = curve.n;
// AES-128-CCM key derivation constants
const KEY_SALT = Buffer.from('tp-kdf-salt-aes128-key');
const KEY_INFO = Buffer.from('tp-kdf-info-aes128-key');
const NONCE_SALT = Buffer.from('tp-kdf-salt-aes128-iv');
const NONCE_INFO = Buffer.from('tp-kdf-info-aes128-iv');
const KEY_LEN = 16;
const TAG_LEN = 16;
const NONCE_LEN = 12;
// SPAKE2+ context
const PAKE_CONTEXT_TAG = Buffer.from('PAKE V1');
/** 8-byte little-endian length prefix + data (as in python-kasa reference) */
function len8le(data) {
    const prefix = Buffer.alloc(8);
    prefix.writeBigUInt64LE(BigInt(data.length));
    return Buffer.concat([prefix, data]);
}
/** Encode w value as big-endian bytes, minimal length, padded if leading bit set */
function encodeW(w) {
    const hex = w.toString(16);
    const padded = hex.length % 2 !== 0 ? '0' + hex : hex;
    const buf = Buffer.from(padded, 'hex');
    // If high bit set, prepend 0x00
    if (buf[0] & 0x80) {
        return Buffer.concat([Buffer.from([0x00]), buf]);
    }
    return buf;
}
/** Uncompressed SEC1 encoding of an EC point */
function pointToUncompressed(point) {
    return Buffer.from(point.encode('array', false));
}
/** HKDF-expand with SHA-256 */
function hkdfExpand(label, prk, length) {
    const salt = Buffer.alloc(length, 0);
    return Buffer.from(crypto_1.default.hkdfSync('sha256', prk, salt, label, length));
}
/** HKDF-derive for session keys */
function hkdfDerive(ikm, salt, info, length) {
    return Buffer.from(crypto_1.default.hkdfSync('sha256', ikm, salt, info, length));
}
class TpapCipher {
    log;
    ip;
    email;
    password;
    key;
    baseNonce;
    sequence;
    stok;
    constructor(log, ip, email, password) {
        this.log = log;
        this.ip = ip;
        this.email = email;
        this.password = password;
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
        // Step 1: pake_register
        this.log.debug(`TPAP register to ${this.ip} with username hash ${authUsername}`);
        const registerPayload = {
            method: 'login',
            params: {
                sub_method: 'pake_register',
                username: authUsername,
                user_random: userRandom.toString('base64'),
                cipher_suites: [1],
                encryption: ['aes_128_ccm'],
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
        this.log.debug(`TPAP register ok: iterations=${iterations}, cipher=${regResult.encryption}`);
        // Resolve credentials based on extra_crypt
        let credential = this.password;
        if (extraCrypt) {
            const cryptType = (extraCrypt.type || '').toLowerCase();
            const params = extraCrypt.params || {};
            if (cryptType === 'password_shadow') {
                const passwdId = params.passwd_id || 0;
                if (passwdId === 2) {
                    credential = crypto_1.default.createHash('sha1').update(this.password).digest('hex');
                    this.log.debug(`TPAP extra_crypt passwd_id=2: using sha1(password)`);
                }
                else {
                    this.log.error(`TPAP unsupported passwd_id=${passwdId}`);
                    throw new Error(`TPAP unsupported passwd_id=${passwdId}`);
                }
            }
        }
        // PBKDF2-SHA256: derive 80 bytes, split into a_value (40B) and b_value (40B)
        const credentialBytes = Buffer.from(credential);
        const derived = crypto_1.default.pbkdf2Sync(credentialBytes, devSalt, iterations, 80, 'sha256');
        const aBytes = derived.subarray(0, 40);
        const bBytes = derived.subarray(40, 80);
        // Convert to BN (big-endian)
        const aValue = new bn_js_1.default(aBytes.toString('hex'), 16);
        const bValue = new bn_js_1.default(bBytes.toString('hex'), 16);
        const w0 = aValue.umod(ORDER);
        const w1 = bValue.umod(ORDER);
        // Random scalar x in [1, order-1]
        let x;
        do {
            const rnd = crypto_1.default.randomBytes(32);
            x = new bn_js_1.default(rnd.toString('hex'), 16).umod(ORDER);
        } while (x.isZero());
        // Client share L = x*G + w0*M
        const xG = G_POINT.mul(x);
        const w0M = M_POINT.mul(w0);
        const L = xG.add(w0M);
        const lEncoded = pointToUncompressed(L);
        // Parse device share R
        const rPoint = curve.keyFromPublic(devShareBytes).getPublic();
        const rEncoded = pointToUncompressed(rPoint);
        // R' = R - w0*N
        const w0N = N_POINT.mul(w0);
        const rPrime = rPoint.add(w0N.neg());
        // Z = x * R'
        const zPoint = rPrime.mul(x);
        const zEncoded = pointToUncompressed(zPoint);
        // V = w1 * R'
        const vPoint = rPrime.mul(w1);
        const vEncoded = pointToUncompressed(vPoint);
        // Context hash
        const contextHash = crypto_1.default.createHash('sha256')
            .update(Buffer.concat([PAKE_CONTEXT_TAG, userRandom, devRandom]))
            .digest();
        // Encode M, N points
        const mEncoded = pointToUncompressed(M_POINT);
        const nEncoded = pointToUncompressed(N_POINT);
        // Encode w0
        const wEncoded = encodeW(w0);
        // Build transcript
        const transcript = Buffer.concat([
            len8le(contextHash),
            len8le(Buffer.alloc(0)), // idProver (empty)
            len8le(Buffer.alloc(0)), // idVerifier (empty)
            len8le(mEncoded),
            len8le(nEncoded),
            len8le(lEncoded),
            len8le(rEncoded),
            len8le(zEncoded),
            len8le(vEncoded),
            len8le(wEncoded),
        ]);
        const transcriptHash = crypto_1.default.createHash('sha256').update(transcript).digest();
        // Confirmation keys (HMAC variant, mac_len=32 for suite 1)
        const macLen = 32;
        const confirmationKeys = hkdfExpand('ConfirmationKeys', transcriptHash, macLen * 2);
        const keyConfirmA = confirmationKeys.subarray(0, macLen);
        const keyConfirmB = confirmationKeys.subarray(macLen, macLen * 2);
        // SharedKey
        const digestLen = 32; // SHA-256
        const sharedKey = hkdfExpand('SharedKey', transcriptHash, digestLen);
        // User confirm = HMAC-SHA256(keyConfirmA, rEncoded)
        const userConfirm = crypto_1.default.createHmac('sha256', keyConfirmA).update(rEncoded).digest();
        // Expected device confirm = HMAC-SHA256(keyConfirmB, lEncoded)
        const expectedDevConfirm = crypto_1.default.createHmac('sha256', keyConfirmB).update(lEncoded).digest();
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
        this.key = hkdfDerive(sharedKey, KEY_SALT, KEY_INFO, KEY_LEN);
        this.baseNonce = hkdfDerive(sharedKey, NONCE_SALT, NONCE_INFO, NONCE_LEN);
        this.log.info(`TPAP handshake successful for ${this.ip}, stok=${this.stok.substring(0, 8)}...`);
    }
    /** Build nonce from base + sequence number */
    nonceFromBase(seq) {
        const nonce = Buffer.from(this.baseNonce);
        nonce.writeUInt32BE(seq, 8); // replace last 4 bytes
        return nonce;
    }
    /** Encrypt payload for sending to device */
    encrypt(payload) {
        const seq = this.sequence;
        const nonce = this.nonceFromBase(seq);
        const plaintext = Buffer.from(payload, 'utf-8');
        const cipher = crypto_1.default.createCipheriv('aes-128-ccm', this.key, nonce, { authTagLength: TAG_LEN });
        const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
        const tag = cipher.getAuthTag();
        // Wire format: 4-byte BE seq + ciphertext + tag
        const seqBuf = Buffer.alloc(4);
        seqBuf.writeUInt32BE(seq);
        this.sequence = seq + 1;
        return { data: Buffer.concat([seqBuf, encrypted, tag]), seq };
    }
    /** Decrypt response from device */
    decrypt(data) {
        if (data.length < 4 + TAG_LEN) {
            throw new Error('TPAP response too short');
        }
        const responseSeq = data.readUInt32BE(0);
        const nonce = this.nonceFromBase(responseSeq);
        const ciphertextWithTag = data.subarray(4);
        const ciphertext = ciphertextWithTag.subarray(0, ciphertextWithTag.length - TAG_LEN);
        const tag = ciphertextWithTag.subarray(ciphertextWithTag.length - TAG_LEN);
        const decipher = crypto_1.default.createDecipheriv('aes-128-ccm', this.key, nonce, { authTagLength: TAG_LEN });
        decipher.setAuthTag(tag);
        const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        return decrypted.toString('utf-8');
    }
}
exports.default = TpapCipher;
//# sourceMappingURL=tpapCipher.js.map