"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = __importDefault(require("crypto"));
class NewTpLinkCipher {
    log;
    iv;
    key;
    _crypto = crypto_1.default;
    sig;
    seq;
    constructor(localSeed, remoteSeed, authHash, log) {
        this.log = log;
        if (authHash) {
            this.calculateKey(localSeed, remoteSeed, authHash);
            this.calculateIvSeq(localSeed, remoteSeed, authHash);
            this.calculateSig(localSeed, remoteSeed, authHash);
        }
    }
    encrypt(data) {
        this.seq += 1;
        if (typeof data === 'string') {
            data = Buffer.from(data, 'utf8');
        }
        const cipher = this._crypto.createCipheriv('aes-128-cbc', this.key, this.ivSeqPair());
        const cipherText = Buffer.concat([cipher.update(data), cipher.final()]);
        const seqBuffer = Buffer.alloc(4);
        seqBuffer.writeInt32BE(this.seq, 0);
        const hash = this._crypto.createHash('sha256');
        hash.update(Buffer.concat([this.sig, seqBuffer, cipherText]));
        const signature = hash.digest();
        return {
            encryptedPayload: Buffer.concat([signature, cipherText]),
            seq: this.seq,
        };
    }
    decrypt(data) {
        const decipher = this._crypto.createDecipheriv('aes-128-cbc', this.key, this.ivSeqPair());
        const decrypted = Buffer.concat([decipher.update(data.subarray(32)), decipher.final()]);
        const dec = decrypted.toString('utf8');
        this.log.debug('decrypted: ' + dec);
        //Some times the json returned is malformed, or the number returned in error_code
        //is not valid e.g. -0301, so we need to use regex to replace the malformed/invalid json parts
        let dec_fixed = '';
        if (dec.match(/{"error_code":([-0-9]+)[^,}]$/)) {
            dec_fixed = dec.replace(/{"error_code":([-0-9]+)[^,}]/gm, '{"error_code":"$1"}');
        }
        else if (dec.match(/{"error_code":([-0-9]+)}$/)) {
            dec_fixed = dec.replace(/{"error_code":([-0-9]+)}$/gm, '{"error_code":"$1"}');
        }
        else {
            dec_fixed = dec.replace(/{"error_code":([-0-9]+)[^,}](.*)/gm, '{"error_code":"$1",$2');
        }
        this.log.debug('decrypted fixed: ' + dec_fixed);
        return dec_fixed;
    }
    calculateKey(local_seed, remote_seed, auth_hash) {
        const buf = Buffer.concat([Buffer.from('lsk'), local_seed, remote_seed, auth_hash]);
        const hash = this._crypto.createHash('sha256').update(buf).digest();
        this.key = hash.subarray(0, 16);
    }
    calculateIvSeq(local_seed, remote_seed, auth_hash) {
        const buf = Buffer.concat([Buffer.from('iv'), local_seed, remote_seed, auth_hash]);
        const ivBuf = this._crypto.createHash('sha256').update(buf).digest();
        this.seq = ivBuf.subarray(-4).readInt32BE(0);
        this.iv = ivBuf.subarray(0, 12);
    }
    calculateSig(local_seed, remote_seed, auth_hash) {
        const payload = Buffer.concat([Buffer.from('ldk'), local_seed, remote_seed, auth_hash]);
        this.sig = this._crypto.createHash('sha256').update(payload).digest().subarray(0, 28);
    }
    ivSeqPair() {
        const seq = Buffer.alloc(4);
        seq.writeInt32BE(this.seq, 0);
        return Buffer.concat([this.iv, seq]);
    }
}
exports.default = NewTpLinkCipher;
//# sourceMappingURL=newTpLinkCipher.js.map