"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = __importDefault(require("crypto"));
class TpLinkCipher {
    log;
    iv;
    key;
    _crypto = crypto_1.default;
    constructor(log, b_arr, b_arr2) {
        this.log = log;
        this.iv = b_arr2;
        this.key = b_arr;
    }
    static mime_encoder(to_encode) {
        const base64data = Buffer.from(to_encode).toString('base64');
        return base64data;
    }
    encrypt(data) {
        const cipher = this._crypto.createCipheriv('aes-128-cbc', this.key, this.iv);
        let encrypted = cipher.update(data, 'utf8', 'base64');
        encrypted += cipher.final('base64');
        return encrypted;
    }
    decrypt(data) {
        const decipher = this._crypto.createDecipheriv('aes-128-cbc', this.key, this.iv);
        let decrypted = decipher.update(data, 'base64', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    }
}
exports.default = TpLinkCipher;
//# sourceMappingURL=tpLinkCipher.js.map