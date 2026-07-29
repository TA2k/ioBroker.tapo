"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var newTpLinkCipher_exports = {};
__export(newTpLinkCipher_exports, {
  default: () => NewTpLinkCipher
});
module.exports = __toCommonJS(newTpLinkCipher_exports);
var import_crypto = __toESM(require("crypto"));
class NewTpLinkCipher {
  constructor(localSeed, remoteSeed, authHash, log) {
    this.log = log;
    if (authHash) {
      this.calculateKey(localSeed, remoteSeed, authHash);
      this.calculateIvSeq(localSeed, remoteSeed, authHash);
      this.calculateSig(localSeed, remoteSeed, authHash);
    }
  }
  iv;
  key;
  _crypto = import_crypto.default;
  sig;
  seq;
  encrypt(data) {
    this.seq += 1;
    if (typeof data === "string") {
      data = Buffer.from(data, "utf8");
    }
    const cipher = this._crypto.createCipheriv("aes-128-cbc", this.key, this.ivSeqPair());
    const cipherText = Buffer.concat([cipher.update(data), cipher.final()]);
    const seqBuffer = Buffer.alloc(4);
    seqBuffer.writeInt32BE(this.seq, 0);
    const hash = this._crypto.createHash("sha256");
    hash.update(Buffer.concat([this.sig, seqBuffer, cipherText]));
    const signature = hash.digest();
    return {
      encryptedPayload: Buffer.concat([signature, cipherText]),
      seq: this.seq
    };
  }
  decrypt(data) {
    var _a;
    if (!Buffer.isBuffer(data)) {
      const preview = ((_a = JSON.stringify(data)) == null ? void 0 : _a.substring(0, 200)) || String(data).substring(0, 200);
      throw new Error("decrypt expected Buffer but got " + typeof data + ": " + preview);
    }
    const decipher = this._crypto.createDecipheriv("aes-128-cbc", this.key, this.ivSeqPair());
    const decrypted = Buffer.concat([decipher.update(data.subarray(32)), decipher.final()]);
    const dec = decrypted.toString("utf8");
    this.log.debug("decrypted: " + dec);
    let dec_fixed = "";
    if (dec.match(/{"error_code":([-0-9]+)[^,}]$/)) {
      dec_fixed = dec.replace(/{"error_code":([-0-9]+)[^,}]/gm, '{"error_code":"$1"}');
    } else if (dec.match(/{"error_code":([-0-9]+)}$/)) {
      dec_fixed = dec.replace(/{"error_code":([-0-9]+)}$/gm, '{"error_code":"$1"}');
    } else {
      dec_fixed = dec.replace(/{"error_code":([-0-9]+)[^,}](.*)/gm, '{"error_code":"$1",$2');
    }
    this.log.debug("decrypted fixed: " + dec_fixed);
    return dec_fixed;
  }
  calculateKey(local_seed, remote_seed, auth_hash) {
    const buf = Buffer.concat([Buffer.from("lsk"), local_seed, remote_seed, auth_hash]);
    const hash = this._crypto.createHash("sha256").update(buf).digest();
    this.key = hash.subarray(0, 16);
  }
  calculateIvSeq(local_seed, remote_seed, auth_hash) {
    const buf = Buffer.concat([Buffer.from("iv"), local_seed, remote_seed, auth_hash]);
    const ivBuf = this._crypto.createHash("sha256").update(buf).digest();
    this.seq = ivBuf.subarray(-4).readInt32BE(0);
    this.iv = ivBuf.subarray(0, 12);
  }
  calculateSig(local_seed, remote_seed, auth_hash) {
    const payload = Buffer.concat([Buffer.from("ldk"), local_seed, remote_seed, auth_hash]);
    this.sig = this._crypto.createHash("sha256").update(payload).digest().subarray(0, 28);
  }
  ivSeqPair() {
    const seq = Buffer.alloc(4);
    seq.writeInt32BE(this.seq, 0);
    return Buffer.concat([this.iv, seq]);
  }
}
//# sourceMappingURL=newTpLinkCipher.js.map
