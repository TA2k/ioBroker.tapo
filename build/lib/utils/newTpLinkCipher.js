"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
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
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var newTpLinkCipher_exports = {};
__export(newTpLinkCipher_exports, {
  default: () => NewTpLinkCipher
});
module.exports = __toCommonJS(newTpLinkCipher_exports);
class NewTpLinkCipher {
  constructor(localSeed, remoteSeed, authHash) {
    this.crypto = require("crypto");
    this.calculateKey(localSeed, remoteSeed, authHash);
    this.calculateIvSeq(localSeed, remoteSeed, authHash);
    this.calculateSig(localSeed, remoteSeed, authHash);
  }
  encrypt(data) {
    this.seq += 1;
    if (typeof data === "string") {
      data = Buffer.from(data, "utf8");
    }
    const cipher = this.crypto.createCipheriv("aes-128-cbc", this.key, this.ivSeqPair());
    const cipherText = Buffer.concat([cipher.update(data), cipher.final()]);
    const seqBuffer = Buffer.alloc(4);
    seqBuffer.writeInt32BE(this.seq, 0);
    const hash = this.crypto.createHash("sha256");
    hash.update(Buffer.concat([this.sig, seqBuffer, cipherText]));
    const signature = hash.digest();
    return {
      encryptedPayload: Buffer.concat([signature, cipherText]),
      seq: this.seq
    };
  }
  decrypt(data) {
    const decipher = this.crypto.createDecipheriv("aes-128-cbc", this.key, this.ivSeqPair());
    const decrypted = Buffer.concat([decipher.update(data.subarray(32)), decipher.final()]);
    return decrypted.toString("utf8");
  }
  calculateKey(local_seed, remote_seed, auth_hash) {
    const buf = Buffer.concat([Buffer.from("lsk"), local_seed, remote_seed, auth_hash]);
    const hash = this.crypto.createHash("sha256").update(buf).digest();
    this.key = hash.subarray(0, 16);
  }
  calculateIvSeq(local_seed, remote_seed, auth_hash) {
    const buf = Buffer.concat([Buffer.from("iv"), local_seed, remote_seed, auth_hash]);
    const ivBuf = this.crypto.createHash("sha256").update(buf).digest();
    this.seq = ivBuf.subarray(-4).readInt32BE(0);
    this.iv = ivBuf.subarray(0, 12);
  }
  calculateSig(local_seed, remote_seed, auth_hash) {
    const payload = Buffer.concat([Buffer.from("ldk"), local_seed, remote_seed, auth_hash]);
    this.sig = this.crypto.createHash("sha256").update(payload).digest().subarray(0, 28);
  }
  ivSeqPair() {
    const seq = Buffer.alloc(4);
    seq.writeInt32BE(this.seq, 0);
    return Buffer.concat([this.iv, seq]);
  }
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {});
//# sourceMappingURL=newTpLinkCipher.js.map
