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
var tpLinkCipher_exports = {};
__export(tpLinkCipher_exports, {
  default: () => TpLinkCipher
});
module.exports = __toCommonJS(tpLinkCipher_exports);
class TpLinkCipher {
  constructor(log, b_arr, b_arr2) {
    this.log = log;
    this.crypto = require("crypto");
    this.iv = b_arr2;
    this.key = b_arr;
  }
  static mime_encoder(to_encode) {
    const base64data = Buffer.from(to_encode).toString("base64");
    return base64data;
  }
  encrypt(data) {
    const cipher = this.crypto.createCipheriv("aes-128-cbc", this.key, this.iv);
    let encrypted = cipher.update(data, "utf8", "base64");
    encrypted += cipher.final("base64");
    return encrypted;
  }
  decrypt(data) {
    const decipher = this.crypto.createDecipheriv("aes-128-cbc", this.key, this.iv);
    let decrypted = decipher.update(data, "base64", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  }
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {});
//# sourceMappingURL=tpLinkCipher.js.map
