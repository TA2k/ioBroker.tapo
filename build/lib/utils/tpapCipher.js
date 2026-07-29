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
var tpapCipher_exports = {};
__export(tpapCipher_exports, {
  default: () => TpapCipher
});
module.exports = __toCommonJS(tpapCipher_exports);
var import_crypto = __toESM(require("crypto"));
var import_elliptic = require("elliptic");
var import_bn = __toESM(require("bn.js"));
const p256 = new import_elliptic.ec("p256");
const p384 = new import_elliptic.ec("p384");
const M_P256 = Buffer.from("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f", "hex");
const N_P256 = Buffer.from("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49", "hex");
const M_P384 = Buffer.from("030ff0895ae5ebf6187080a82d82b42e2765e3b2f8749c7e05eba366434b363d3dc36f15314739074d2eb8613fceec2853", "hex");
const N_P384 = Buffer.from("02c72cf2e390853a1c1c4ad816a62fd15824f56078918f43f922ca21518f9c543bb252c5490214cf9aa3f0baab4b665c10", "hex");
const CIPHER_PARAMS = {
  aes_128_ccm: {
    keySalt: Buffer.from("tp-kdf-salt-aes128-key"),
    keyInfo: Buffer.from("tp-kdf-info-aes128-key"),
    nonceSalt: Buffer.from("tp-kdf-salt-aes128-iv"),
    nonceInfo: Buffer.from("tp-kdf-info-aes128-iv"),
    keyLen: 16,
    algorithm: "aes-128-ccm"
  },
  aes_256_ccm: {
    keySalt: Buffer.from("tp-kdf-salt-aes256-key"),
    keyInfo: Buffer.from("tp-kdf-info-aes256-key"),
    nonceSalt: Buffer.from("tp-kdf-salt-aes256-iv"),
    nonceInfo: Buffer.from("tp-kdf-info-aes256-iv"),
    keyLen: 32,
    algorithm: "aes-256-ccm"
  },
  chacha20_poly1305: {
    keySalt: Buffer.from("tp-kdf-salt-chacha20-key"),
    keyInfo: Buffer.from("tp-kdf-info-chacha20-key"),
    nonceSalt: Buffer.from("tp-kdf-salt-chacha20-iv"),
    nonceInfo: Buffer.from("tp-kdf-info-chacha20-iv"),
    keyLen: 32,
    algorithm: "chacha20-poly1305"
  }
};
function getSuiteConfig(suiteType) {
  const useSha512 = [2, 4, 5, 7, 9].includes(suiteType);
  const useCmac = [8, 9].includes(suiteType);
  const useP384 = [3, 4].includes(suiteType);
  return {
    hashAlgo: useSha512 ? "sha512" : "sha256",
    digestLen: useSha512 ? 64 : 32,
    macType: useCmac ? "cmac" : "hmac",
    macLen: useCmac ? 16 : useSha512 ? 64 : 32,
    curve: useP384 ? p384 : p256,
    mPoint: useP384 ? M_P384 : M_P256,
    nPoint: useP384 ? N_P384 : N_P256
  };
}
const ALL_CIPHER_SUITES = [1, 2, 3, 4, 5, 6, 7, 8, 9];
const ALL_ENCRYPTIONS = ["aes_128_ccm", "aes_256_ccm", "chacha20_poly1305"];
const TAG_LEN = 16;
const NONCE_LEN = 12;
const PAKE_CONTEXT_TAG = Buffer.from("PAKE V1");
function len8le(data) {
  const prefix = Buffer.alloc(8);
  prefix.writeBigUInt64LE(BigInt(data.length));
  return Buffer.concat([prefix, data]);
}
function encodeW(w) {
  const hex = w.toString(16);
  const padded = hex.length % 2 !== 0 ? "0" + hex : hex;
  const buf = Buffer.from(padded, "hex");
  if (buf.length % 2 === 0) {
    return buf;
  }
  if (buf[0] & 128) {
    return Buffer.concat([Buffer.from([0]), buf]);
  }
  return buf;
}
function pointToUncompressed(point) {
  return Buffer.from(point.encode("array", false));
}
function hkdfExpand(label, prk, length, hashAlgo) {
  const salt = Buffer.alloc(length, 0);
  return Buffer.from(import_crypto.default.hkdfSync(hashAlgo, prk, salt, label, length));
}
function hkdfDerive(ikm, salt, info, length, hashAlgo) {
  return Buffer.from(import_crypto.default.hkdfSync(hashAlgo, ikm, salt, info, length));
}
function cmacAes128(key, data) {
  const cipher0 = import_crypto.default.createCipheriv("aes-128-ecb", key, null);
  cipher0.setAutoPadding(false);
  const L = cipher0.update(Buffer.alloc(16, 0));
  const Rb = Buffer.from("00000000000000000000000000000087", "hex");
  function dbl(buf) {
    const shifted = Buffer.alloc(16);
    let carry = 0;
    for (let i = 15; i >= 0; i--) {
      const val = buf[i] << 1 | carry;
      shifted[i] = val & 255;
      carry = buf[i] >> 7;
    }
    if (buf[0] & 128) {
      for (let i = 0; i < 16; i++) shifted[i] ^= Rb[i];
    }
    return shifted;
  }
  const K1 = dbl(L);
  const K2 = dbl(K1);
  const n = data.length === 0 ? 1 : Math.ceil(data.length / 16);
  const lastComplete = data.length > 0 && data.length % 16 === 0;
  const padded = Buffer.alloc(n * 16, 0);
  data.copy(padded);
  if (!lastComplete) {
    if (data.length > 0) {
      padded[data.length] = 128;
    } else {
      padded[0] = 128;
    }
  }
  const lastBlockStart = (n - 1) * 16;
  const subkey = lastComplete ? K1 : K2;
  for (let i = 0; i < 16; i++) {
    padded[lastBlockStart + i] ^= subkey[i];
  }
  let x = Buffer.alloc(16, 0);
  for (let i = 0; i < n; i++) {
    const block = padded.subarray(i * 16, (i + 1) * 16);
    const xored = Buffer.alloc(16);
    for (let j = 0; j < 16; j++) xored[j] = x[j] ^ block[j];
    const c = import_crypto.default.createCipheriv("aes-128-ecb", key, null);
    c.setAutoPadding(false);
    x = c.update(xored);
  }
  return x;
}
function md5Crypt(password, prefix) {
  const parts = prefix.split("$").filter(Boolean);
  if (parts.length < 2 || parts[0] !== "1") return null;
  const salt = parts[1].substring(0, 8);
  const pw = Buffer.from(password);
  const sl = Buffer.from(salt);
  const magic = Buffer.from("$1$");
  const alt = import_crypto.default.createHash("md5").update(pw).update(sl).update(pw).digest();
  const ctx = import_crypto.default.createHash("md5");
  ctx.update(pw);
  ctx.update(magic);
  ctx.update(sl);
  for (let i = pw.length; i > 0; i -= 16) {
    ctx.update(alt.subarray(0, Math.min(i, 16)));
  }
  for (let i = pw.length; i > 0; i >>= 1) {
    if (i & 1) {
      ctx.update(Buffer.from([0]));
    } else {
      ctx.update(pw.subarray(0, 1));
    }
  }
  let result = ctx.digest();
  for (let i = 0; i < 1e3; i++) {
    const c = import_crypto.default.createHash("md5");
    if (i & 1) c.update(pw);
    else c.update(result);
    if (i % 3) c.update(sl);
    if (i % 7) c.update(pw);
    if (i & 1) c.update(result);
    else c.update(pw);
    result = c.digest();
  }
  const b64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  function to64(v, n) {
    let s = "";
    for (let i = 0; i < n; i++) {
      s += b64[v & 63];
      v >>= 6;
    }
    return s;
  }
  let encoded = "";
  encoded += to64(result[0] << 16 | result[6] << 8 | result[12], 4);
  encoded += to64(result[1] << 16 | result[7] << 8 | result[13], 4);
  encoded += to64(result[2] << 16 | result[8] << 8 | result[14], 4);
  encoded += to64(result[3] << 16 | result[9] << 8 | result[15], 4);
  encoded += to64(result[4] << 16 | result[10] << 8 | result[5], 4);
  encoded += to64(result[11], 2);
  return `$1$${salt}$${encoded}`;
}
function sha256Crypt(password, prefix, rounds) {
  const parts = prefix.split("$").filter(Boolean);
  if (parts.length < 2 || parts[0] !== "5") return null;
  const salt = parts[1].substring(0, 16);
  const r = rounds || 5e3;
  const pw = Buffer.from(password);
  const sl = Buffer.from(salt);
  const B = import_crypto.default.createHash("sha256").update(pw).update(sl).update(pw).digest();
  const ctxA = import_crypto.default.createHash("sha256");
  ctxA.update(pw).update(sl);
  for (let i = pw.length; i > 0; i -= 32) {
    ctxA.update(B.subarray(0, Math.min(i, 32)));
  }
  for (let i = pw.length; i > 0; i >>= 1) {
    if (i & 1) ctxA.update(B);
    else ctxA.update(pw);
  }
  const A = ctxA.digest();
  const ctxDP = import_crypto.default.createHash("sha256");
  for (let i = 0; i < pw.length; i++) ctxDP.update(pw);
  const DP = ctxDP.digest();
  const P = Buffer.alloc(pw.length);
  for (let i = 0; i < pw.length; i++) P[i] = DP[i % 32];
  const ctxDS = import_crypto.default.createHash("sha256");
  for (let i = 0; i < 16 + A[0]; i++) ctxDS.update(sl);
  const DS = ctxDS.digest();
  const S = Buffer.alloc(sl.length);
  for (let i = 0; i < sl.length; i++) S[i] = DS[i % 32];
  let C = A;
  for (let i = 0; i < r; i++) {
    const ctx = import_crypto.default.createHash("sha256");
    if (i & 1) ctx.update(P);
    else ctx.update(C);
    if (i % 3) ctx.update(S);
    if (i % 7) ctx.update(P);
    if (i & 1) ctx.update(C);
    else ctx.update(P);
    C = ctx.digest();
  }
  const b64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  function to64(v, n) {
    let s = "";
    for (let i = 0; i < n; i++) {
      s += b64[v & 63];
      v >>= 6;
    }
    return s;
  }
  let encoded = "";
  encoded += to64(C[0] << 16 | C[10] << 8 | C[20], 4);
  encoded += to64(C[21] << 16 | C[1] << 8 | C[11], 4);
  encoded += to64(C[12] << 16 | C[22] << 8 | C[2], 4);
  encoded += to64(C[3] << 16 | C[13] << 8 | C[23], 4);
  encoded += to64(C[24] << 16 | C[4] << 8 | C[14], 4);
  encoded += to64(C[15] << 16 | C[25] << 8 | C[5], 4);
  encoded += to64(C[6] << 16 | C[16] << 8 | C[26], 4);
  encoded += to64(C[27] << 16 | C[7] << 8 | C[17], 4);
  encoded += to64(C[18] << 16 | C[28] << 8 | C[8], 4);
  encoded += to64(C[9] << 16 | C[19] << 8 | C[29], 4);
  encoded += to64(C[30] << 16 | C[31] << 8, 3);
  const roundsStr = r !== 5e3 ? `rounds=${r}$` : "";
  return `$5$${roundsStr}${salt}$${encoded}`;
}
function resolveCredential(log, password, username, mac, extraCrypt, isSmartCam) {
  if (!extraCrypt) {
    if (!isSmartCam && username) {
      return username + "/" + password;
    }
    return password;
  }
  const cryptType = (extraCrypt.type || "").toLowerCase();
  const params = extraCrypt.params || {};
  if (cryptType === "password_shadow") {
    const passwdId = parseInt(params.passwd_id || "0", 10);
    const prefix = String(params.passwd_prefix || "");
    if (passwdId === 1) {
      const result = md5Crypt(password, prefix);
      if (result) {
        log.debug("TPAP extra_crypt passwd_id=1: md5_crypt");
        return result;
      }
      log.error("TPAP md5_crypt failed, falling back to raw password");
      return password;
    }
    if (passwdId === 2) {
      log.debug("TPAP extra_crypt passwd_id=2: sha1(password)");
      return import_crypto.default.createHash("sha1").update(password).digest("hex");
    }
    if (passwdId === 3) {
      const macNoColon = mac.replace(/[:-]/g, "").toUpperCase();
      const macFormatted = macNoColon.match(/.{2}/g).join(":");
      const md5pw = import_crypto.default.createHash("md5").update(password).digest("hex");
      const result = import_crypto.default.createHash("sha1").update(md5pw + "_" + macFormatted).digest("hex");
      log.debug('TPAP extra_crypt passwd_id=3: sha1(md5(pw)+"_"+MAC)');
      return result;
    }
    if (passwdId === 5) {
      const rounds = params.passwd_rounds ? parseInt(params.passwd_rounds, 10) : void 0;
      const result = sha256Crypt(password, prefix, rounds);
      if (result) {
        log.debug("TPAP extra_crypt passwd_id=5: sha256_crypt");
        return result;
      }
      log.error("TPAP sha256_crypt failed, falling back to raw password");
      return password;
    }
    log.error(`TPAP unsupported passwd_id=${passwdId}`);
    return password;
  }
  if (cryptType === "password_authkey") {
    const tmpkey = String(params.authkey_tmpkey || "");
    const dictionary = String(params.authkey_dictionary || "");
    if (tmpkey && dictionary) {
      const maxLen = Math.max(tmpkey.length, password.length);
      let result = "";
      for (let i = 0; i < maxLen; i++) {
        const a = i < password.length ? password.charCodeAt(i) : 187;
        const b = i < tmpkey.length ? tmpkey.charCodeAt(i) : 187;
        const xored = a ^ b;
        result += dictionary[xored % dictionary.length];
      }
      log.debug("TPAP extra_crypt password_authkey: XOR derivation");
      return result;
    }
    log.error("TPAP password_authkey missing tmpkey/dictionary");
    return password;
  }
  if (cryptType === "password_sha_with_salt") {
    const shaName = parseInt(params.sha_name || "0", 10);
    const name = shaName === 0 ? "admin" : "user";
    const shaSalt = params.sha_salt ? Buffer.from(params.sha_salt, "base64") : Buffer.alloc(0);
    const result = import_crypto.default.createHash("sha256").update(name).update(shaSalt).update(password).digest("hex");
    log.debug(`TPAP extra_crypt password_sha_with_salt: SHA256(${name}+salt+pw)`);
    return result;
  }
  log.error(`TPAP unsupported extra_crypt type: ${cryptType}`);
  return password;
}
function macPassFromDeviceMac(mac) {
  const macHex = mac.replace(/[:-]/g, "");
  const macBytes = Buffer.from(macHex, "hex");
  if (macBytes.length < 6) {
    throw new Error("Device MAC too short for default passcode derivation");
  }
  const seed = Buffer.from("GqY5o136oa4i6VprTlMW2DpVXxmfW8");
  const ikm = Buffer.concat([seed, macBytes.subarray(3, 6), macBytes.subarray(0, 3)]);
  return Buffer.from(
    import_crypto.default.hkdfSync("sha256", ikm, Buffer.from("tp-kdf-salt-default-passcode"), Buffer.from("tp-kdf-info-default-passcode"), 32)
  ).toString("hex").toUpperCase();
}
class TpapCipher {
  constructor(log, ip, email, password, mac = "", port = 80, useHttps = false, ciphers) {
    this.log = log;
    this.ip = ip;
    this.email = email;
    this.password = password;
    this.mac = mac;
    this.port = port;
    this.useHttps = useHttps;
    this.ciphers = ciphers;
  }
  key;
  baseNonce;
  sequence;
  stok;
  cipherAlgorithm = "aes-128-ccm";
  tagLen = TAG_LEN;
  get baseUrl() {
    const proto = this.useHttps ? "https" : "http";
    const isDefault = this.useHttps && this.port === 443 || !this.useHttps && this.port === 80;
    const suffix = isDefault ? "" : ":" + this.port;
    return `${proto}://${this.ip}${suffix}`;
  }
  get sessionUrl() {
    return `${this.baseUrl}/stok=${this.stok}/ds`;
  }
  get isReady() {
    return !!this.key && !!this.baseNonce && !!this.stok;
  }
  /** Determine auth username hash based on device type and user_hash_type */
  getAuthUsername(pakeList, userHashType) {
    const isDefaultOrPlug = !pakeList.length || pakeList.includes(0) || pakeList.includes(2) || pakeList.includes(5);
    const rawUsername = isDefaultOrPlug ? "admin" : this.email || "admin";
    if (userHashType === 1) {
      return import_crypto.default.createHash("sha256").update(rawUsername).digest("hex").toUpperCase();
    }
    return import_crypto.default.createHash("md5").update(rawUsername).digest("hex");
  }
  /** Get passcode_type based on pake list */
  getPasscodeType(pakeList) {
    if (pakeList.includes(0)) return "default_userpw";
    if (pakeList.includes(2) || pakeList.includes(5)) return "userpw";
    if (pakeList.includes(1)) return "userpw";
    if (pakeList.includes(3)) return "shared_token";
    return "default_userpw";
  }
  /** Get candidate secrets to try, based on pake version */
  getCandidateSecrets(pakeList) {
    if (!pakeList.length || pakeList.includes(0)) {
      if (this.mac) {
        try {
          return [macPassFromDeviceMac(this.mac)];
        } catch (e) {
          this.log.debug("TPAP MAC default passcode failed: " + e.message);
        }
      }
      return [this.password];
    }
    const isSmartCam = pakeList.includes(3) || pakeList.includes(2) && !pakeList.includes(0);
    if (pakeList.includes(2)) {
      const md5pw = import_crypto.default.createHash("md5").update(this.password).digest("hex");
      const sha256pw = import_crypto.default.createHash("sha256").update(this.password).digest("hex").toUpperCase();
      const candidates = [this.password, md5pw, sha256pw];
      return [...new Set(candidates)];
    }
    if (pakeList.includes(1)) {
      return [this.password];
    }
    if (pakeList.includes(3)) {
      return [import_crypto.default.createHash("md5").update(this.password).digest("hex")];
    }
    return [this.password];
  }
  /** Full SPAKE2+ handshake: register → share → derive keys */
  async handshake(pakeList, userHashType) {
    const pake = pakeList || [];
    const candidates = this.getCandidateSecrets(pake);
    const isSmartCam = pake.includes(3) || pake.includes(2) && !!this.email;
    let lastError = null;
    for (const candidateSecret of candidates) {
      try {
        await this.tryHandshake(pake, userHashType || 0, candidateSecret, isSmartCam);
        return;
      } catch (e) {
        lastError = e;
        if (e.message && (e.message.includes("EHOSTUNREACH") || e.message.includes("ECONNREFUSED") || e.message.includes("ETIMEDOUT"))) {
          throw e;
        }
        this.log.debug(`TPAP candidate failed: ${e.message}`);
      }
    }
    throw lastError || new Error("TPAP handshake failed: no candidates");
  }
  /** Single handshake attempt with a specific candidate secret */
  async tryHandshake(pakeList, userHashType, candidateSecret, isSmartCam) {
    const axios = (await Promise.resolve().then(() => __toESM(require("axios")))).default;
    const https = await Promise.resolve().then(() => __toESM(require("https")));
    const baseUrl = this.baseUrl;
    this.log.debug(`TPAP tryHandshake baseUrl=${baseUrl}`);
    const httpsAgent = this.useHttps ? new https.Agent({ rejectUnauthorized: false, ...this.ciphers ? { ciphers: this.ciphers } : {} }) : void 0;
    const headers = {
      "Content-Type": "application/json; charset=UTF-8",
      Accept: "application/json",
      Connection: "Keep-Alive"
    };
    const authUsername = this.getAuthUsername(pakeList, userHashType);
    const userRandom = import_crypto.default.randomBytes(32);
    const passcodeType = this.getPasscodeType(pakeList);
    this.log.debug(`TPAP register to ${this.ip} with username=${authUsername}, passcode_type=${passcodeType}`);
    const registerPayload = {
      method: "login",
      params: {
        sub_method: "pake_register",
        username: authUsername,
        user_random: userRandom.toString("base64"),
        cipher_suites: [1],
        encryption: ["aes_128_ccm"],
        passcode_type: passcodeType,
        stok: null
      }
    };
    const r1 = await axios.post(baseUrl, registerPayload, { headers, timeout: 5e3, httpsAgent });
    if (r1.data.error_code !== 0) {
      throw new Error(`TPAP register failed: error_code=${r1.data.error_code}`);
    }
    const regResult = r1.data.result;
    const devRandom = Buffer.from(regResult.dev_random, "base64");
    const devSalt = Buffer.from(regResult.dev_salt, "base64");
    const devShareBytes = Buffer.from(regResult.dev_share, "base64");
    const iterations = regResult.iterations;
    const extraCrypt = regResult.extra_crypt;
    const negotiatedSuite = regResult.cipher_suites || 1;
    const negotiatedEncryption = regResult.encryption || "aes_128_ccm";
    this.log.debug(`TPAP register ok: suite=${negotiatedSuite}, encryption=${negotiatedEncryption}, iterations=${iterations}`);
    const suite = getSuiteConfig(negotiatedSuite);
    const cipherParams = CIPHER_PARAMS[negotiatedEncryption];
    if (!cipherParams) {
      throw new Error(`TPAP unsupported encryption: ${negotiatedEncryption}`);
    }
    this.cipherAlgorithm = cipherParams.algorithm;
    this.tagLen = TAG_LEN;
    let credential;
    if ((!pakeList.length || pakeList.includes(0)) && this.mac) {
      credential = candidateSecret;
    } else {
      const credUsername = isSmartCam ? "" : this.email || "";
      credential = resolveCredential(this.log, candidateSecret, credUsername, this.mac, extraCrypt, isSmartCam);
    }
    const hashLen = suite.digestLen;
    const idLen = hashLen + 8;
    const derived = import_crypto.default.pbkdf2Sync(Buffer.from(credential), devSalt, iterations, idLen * 2, suite.hashAlgo);
    const aBytes = derived.subarray(0, idLen);
    const bBytes = derived.subarray(idLen, idLen * 2);
    const ec = suite.curve;
    const order = ec.n;
    const gPoint = ec.g;
    const mPoint = ec.keyFromPublic(suite.mPoint).getPublic();
    const nPoint = ec.keyFromPublic(suite.nPoint).getPublic();
    const aValue = new import_bn.default(aBytes.toString("hex"), 16);
    const bValue = new import_bn.default(bBytes.toString("hex"), 16);
    const w0 = aValue.umod(order);
    const w1 = bValue.umod(order);
    let x;
    do {
      const rnd = import_crypto.default.randomBytes(48);
      x = new import_bn.default(rnd.toString("hex"), 16).umod(order);
    } while (x.isZero());
    const L = gPoint.mul(x).add(mPoint.mul(w0));
    const lEncoded = pointToUncompressed(L);
    const rPoint = ec.keyFromPublic(devShareBytes).getPublic();
    const rEncoded = pointToUncompressed(rPoint);
    const rPrime = rPoint.add(nPoint.mul(w0).neg());
    const zEncoded = pointToUncompressed(rPrime.mul(x));
    const vEncoded = pointToUncompressed(rPrime.mul(w1));
    const contextHash = import_crypto.default.createHash(suite.hashAlgo).update(Buffer.concat([PAKE_CONTEXT_TAG, userRandom, devRandom])).digest();
    const mEncoded = pointToUncompressed(mPoint);
    const nEncoded = pointToUncompressed(nPoint);
    const wEncoded = encodeW(w0);
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
      len8le(wEncoded)
    ]);
    const transcriptHash = import_crypto.default.createHash(suite.hashAlgo).update(transcript).digest();
    const macLen = suite.macLen;
    const confirmationKeys = hkdfExpand("ConfirmationKeys", transcriptHash, macLen * 2, suite.hashAlgo);
    const keyConfirmA = confirmationKeys.subarray(0, macLen);
    const keyConfirmB = confirmationKeys.subarray(macLen, macLen * 2);
    const sharedKey = hkdfExpand("SharedKey", transcriptHash, suite.digestLen, suite.hashAlgo);
    let userConfirm;
    let expectedDevConfirm;
    if (suite.macType === "cmac") {
      userConfirm = cmacAes128(keyConfirmA, rEncoded);
      expectedDevConfirm = cmacAes128(keyConfirmB, lEncoded);
    } else {
      userConfirm = import_crypto.default.createHmac(suite.hashAlgo, keyConfirmA).update(rEncoded).digest();
      expectedDevConfirm = import_crypto.default.createHmac(suite.hashAlgo, keyConfirmB).update(lEncoded).digest();
    }
    this.log.debug(`TPAP pake_share to ${this.ip}`);
    const sharePayload = {
      method: "login",
      params: {
        sub_method: "pake_share",
        user_share: lEncoded.toString("base64"),
        user_confirm: userConfirm.toString("base64")
      }
    };
    const r2 = await axios.post(baseUrl, sharePayload, { headers, timeout: 5e3, httpsAgent });
    if (r2.data.error_code !== 0) {
      throw new Error(`TPAP pake_share failed: error_code=${r2.data.error_code}`);
    }
    const shareResult = r2.data.result;
    const devConfirm = Buffer.from(shareResult.dev_confirm, "base64");
    if (!devConfirm.equals(expectedDevConfirm)) {
      throw new Error("TPAP device confirmation mismatch");
    }
    this.log.debug("TPAP device confirmation verified");
    this.stok = String(shareResult.sessionId || shareResult.stok || "");
    const startSeq = parseInt(shareResult.start_seq, 10);
    this.sequence = startSeq;
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
    const plaintext = Buffer.from(payload, "utf-8");
    let encrypted;
    let tag;
    if (this.cipherAlgorithm === "chacha20-poly1305") {
      const cipher = import_crypto.default.createCipheriv("chacha20-poly1305", this.key, nonce, { authTagLength: this.tagLen });
      encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      tag = cipher.getAuthTag();
    } else {
      const cipher = import_crypto.default.createCipheriv(this.cipherAlgorithm, this.key, nonce, { authTagLength: this.tagLen });
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
      throw new Error("TPAP response too short");
    }
    const responseSeq = data.readUInt32BE(0);
    const nonce = this.nonceFromBase(responseSeq);
    const ciphertextWithTag = data.subarray(4);
    const ciphertext = ciphertextWithTag.subarray(0, ciphertextWithTag.length - this.tagLen);
    const tag = ciphertextWithTag.subarray(ciphertextWithTag.length - this.tagLen);
    let decrypted;
    if (this.cipherAlgorithm === "chacha20-poly1305") {
      const decipher = import_crypto.default.createDecipheriv("chacha20-poly1305", this.key, nonce, { authTagLength: this.tagLen });
      decipher.setAuthTag(tag);
      decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } else {
      const decipher = import_crypto.default.createDecipheriv(this.cipherAlgorithm, this.key, nonce, { authTagLength: this.tagLen });
      decipher.setAuthTag(tag);
      decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    }
    return decrypted.toString("utf-8");
  }
}
//# sourceMappingURL=tpapCipher.js.map
