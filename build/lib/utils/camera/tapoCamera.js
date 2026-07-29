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
var tapoCamera_exports = {};
__export(tapoCamera_exports, {
  TAPOCamera: () => TAPOCamera
});
module.exports = __toCommonJS(tapoCamera_exports);
var import_crypto = __toESM(require("crypto"));
var import_onvifCamera = require("./onvifCamera");
var import_tpapCipher = __toESM(require("../tpapCipher.js"));
var import_undici = require("undici");
const MAX_LOGIN_RETRIES = 3;
const AES_BLOCK_SIZE = 16;
const ERROR_CODES_MAP = {
  "-40401": "Invalid stok value",
  "-40210": "Function not supported",
  "-64303": "Action cannot be done while camera is in patrol mode.",
  "-64324": "Privacy mode is ON, not able to execute",
  "-64302": "Preset ID not found",
  "-64321": "Preset ID was deleted so no longer exists",
  "-40106": "Parameter to get/do does not exist",
  "-40105": "Method does not exist",
  "-40101": "Parameter to set does not exist",
  "-40209": "Invalid login credentials",
  "-64304": "Maximum Pan/Tilt range reached",
  "-71103": "User ID is not authorized"
};
class TAPOCamera extends import_onvifCamera.OnvifCamera {
  constructor(log, config) {
    super(log, config);
    this.log = log;
    this.config = config;
    this.fetchAgent = new import_undici.Agent({
      connectTimeout: 5e3,
      connect: {
        // TAPO devices have self-signed certificates
        rejectUnauthorized: false,
        ciphers: "ECDHE-RSA-AES128-GCM-SHA256:AES256-GCM-SHA384:AES256-SHA256:AES128-GCM-SHA256:AES128-SHA256:AES256-SHA"
      }
    });
    this.cnonce = this.generateCnonce();
    const candidates = [config.password, "admin"];
    if (config.loginVersion === 3) {
      candidates.push("TPL075526460603");
    }
    this.passwordCandidates = [...new Set(candidates.filter(Boolean))];
    this.hashedPassword = import_crypto.default.createHash("md5").update(config.password).digest("hex").toUpperCase();
    this.hashedSha256Password = import_crypto.default.createHash("sha256").update(config.password).digest("hex").toUpperCase();
  }
  kStreamPort = 554;
  fetchAgent;
  // Active hashes for the currently matched credential candidate. Not readonly:
  // validateDeviceConfirm switches these to whichever candidate the device accepts,
  // so that digest_passwd, lsk/ivb and Tapo_tag stay consistent.
  hashedPassword;
  hashedSha256Password;
  passwordEncryptionMethod = null;
  // Candidate plaintext passwords tried during device_confirm validation.
  // Cloud password first, then camera defaults (matches python-kasa sslaestransport).
  passwordCandidates;
  isSecureConnectionValue = null;
  stokPromise;
  cnonce;
  lsk;
  ivb;
  seq;
  stok;
  suspendUntil = 0;
  // TPAP/SPAKE2+ path (newer camera firmware, FW 1.4.3+). When set and ready, the
  // stok/device_confirm flow is bypassed and requests go through this cipher instead.
  tpapCipher;
  // TPAP is disabled only after repeated failures (transient errors get retried).
  tpapFailCount = 0;
  static TPAP_MAX_FAILS = 3;
  // pake list resolved via TPAP HTTP discovery (fallback when UDP discovery lacks it).
  tpapPakeList;
  tpapUserHashType;
  // TLS ciphers accepted by Tapo cameras (self-signed, legacy suites).
  static CAMERA_CIPHERS = "ECDHE-RSA-AES128-GCM-SHA256:AES256-GCM-SHA384:AES256-SHA256:AES128-GCM-SHA256:AES128-SHA256:AES256-SHA";
  getUsername() {
    return this.config.username || "admin";
  }
  getHeaders() {
    return {
      Host: `${this.config.ipAddress}`,
      Referer: `https://${this.config.ipAddress}`,
      Accept: "application/json",
      "Accept-Encoding": "gzip, deflate",
      "User-Agent": "Tapo CameraClient Android",
      Connection: "close",
      requestByApp: "true",
      "Content-Type": "application/json; charset=UTF-8"
    };
  }
  getHashedPassword() {
    if (this.passwordEncryptionMethod === "md5") {
      return this.hashedPassword;
    } else if (this.passwordEncryptionMethod === "sha256") {
      return this.hashedSha256Password;
    } else {
      this.log.error("Unknown password encryption method");
    }
  }
  fetch(url, data) {
    return fetch(url, {
      headers: this.getHeaders(),
      // @ts-expect-error Dispatcher type not there
      dispatcher: this.fetchAgent,
      ...data
    });
  }
  generateEncryptionToken(tokenType, nonce) {
    const hashedKey = import_crypto.default.createHash("sha256").update(this.cnonce + this.getHashedPassword() + nonce).digest("hex").toUpperCase();
    return import_crypto.default.createHash("sha256").update(tokenType + this.cnonce + nonce + hashedKey).digest().slice(0, 16);
  }
  getAuthenticatedStreamUrl(lowQuality = false) {
    const prefix = `rtsp://${this.config.streamUser}:${this.config.streamPassword}@${this.config.ipAddress}:${this.kStreamPort}`;
    return lowQuality ? `${prefix}/stream2` : `${prefix}/stream1`;
  }
  generateCnonce() {
    return import_crypto.default.randomBytes(8).toString("hex").toUpperCase();
  }
  validateDeviceConfirm(nonce, deviceConfirm) {
    this.passwordEncryptionMethod = null;
    for (let i = 0; i < this.passwordCandidates.length; i++) {
      const candidate = this.passwordCandidates[i];
      const md5Hash = import_crypto.default.createHash("md5").update(candidate).digest("hex").toUpperCase();
      const sha256Hash = import_crypto.default.createHash("sha256").update(candidate).digest("hex").toUpperCase();
      const confirmSha256 = import_crypto.default.createHash("sha256").update(this.cnonce + sha256Hash + nonce).digest("hex").toUpperCase() + nonce + this.cnonce;
      if (deviceConfirm === confirmSha256) {
        this.hashedPassword = md5Hash;
        this.hashedSha256Password = sha256Hash;
        this.passwordEncryptionMethod = "sha256";
        this.log.debug(`validateDeviceConfirm: matched candidate #${i} via sha256`);
        return true;
      }
      const confirmMd5 = import_crypto.default.createHash("sha256").update(this.cnonce + md5Hash + nonce).digest("hex").toUpperCase() + nonce + this.cnonce;
      if (deviceConfirm === confirmMd5) {
        this.hashedPassword = md5Hash;
        this.hashedSha256Password = sha256Hash;
        this.passwordEncryptionMethod = "md5";
        this.log.debug(`validateDeviceConfirm: matched candidate #${i} via md5`);
        return true;
      }
    }
    this.log.debug("Invalid device confirm, no candidate password matched (sha256 or md5)", {
      deviceConfirm,
      nonce,
      candidates: this.passwordCandidates.length
    });
    return false;
  }
  async refreshStok(loginRetryCount = 0) {
    var _a, _b, _c, _d, _e, _f, _g, _h, _i, _j, _k, _l, _m, _n, _o;
    this.log.debug("refreshStok: Refreshing stok...");
    if (this.suspendUntil > Date.now()) {
      this.log.debug("refreshStok: Still suspended, skipping");
      return;
    }
    this.cnonce = this.generateCnonce();
    const isSecureConnection = await this.isSecureConnection();
    this.log.debug("refreshStok: isSecureConnection=" + isSecureConnection + " username=" + this.getUsername() + " cnonce=" + this.cnonce);
    if (this.suspendUntil > Date.now()) {
      this.log.debug("refreshStok: camera locked out (detected during probe), skipping login");
      return;
    }
    let fetchParams = {};
    if (isSecureConnection) {
      fetchParams = {
        method: "post",
        body: JSON.stringify({
          method: "login",
          params: {
            cnonce: this.cnonce,
            encrypt_type: "3",
            username: this.getUsername()
          }
        })
      };
    } else {
      fetchParams = {
        method: "post",
        body: JSON.stringify({
          method: "login",
          params: {
            username: this.getUsername(),
            password: this.hashedPassword,
            hashed: true
          }
        })
      };
    }
    const responseLogin = await this.fetch(`https://${this.config.ipAddress}`, fetchParams).catch((e) => {
      this.log.debug("refreshStok: Error during login", e);
      return null;
    });
    if (!responseLogin) {
      this.log.debug("refreshStok: empty response login, raising exception");
      this.log.error("Empty response login");
      return;
    }
    const responseLoginData = await responseLogin.json();
    let response, responseData;
    if (!responseLoginData) {
      this.log.debug("refreshStok: empty response login data, raising exception", responseLogin.status);
      this.log.error("Empty response login data");
    }
    this.log.debug("refreshStok: Login response status=" + responseLogin.status + " data=" + JSON.stringify(responseLoginData));
    if (responseLogin.status === 401 && ((_b = (_a = responseLoginData.result) == null ? void 0 : _a.data) == null ? void 0 : _b.code) === -40411) {
      this.log.debug("refreshStok: invalid credentials, raising exception", responseLogin.status);
      this.log.error("Invalid credentials");
    }
    if (isSecureConnection) {
      const nonce = (_d = (_c = responseLoginData.result) == null ? void 0 : _c.data) == null ? void 0 : _d.nonce;
      const deviceConfirm = (_f = (_e = responseLoginData.result) == null ? void 0 : _e.data) == null ? void 0 : _f.device_confirm;
      this.log.debug("refreshStok: nonce=" + (nonce ? nonce.substring(0, 16) + "..." : "null") + " deviceConfirm=" + (deviceConfirm ? deviceConfirm.substring(0, 16) + "..." : "null"));
      if (nonce && deviceConfirm && this.validateDeviceConfirm(nonce, deviceConfirm)) {
        this.log.debug("refreshStok: deviceConfirm validated, encryptionMethod=" + this.passwordEncryptionMethod);
        const digestPasswd = import_crypto.default.createHash("sha256").update(this.getHashedPassword() + this.cnonce + nonce).digest("hex").toUpperCase();
        const digestPasswdFull = Buffer.concat([
          Buffer.from(digestPasswd, "utf8"),
          Buffer.from(this.cnonce, "utf8"),
          Buffer.from(nonce, "utf8")
        ]).toString("utf8");
        this.log.debug("refreshStok: sending start_seq request");
        response = await this.fetch(`https://${this.config.ipAddress}`, {
          method: "POST",
          body: JSON.stringify({
            method: "login",
            params: {
              cnonce: this.cnonce,
              encrypt_type: "3",
              digest_passwd: digestPasswdFull,
              username: this.getUsername()
            }
          })
        });
        responseData = await response.json();
        if (!responseData) {
          this.log.debug("refreshStock: empty response start_seq data, raising exception", response.status);
          this.log.error("Empty response start_seq data");
          return;
        }
        this.log.debug("refreshStok: start_seq response", response.status, JSON.stringify(responseData));
        if (((_g = responseData.result) == null ? void 0 : _g.start_seq) !== void 0) {
          this.log.debug("refreshStok: start_seq=" + responseData.result.start_seq + " user_group=" + ((_h = responseData.result) == null ? void 0 : _h.user_group) + " stok=" + (((_i = responseData.result) == null ? void 0 : _i.stok) ? "present" : "missing"));
          if (((_j = responseData.result) == null ? void 0 : _j.user_group) !== "root") {
            this.log.debug("refreshStock: Incorrect user_group detected");
            this.log.error("Incorrect user_group detected");
          }
          this.lsk = this.generateEncryptionToken("lsk", nonce);
          this.ivb = this.generateEncryptionToken("ivb", nonce);
          this.seq = responseData.result.start_seq;
        }
      } else {
        if ((responseLoginData.error_code === -40413 || responseLoginData.error_code === -40211) && loginRetryCount < MAX_LOGIN_RETRIES) {
          this.log.debug(
            `refreshStock: Invalid device confirm, retrying: ${loginRetryCount}/${MAX_LOGIN_RETRIES}.`,
            responseLogin.status,
            responseLoginData
          );
          this.isSecureConnectionValue = null;
          return this.refreshStok(loginRetryCount + 1);
        }
        this.log.debug(
          "refreshStock: Invalid device confirm and loginRetryCount exhausted, raising exception",
          loginRetryCount,
          responseLoginData
        );
        this.isSecureConnectionValue = null;
        this.log.error("Invalid device confirm. Please activate 3rd Patry support in the TP App under TP Labor -> 3rd Party Control");
        return;
      }
    } else {
      this.passwordEncryptionMethod = "md5";
      response = responseLogin;
      responseData = responseLoginData;
    }
    if (((_l = (_k = responseData.result) == null ? void 0 : _k.data) == null ? void 0 : _l.sec_left) && responseData.result.data.sec_left > 0) {
      this.log.debug("refreshStok: temporary suspension", responseData);
      this.suspendUntil = Date.now() + responseData.result.data.sec_left * 1e3;
      this.log.error(`Temporary Suspension: Try again in ${responseData.result.data.sec_left} seconds`);
      return;
    }
    if (responseData && responseData.result && responseData.result.responses && responseData.result.responses[0].error_code !== 0) {
      this.log.debug(
        `API request failed with specific error code ${responseData.result.responses[0].error_code}: ${responseData.result.responses[0].error_message}`
      );
    }
    if (((_m = responseData == null ? void 0 : responseData.data) == null ? void 0 : _m.code) === -40404 && ((_n = responseData == null ? void 0 : responseData.data) == null ? void 0 : _n.sec_left) && responseData.data.sec_left > 0) {
      this.log.debug("refreshStok: temporary suspension", responseData);
      this.suspendUntil = Date.now() + responseData.data.sec_left * 1e3;
      this.log.error(`refreshStok: Temporary Suspension: Try again in ${responseData.data.sec_left} seconds`);
      return;
    }
    if ((_o = responseData == null ? void 0 : responseData.result) == null ? void 0 : _o.stok) {
      this.stok = responseData.result.stok;
      this.log.debug("refreshStok: Success in obtaining STOK", this.stok);
      return;
    }
    if (((responseData == null ? void 0 : responseData.error_code) === -40413 || (responseData == null ? void 0 : responseData.error_code) === -40211) && loginRetryCount < MAX_LOGIN_RETRIES) {
      this.log.debug(
        `refreshStock: Unexpected response, retrying: ${loginRetryCount}/${MAX_LOGIN_RETRIES}.`,
        response.status,
        responseData
      );
      this.isSecureConnectionValue = null;
      return this.refreshStok(loginRetryCount + 1);
    }
    this.log.debug("refreshStock: Unexpected end of flow, responseData=" + JSON.stringify(responseData));
    this.isSecureConnectionValue = null;
    this.log.error("Invalid authentication data");
  }
  async isSecureConnection() {
    var _a, _b, _c, _d, _e, _f;
    if (this.suspendUntil > Date.now()) {
      this.log.debug("isSecureConnection: camera suspended, skipping probe");
      return this.isSecureConnectionValue === true;
    }
    if (this.isSecureConnectionValue === null) {
      this.log.debug("isSecureConnection: Checking secure connection...");
      const probeCnonce = import_crypto.default.randomBytes(8).toString("hex").toUpperCase();
      const response = await this.fetch(`https://${this.config.ipAddress}`, {
        method: "post",
        headers: this.getHeaders(),
        body: JSON.stringify({
          method: "login",
          params: {
            encrypt_type: "3",
            username: this.getUsername(),
            cnonce: probeCnonce
          }
        })
      });
      const responseData = await response.json();
      this.log.debug("isSecureConnection response status=" + response.status + " data=" + JSON.stringify(responseData));
      const secLeft = (_a = responseData == null ? void 0 : responseData.data) == null ? void 0 : _a.sec_left;
      const innerCode = (_b = responseData == null ? void 0 : responseData.data) == null ? void 0 : _b.code;
      if (innerCode === -40404 && secLeft > 0) {
        this.suspendUntil = Date.now() + secLeft * 1e3;
        this.log.error(`Temporary Suspension: Try again in ${secLeft} seconds`);
        this.isSecureConnectionValue = null;
        return false;
      }
      const errorCode = responseData == null ? void 0 : responseData.error_code;
      const encryptType = String(((_d = (_c = responseData == null ? void 0 : responseData.result) == null ? void 0 : _c.data) == null ? void 0 : _d.encrypt_type) || "");
      const hasNonce = !!((_f = (_e = responseData == null ? void 0 : responseData.result) == null ? void 0 : _e.data) == null ? void 0 : _f.nonce);
      this.isSecureConnectionValue = errorCode === -40413 && encryptType.includes("3") || errorCode === -40211 || hasNonce;
      this.log.debug("isSecureConnection result=" + this.isSecureConnectionValue + " errorCode=" + errorCode + " encryptType=" + encryptType + " hasNonce=" + hasNonce);
    }
    return this.isSecureConnectionValue;
  }
  getStok(loginRetryCount = 0) {
    return new Promise((resolve) => {
      if (this.stok) {
        return resolve(this.stok);
      }
      if (!this.stokPromise) {
        this.stokPromise = () => this.refreshStok(loginRetryCount);
      }
      this.stokPromise().then(() => {
        if (!this.stok) {
          if (this.suspendUntil > Date.now()) {
            this.log.debug("STOK not found (camera suspended)");
          } else {
            this.log.error("STOK not found");
          }
        }
        resolve(this.stok);
      }).finally(() => {
        this.stokPromise = void 0;
      });
    });
  }
  async getAuthenticatedAPIURL(loginRetryCount = 0) {
    const token = await this.getStok(loginRetryCount);
    return `https://${this.config.ipAddress}/stok=${token}/ds`;
  }
  encryptRequest(request) {
    const cipher = import_crypto.default.createCipheriv("aes-128-cbc", this.lsk, this.ivb);
    let ct_bytes = cipher.update(this.encryptPad(request, AES_BLOCK_SIZE), "utf-8", "hex");
    ct_bytes += cipher.final("hex");
    return Buffer.from(ct_bytes, "hex");
  }
  encryptPad(text, blocksize) {
    const padSize = blocksize - text.length % blocksize;
    const padding = String.fromCharCode(padSize).repeat(padSize);
    return text + padding;
  }
  decryptResponse(response) {
    const decipher = import_crypto.default.createDecipheriv("aes-128-cbc", this.lsk, this.ivb);
    let decrypted = decipher.update(response, "base64", "utf-8");
    decrypted += decipher.final("utf-8");
    return this.encryptUnpad(decrypted, AES_BLOCK_SIZE);
  }
  encryptUnpad(text, blockSize) {
    const paddingLength = Number(text[text.length - 1]) || 0;
    if (paddingLength > blockSize || paddingLength > text.length) {
      this.log.error("Invalid padding");
    }
    for (let i = text.length - paddingLength; i < text.length; i++) {
      if (text.charCodeAt(i) !== paddingLength) {
        this.log.error("Invalid padding");
      }
    }
    return text.slice(0, text.length - paddingLength).toString();
  }
  getTapoTag(request) {
    const tag = import_crypto.default.createHash("sha256").update(this.getHashedPassword() + this.cnonce).digest("hex").toUpperCase();
    return import_crypto.default.createHash("sha256").update(tag + JSON.stringify(request) + this.seq.toString()).digest("hex").toUpperCase();
  }
  /** Whether UDP discovery flagged this camera as TPAP/SPAKE2+ capable. */
  isTpapCapable() {
    var _a, _b;
    return this.config.encryptType === "TPAP" || !!this.config.tpapPreferred || ((_b = (_a = this.config.pake) == null ? void 0 : _a.length) != null ? _b : 0) > 0;
  }
  /**
   * TPAP HTTP discovery: POST {method:login, params:{sub_method:discover}} to fetch
   * the pake list / mac / user_hash_type. Mirrors P100.handshake_tpap().
   * Returns true only when the device genuinely advertises a TPAP pake list.
   *
   * IMPORTANT: we do NOT default to a pake list when discovery is silent. A blind
   * SPAKE2+ handshake against a plain stok camera counts as a failed login and can
   * trigger the device's lockout (error -40404 sec_left). Only handshake when the
   * device actually reports TPAP support.
   */
  async tpapDiscover(tpapPort, useHttps) {
    var _a, _b, _c, _d, _e, _f, _g;
    if ((_a = this.config.pake) == null ? void 0 : _a.length) {
      this.tpapPakeList = this.config.pake;
      this.tpapUserHashType = this.config.userHashType;
      return true;
    }
    if ((_b = this.tpapPakeList) == null ? void 0 : _b.length) {
      return true;
    }
    const axios = (await Promise.resolve().then(() => __toESM(require("axios")))).default;
    const https = await Promise.resolve().then(() => __toESM(require("https")));
    const proto = useHttps ? "https" : "http";
    const isDefault = useHttps && tpapPort === 443 || !useHttps && tpapPort === 80;
    const baseUrl = `${proto}://${this.config.ipAddress}${isDefault ? "" : ":" + tpapPort}`;
    const httpsAgent = useHttps ? new https.Agent({ rejectUnauthorized: false, ciphers: TAPOCamera.CAMERA_CIPHERS }) : void 0;
    try {
      const res = await axios.post(
        baseUrl + "/",
        { method: "login", params: { sub_method: "discover" } },
        { timeout: 5e3, httpsAgent }
      );
      const tpap = (_d = (_c = res.data) == null ? void 0 : _c.result) == null ? void 0 : _d.tpap;
      this.log.debug(`TPAP camera discover response: ${JSON.stringify((_g = (_f = (_e = res.data) == null ? void 0 : _e.result) == null ? void 0 : _f.tpap) != null ? _g : res.data)}`);
      if (Array.isArray(tpap == null ? void 0 : tpap.pake) && tpap.pake.length) {
        this.tpapPakeList = tpap.pake;
        if (tpap.user_hash_type != null) {
          this.tpapUserHashType = tpap.user_hash_type;
        }
        this.log.debug(`TPAP camera discover: pake=${JSON.stringify(this.tpapPakeList)} user_hash_type=${this.tpapUserHashType}`);
        return true;
      }
    } catch (e) {
      this.log.debug(`TPAP camera discover failed: ${(e == null ? void 0 : e.message) || e}`);
    }
    this.log.debug(`TPAP camera discover: no pake info for ${this.config.ipAddress}, TPAP not available`);
    return false;
  }
  /**
   * Establish a TPAP/SPAKE2+ session (newer camera firmware, FW 1.4.3+).
   * Reuses the plug SPAKE2+ handshake (TpapCipher) over HTTPS. Returns true on success.
   * Only handshakes when TPAP discovery confirms support, to avoid failed-login
   * lockouts on plain stok cameras. Disabled after TPAP_MAX_FAILS failures.
   */
  async tryTpapHandshake() {
    var _a;
    const tpapPort = this.config.tpapPort || 443;
    const useHttps = this.config.tpapTls === void 0 ? true : this.config.tpapTls === 1;
    this.log.debug(
      `TPAP camera discovery info for ${this.config.ipAddress}: encryptType=${this.config.encryptType} tpapPreferred=${this.config.tpapPreferred} pake=${JSON.stringify(this.config.pake)} userHashType=${this.config.userHashType} tpapPort=${this.config.tpapPort} tpapTls=${this.config.tpapTls} mac=${this.config.mac} loginVersion=${this.config.loginVersion}`
    );
    try {
      if (!await this.tpapDiscover(tpapPort, useHttps)) {
        this.tpapFailCount = TAPOCamera.TPAP_MAX_FAILS;
        return false;
      }
      const pakeList = this.tpapPakeList;
      const userHashType = (_a = this.config.userHashType) != null ? _a : this.tpapUserHashType;
      this.log.debug(`TPAP camera handshake to ${this.config.ipAddress}:${tpapPort} useHttps=${useHttps} pake=${JSON.stringify(pakeList)}`);
      const cipher = new import_tpapCipher.default(
        this.log,
        this.config.ipAddress,
        this.config.username || "",
        this.config.password,
        this.config.mac || "",
        tpapPort,
        useHttps,
        TAPOCamera.CAMERA_CIPHERS
      );
      await cipher.handshake(pakeList, userHashType);
      if (cipher.isReady) {
        this.tpapCipher = cipher;
        this.tpapFailCount = 0;
        this.log.info(`TPAP camera session established for ${this.config.ipAddress}`);
        return true;
      }
      this.log.debug(`TPAP camera handshake for ${this.config.ipAddress} returned but cipher not ready`);
    } catch (e) {
      this.log.debug(`TPAP camera handshake failed for ${this.config.ipAddress}: ${(e == null ? void 0 : e.message) || e}`);
    }
    this.tpapFailCount += 1;
    if (this.tpapFailCount >= TAPOCamera.TPAP_MAX_FAILS) {
      this.log.debug(`TPAP camera handshake disabled for ${this.config.ipAddress} after ${this.tpapFailCount} failures`);
    }
    return false;
  }
  /** Send an already-built request through the TPAP/SPAKE2+ session. */
  async tpapApiRequest(req) {
    const axios = (await Promise.resolve().then(() => __toESM(require("axios")))).default;
    const https = await Promise.resolve().then(() => __toESM(require("https")));
    const cipher = this.tpapCipher;
    const httpsAgent = new https.Agent({ rejectUnauthorized: false, ciphers: TAPOCamera.CAMERA_CIPHERS });
    try {
      this.log.debug(`TPAP camera request to ${cipher.sessionUrl}: ${JSON.stringify(req)}`);
      const encrypted = cipher.encrypt(JSON.stringify(req));
      const res = await axios.post(cipher.sessionUrl, encrypted.data, {
        timeout: 1e4,
        responseType: "arraybuffer",
        httpsAgent,
        headers: { "Content-Type": "application/octet-stream", Connection: "Keep-Alive" }
      });
      const buf = Buffer.isBuffer(res.data) ? res.data : Buffer.from(res.data);
      const responseData = JSON.parse(cipher.decrypt(buf));
      this.log.debug("TPAP camera response status=" + res.status + " data=" + JSON.stringify(responseData));
      return responseData;
    } catch (e) {
      this.log.debug("TPAP camera request failed: " + ((e == null ? void 0 : e.message) || e));
      this.tpapCipher = void 0;
      return {};
    }
  }
  pendingAPIRequests = /* @__PURE__ */ new Map();
  async apiRequest(req, loginRetryCount = 0) {
    const reqJson = JSON.stringify(req);
    if (this.pendingAPIRequests.has(reqJson)) {
      this.log.debug("API request already pending", reqJson);
      return this.pendingAPIRequests.get(reqJson);
    } else {
      this.log.debug("New API request", reqJson);
    }
    this.pendingAPIRequests.set(
      reqJson,
      (async () => {
        var _a, _b;
        try {
          if ((_a = this.tpapCipher) == null ? void 0 : _a.isReady) {
            return await this.tpapApiRequest(req);
          }
          const isSecureConnection = await this.isSecureConnection();
          const url = await this.getAuthenticatedAPIURL(loginRetryCount);
          if (!this.stok && this.suspendUntil <= Date.now() && this.tpapFailCount < TAPOCamera.TPAP_MAX_FAILS) {
            this.log.debug(
              `stok login unavailable, attempting TPAP/SPAKE2+ for ${this.config.ipAddress} (tpapCapable=${this.isTpapCapable()})`
            );
            if (await this.tryTpapHandshake()) {
              return await this.tpapApiRequest(req);
            }
          }
          const fetchParams = {
            method: "post"
          };
          if (this.seq && isSecureConnection) {
            const encryptedRequest = {
              method: "securePassthrough",
              params: {
                request: Buffer.from(this.encryptRequest(JSON.stringify(req))).toString("base64")
              }
            };
            fetchParams.headers = {
              ...this.getHeaders(),
              Tapo_tag: this.getTapoTag(encryptedRequest),
              Seq: this.seq.toString()
            };
            fetchParams.body = JSON.stringify(encryptedRequest);
            this.seq += 1;
          } else {
            fetchParams.body = JSON.stringify(req);
          }
          const response = await this.fetch(url, fetchParams).catch((e) => {
            this.log.debug("Error during camera fetch", e);
            return;
          });
          if (!response) {
            this.log.debug("API request failed, empty response");
            return {};
          }
          const responseDataTmp = await response.json();
          if (isSecureConnection && response.status === 500) {
            this.log.debug("Stok expired, reauthenticating on next request, setting STOK to undefined");
            this.stok = void 0;
          }
          let responseData = null;
          if (isSecureConnection) {
            const encryptedResponse = responseDataTmp;
            if ((_b = encryptedResponse == null ? void 0 : encryptedResponse.result) == null ? void 0 : _b.response) {
              const decryptedResponse = this.decryptResponse(encryptedResponse.result.response);
              responseData = JSON.parse(decryptedResponse);
            }
          } else {
            responseData = responseDataTmp;
          }
          this.log.debug("API response", response.status, JSON.stringify(responseData));
          if (responseData && responseData.error_code !== 0) {
            const errorCode = String(responseData.error_code);
            const errorMessage = errorCode in ERROR_CODES_MAP ? ERROR_CODES_MAP[errorCode] : "Unknown error";
            this.log.debug(`API request failed with specific error code ${errorCode}: ${errorMessage}`);
          }
          if (!responseData || responseData.error_code === -40401 || responseData.error_code === -1) {
            this.log.debug("API request failed", responseData);
            this.stok = void 0;
            return {};
          }
          return responseData;
        } finally {
          this.pendingAPIRequests.delete(reqJson);
        }
      })()
    );
    return this.pendingAPIRequests.get(reqJson);
  }
  static SERVICE_MAP = {
    eyes: (value) => ({
      method: "setLensMaskConfig",
      params: {
        lens_mask: {
          lens_mask_info: {
            // Watch out for the inversion
            enabled: value ? "off" : "on"
          }
        }
      }
    }),
    alarm: (value) => ({
      method: "setAlertConfig",
      params: {
        msg_alarm: {
          chn1_msg_alarm_info: {
            enabled: value ? "on" : "off"
          }
        }
      }
    }),
    notifications: (value) => ({
      method: "setMsgPushConfig",
      params: {
        msg_push: {
          chn1_msg_push_info: {
            notification_enabled: value ? "on" : "off",
            rich_notification_enabled: value ? "on" : "off"
          }
        }
      }
    }),
    motionDetection: (value) => ({
      method: "setDetectionConfig",
      params: {
        motion_detection: {
          motion_det: {
            enabled: value ? "on" : "off"
          }
        }
      }
    }),
    led: (value) => ({
      method: "setLedStatus",
      params: {
        led: {
          config: {
            enabled: value ? "on" : "off"
          }
        }
      }
    }),
    autoTrack: (value) => ({
      method: "setTargetTrackConfig",
      params: {
        target_track: {
          target_track_info: {
            enabled: value ? "on" : "off"
          }
        }
      }
    }),
    personDetection: (value) => ({
      method: "setPersonDetectionConfig",
      params: {
        people_detection: {
          detection: {
            enabled: value ? "on" : "off"
          }
        }
      }
    }),
    vehicleDetection: (value) => ({
      method: "setVehicleDetectionConfig",
      params: {
        vehicle_detection: {
          detection: {
            enabled: value ? "on" : "off"
          }
        }
      }
    }),
    petDetection: (value) => ({
      method: "setPetDetectionConfig",
      params: {
        pet_detection: {
          detection: {
            enabled: value ? "on" : "off"
          }
        }
      }
    }),
    babyCryDetection: (value) => ({
      method: "setBCDConfig",
      params: {
        sound_detection: {
          bcd: {
            enabled: value ? "on" : "off"
          }
        }
      }
    }),
    barkDetection: (value) => ({
      method: "setBarkDetectionConfig",
      params: {
        bark_detection: {
          detection: {
            enabled: value ? "on" : "off"
          }
        }
      }
    }),
    meowDetection: (value) => ({
      method: "setMeowDetectionConfig",
      params: {
        meow_detection: {
          detection: {
            enabled: value ? "on" : "off"
          }
        }
      }
    }),
    glassBreakDetection: (value) => ({
      method: "setGlassDetectionConfig",
      params: {
        glass_detection: {
          detection: {
            enabled: value ? "on" : "off"
          }
        }
      }
    }),
    tamperDetection: (value) => ({
      method: "setTamperDetectionConfig",
      params: {
        tamper_detection: {
          tamper_det: {
            enabled: value ? "on" : "off"
          }
        }
      }
    }),
    imageFlip: (value) => ({
      method: "setLdc",
      params: {
        image: {
          switch: {
            flip_type: value ? "center" : "off"
          }
        }
      }
    }),
    ldc: (value) => ({
      method: "setLdc",
      params: {
        image: {
          switch: {
            ldc: value ? "on" : "off"
          }
        }
      }
    }),
    recordAudio: (value) => ({
      method: "setRecordAudio",
      params: {
        audio_config: {
          record_audio: {
            enabled: value ? "on" : "off"
          }
        }
      }
    }),
    autoUpgrade: (value) => ({
      method: "setFirmwareAutoUpgradeConfig",
      params: {
        auto_upgrade: {
          common: {
            enabled: value ? "on" : "off"
          }
        }
      }
    })
  };
  async setStatus(service, value) {
    const responseData = await this.apiRequest({
      method: "multipleRequest",
      params: {
        requests: [TAPOCamera.SERVICE_MAP[service](value)]
      }
    });
    if (responseData.error_code !== 0) {
      this.log.error(`Failed to perform ${service} action`);
    }
    const method = TAPOCamera.SERVICE_MAP[service](value).method;
    const operation = responseData.result.responses.find((e) => e.method === method);
    if ((operation == null ? void 0 : operation.error_code) !== 0) {
      this.log.error(`Failed to perform ${service} action`);
    }
    return operation == null ? void 0 : operation.result;
  }
  async getBasicInfo() {
    const responseData = await this.apiRequest({
      method: "multipleRequest",
      params: {
        requests: [
          {
            method: "getDeviceInfo",
            params: {
              device_info: {
                name: ["basic_info"]
              }
            }
          }
        ]
      }
    });
    const info = responseData.result.responses[0];
    return info.result.device_info.basic_info;
  }
  async getStatus() {
    var _a, _b, _c, _d, _e, _f, _g, _h, _i, _j, _k, _l, _m, _n, _o, _p, _q, _r, _s, _t, _u, _v, _w, _x, _y, _z, _A, _B, _C, _D, _E, _F, _G, _H, _I, _J, _K, _L, _M, _N, _O, _P, _Q, _R, _S, _T, _U, _V, _W, _X, _Y, _Z, __, _$;
    const responseData = await this.apiRequest({
      method: "multipleRequest",
      params: {
        requests: [
          { method: "getAlertConfig", params: { msg_alarm: { name: "chn1_msg_alarm_info" } } },
          { method: "getLensMaskConfig", params: { lens_mask: { name: "lens_mask_info" } } },
          { method: "getMsgPushConfig", params: { msg_push: { name: "chn1_msg_push_info" } } },
          { method: "getDetectionConfig", params: { motion_detection: { name: "motion_det" } } },
          { method: "getLedStatus", params: { led: { name: "config" } } },
          { method: "getTargetTrackConfig", params: { target_track: { name: ["target_track_info"] } } },
          { method: "getPersonDetectionConfig", params: { people_detection: { name: ["detection"] } } },
          { method: "getVehicleDetectionConfig", params: { vehicle_detection: { name: ["detection"] } } },
          { method: "getPetDetectionConfig", params: { pet_detection: { name: ["detection"] } } },
          { method: "getBCDConfig", params: { sound_detection: { name: ["bcd"] } } },
          { method: "getBarkDetectionConfig", params: { bark_detection: { name: ["detection"] } } },
          { method: "getMeowDetectionConfig", params: { meow_detection: { name: ["detection"] } } },
          { method: "getGlassDetectionConfig", params: { glass_detection: { name: ["detection"] } } },
          { method: "getTamperDetectionConfig", params: { tamper_detection: { name: ["tamper_det"] } } },
          { method: "getRotationStatus", params: { image: { name: ["switch"] } } },
          { method: "getLdc", params: { image: { name: ["switch"] } } },
          { method: "getAudioConfig", params: { audio_config: { name: ["record_audio"] } } },
          { method: "getFirmwareAutoUpgradeConfig", params: { auto_upgrade: { name: ["common"] } } }
        ]
      }
    });
    if (!responseData || !responseData.result || !responseData.result.responses) {
      this.log.debug("No response data found");
      return {
        alarm: void 0,
        eyes: void 0,
        notifications: void 0,
        motionDetection: void 0,
        led: void 0,
        autoTrack: void 0,
        personDetection: void 0,
        vehicleDetection: void 0,
        petDetection: void 0,
        babyCryDetection: void 0,
        barkDetection: void 0,
        meowDetection: void 0,
        glassBreakDetection: void 0,
        tamperDetection: void 0,
        imageFlip: void 0,
        ldc: void 0,
        recordAudio: void 0,
        autoUpgrade: void 0
      };
    }
    const ops = responseData.result.responses;
    const find = (m) => ops.find((r) => r.method === m);
    const alert = find("getAlertConfig");
    const lensMask = find("getLensMaskConfig");
    const notifications = find("getMsgPushConfig");
    const motionDetection = find("getDetectionConfig");
    const led = find("getLedStatus");
    const autoTrack = find("getTargetTrackConfig");
    const personDet = find("getPersonDetectionConfig");
    const vehicleDet = find("getVehicleDetectionConfig");
    const petDet = find("getPetDetectionConfig");
    const babyCry = find("getBCDConfig");
    const bark = find("getBarkDetectionConfig");
    const meow = find("getMeowDetectionConfig");
    const glass = find("getGlassDetectionConfig");
    const tamper = find("getTamperDetectionConfig");
    const rotation = find("getRotationStatus");
    const ldcResp = find("getLdc");
    const audio = find("getAudioConfig");
    const autoUpg = find("getFirmwareAutoUpgradeConfig");
    return {
      alarm: ((_c = (_b = (_a = alert == null ? void 0 : alert.result) == null ? void 0 : _a.msg_alarm) == null ? void 0 : _b.chn1_msg_alarm_info) == null ? void 0 : _c.enabled) === "on" ? true : alert ? false : void 0,
      eyes: ((_f = (_e = (_d = lensMask == null ? void 0 : lensMask.result) == null ? void 0 : _d.lens_mask) == null ? void 0 : _e.lens_mask_info) == null ? void 0 : _f.enabled) === "off" ? true : lensMask ? false : void 0,
      notifications: ((_i = (_h = (_g = notifications == null ? void 0 : notifications.result) == null ? void 0 : _g.msg_push) == null ? void 0 : _h.chn1_msg_push_info) == null ? void 0 : _i.notification_enabled) === "on" ? true : notifications ? false : void 0,
      motionDetection: ((_l = (_k = (_j = motionDetection == null ? void 0 : motionDetection.result) == null ? void 0 : _j.motion_detection) == null ? void 0 : _k.motion_det) == null ? void 0 : _l.enabled) === "on" ? true : motionDetection ? false : void 0,
      led: ((_o = (_n = (_m = led == null ? void 0 : led.result) == null ? void 0 : _m.led) == null ? void 0 : _n.config) == null ? void 0 : _o.enabled) === "on" ? true : led ? false : void 0,
      autoTrack: ((_r = (_q = (_p = autoTrack == null ? void 0 : autoTrack.result) == null ? void 0 : _p.target_track) == null ? void 0 : _q.target_track_info) == null ? void 0 : _r.enabled) === "on" ? true : autoTrack ? false : void 0,
      personDetection: ((_u = (_t = (_s = personDet == null ? void 0 : personDet.result) == null ? void 0 : _s.people_detection) == null ? void 0 : _t.detection) == null ? void 0 : _u.enabled) === "on" ? true : personDet ? false : void 0,
      vehicleDetection: ((_x = (_w = (_v = vehicleDet == null ? void 0 : vehicleDet.result) == null ? void 0 : _v.vehicle_detection) == null ? void 0 : _w.detection) == null ? void 0 : _x.enabled) === "on" ? true : vehicleDet ? false : void 0,
      petDetection: ((_A = (_z = (_y = petDet == null ? void 0 : petDet.result) == null ? void 0 : _y.pet_detection) == null ? void 0 : _z.detection) == null ? void 0 : _A.enabled) === "on" ? true : petDet ? false : void 0,
      babyCryDetection: ((_D = (_C = (_B = babyCry == null ? void 0 : babyCry.result) == null ? void 0 : _B.sound_detection) == null ? void 0 : _C.bcd) == null ? void 0 : _D.enabled) === "on" ? true : babyCry ? false : void 0,
      barkDetection: ((_G = (_F = (_E = bark == null ? void 0 : bark.result) == null ? void 0 : _E.bark_detection) == null ? void 0 : _F.detection) == null ? void 0 : _G.enabled) === "on" ? true : bark ? false : void 0,
      meowDetection: ((_J = (_I = (_H = meow == null ? void 0 : meow.result) == null ? void 0 : _H.meow_detection) == null ? void 0 : _I.detection) == null ? void 0 : _J.enabled) === "on" ? true : meow ? false : void 0,
      glassBreakDetection: ((_M = (_L = (_K = glass == null ? void 0 : glass.result) == null ? void 0 : _K.glass_detection) == null ? void 0 : _L.detection) == null ? void 0 : _M.enabled) === "on" ? true : glass ? false : void 0,
      tamperDetection: ((_P = (_O = (_N = tamper == null ? void 0 : tamper.result) == null ? void 0 : _N.tamper_detection) == null ? void 0 : _O.tamper_det) == null ? void 0 : _P.enabled) === "on" ? true : tamper ? false : void 0,
      imageFlip: ((_S = (_R = (_Q = rotation == null ? void 0 : rotation.result) == null ? void 0 : _Q.image) == null ? void 0 : _R.switch) == null ? void 0 : _S.flip_type) === "center" ? true : rotation ? false : void 0,
      ldc: ((_V = (_U = (_T = ldcResp == null ? void 0 : ldcResp.result) == null ? void 0 : _T.image) == null ? void 0 : _U.switch) == null ? void 0 : _V.ldc) === "on" ? true : ldcResp ? false : void 0,
      recordAudio: ((_Y = (_X = (_W = audio == null ? void 0 : audio.result) == null ? void 0 : _W.audio_config) == null ? void 0 : _X.record_audio) == null ? void 0 : _Y.enabled) === "on" ? true : audio ? false : void 0,
      autoUpgrade: ((_$ = (__ = (_Z = autoUpg == null ? void 0 : autoUpg.result) == null ? void 0 : _Z.auto_upgrade) == null ? void 0 : __.common) == null ? void 0 : _$.enabled) === "on" ? true : autoUpg ? false : void 0
    };
  }
  async setForceWhitelampState(value) {
    const json = await this.apiRequest({
      method: "multipleRequest",
      params: {
        requests: [
          {
            method: "setForceWhitelampState",
            params: {
              image: {
                switch: {
                  force_wtl_state: value ? "on" : "off"
                }
              }
            }
          }
        ]
      }
    });
    return json.error_code !== 0;
  }
  async moveMotorStep(angle) {
    angle = angle.toString();
    const json = await this.apiRequest({ method: "do", motor: { movestep: { direction: angle } } });
    return json.error_code !== 0;
  }
  async moveToPreset(presetId) {
    const json = await this.apiRequest({
      method: "multipleRequest",
      params: { requests: [{ method: "motorMoveToPreset", params: { goto_preset: { id: presetId } } }] }
    });
    return json.error_code !== 0;
  }
  async moveMotor(x, y) {
    const json = await this.apiRequest({
      method: "do",
      motor: { move: { x_coord: x, y_coord: y } }
    });
    return json.error_code !== 0;
  }
  // --- Detection event polling ---
  async getLastAlarmInfo() {
    var _a, _b, _c, _d, _e;
    const response = await this.apiRequest({
      method: "multipleRequest",
      params: {
        requests: [{ method: "getLastAlarmInfo", params: { msg_alarm: { name: ["chn1_msg_alarm_info"] } } }]
      }
    });
    this.log.debug("getLastAlarmInfo raw: " + JSON.stringify(response));
    const ops = (_a = response == null ? void 0 : response.result) == null ? void 0 : _a.responses;
    if (!(ops == null ? void 0 : ops.length)) return null;
    return (_e = (_d = (_c = (_b = ops[0]) == null ? void 0 : _b.result) == null ? void 0 : _c.msg_alarm) == null ? void 0 : _d.chn1_msg_alarm_info) != null ? _e : null;
  }
  async getDetectionEvents(startTime, endTime) {
    var _a, _b, _c, _d, _e, _f;
    const now = Math.floor(Date.now() / 1e3);
    const response = await this.apiRequest({
      method: "multipleRequest",
      params: {
        requests: [
          {
            method: "searchDetectionList",
            params: {
              playback: {
                search_detection_list: {
                  start_index: 0,
                  channel: 0,
                  start_time: startTime || now - 600,
                  end_time: endTime || now + 60,
                  end_index: 9
                }
              }
            }
          }
        ]
      }
    });
    const ops = (_a = response == null ? void 0 : response.result) == null ? void 0 : _a.responses;
    if (!(ops == null ? void 0 : ops.length)) return [];
    this.log.debug("searchDetectionList raw: " + JSON.stringify((_b = ops[0]) == null ? void 0 : _b.result));
    const events = (_f = (_e = (_d = (_c = ops[0]) == null ? void 0 : _c.result) == null ? void 0 : _d.playback) == null ? void 0 : _e.search_detection_list) != null ? _f : [];
    return events;
  }
  async getAlertEventType() {
    var _a, _b, _c, _d, _e;
    const response = await this.apiRequest({
      method: "multipleRequest",
      params: {
        requests: [{ method: "getAlertEventType", params: { msg_alarm: { table: "msg_alarm_type" } } }]
      }
    });
    const ops = (_a = response == null ? void 0 : response.result) == null ? void 0 : _a.responses;
    if (!(ops == null ? void 0 : ops.length)) return [];
    return (_e = (_d = (_c = (_b = ops[0]) == null ? void 0 : _b.result) == null ? void 0 : _c.msg_alarm) == null ? void 0 : _d.msg_alarm_type) != null ? _e : [];
  }
  // --- Action methods ---
  async calibrateMotor() {
    return this.apiRequest({ method: "do", motor: { manual_cali: "" } });
  }
  async startManualAlarm() {
    return this.apiRequest({ method: "do", msg_alarm: { manual_msg_alarm: { action: "start" } } });
  }
  async stopManualAlarm() {
    return this.apiRequest({ method: "do", msg_alarm: { manual_msg_alarm: { action: "stop" } } });
  }
  async reboot() {
    return this.apiRequest({
      method: "multipleRequest",
      params: { requests: [{ method: "rebootDevice", params: { system: { reboot: "null" } } }] }
    });
  }
  async formatSdCard() {
    return this.apiRequest({
      method: "multipleRequest",
      params: { requests: [{ method: "formatSdCard", params: { harddisk_manage: { format_hd: "1" } } }] }
    });
  }
  async savePreset(name) {
    return this.apiRequest({
      method: "multipleRequest",
      params: { requests: [{ method: "addMotorPostion", params: { preset: { set_preset: { name, save_ptz: "1" } } } }] }
    });
  }
  async deletePreset(id) {
    return this.apiRequest({
      method: "multipleRequest",
      params: { requests: [{ method: "deletePreset", params: { preset: { remove_preset: { id: [id] } } } }] }
    });
  }
  async setCruise(mode) {
    if (mode === "off") {
      return this.apiRequest({ method: "do", motor: { cruise_stop: {} } });
    }
    return this.apiRequest({ method: "do", motor: { cruise: { coord: mode } } });
  }
  async setDayNightMode(mode) {
    return this.apiRequest({
      method: "multipleRequest",
      params: {
        requests: [{ method: "setNightVisionModeConfig", params: { image: { switch: { night_vision_mode: mode } } } }]
      }
    });
  }
  async setLightFrequencyMode(mode) {
    return this.apiRequest({
      method: "multipleRequest",
      params: {
        requests: [{ method: "setLightFrequencyInfo", params: { image: { common: { light_freq_mode: mode } } } }]
      }
    });
  }
  async setAlarmMode(mode) {
    const enabled = mode !== "off";
    const soundEnabled = mode === "both" || mode === "sound";
    const lightEnabled = mode === "both" || mode === "light";
    const alarmMode = [];
    if (soundEnabled) alarmMode.push("sound");
    if (lightEnabled) alarmMode.push("light");
    return this.apiRequest({
      method: "multipleRequest",
      params: {
        requests: [
          {
            method: "setAlertConfig",
            params: {
              msg_alarm: {
                chn1_msg_alarm_info: {
                  enabled: enabled ? "on" : "off",
                  alarm_mode: alarmMode
                }
              }
            }
          }
        ]
      }
    });
  }
  async setSpeakerVolume(volume) {
    return this.apiRequest({
      method: "multipleRequest",
      params: { requests: [{ method: "setSpeakerVolume", params: { audio_config: { speaker: { volume } } } }] }
    });
  }
  async setMicrophoneVolume(volume) {
    return this.apiRequest({
      method: "multipleRequest",
      params: { requests: [{ method: "setMicrophoneVolume", params: { audio_config: { microphone: { volume } } } }] }
    });
  }
  async setMotionDetectionSensitivity(sensitivity) {
    return this.apiRequest({
      method: "multipleRequest",
      params: {
        requests: [
          { method: "setDetectionConfig", params: { motion_detection: { motion_det: { sensitivity } } } }
        ]
      }
    });
  }
  async setPersonDetectionSensitivity(sensitivity) {
    return this.apiRequest({
      method: "multipleRequest",
      params: {
        requests: [
          { method: "setPersonDetectionConfig", params: { people_detection: { detection: { sensitivity } } } }
        ]
      }
    });
  }
  async setCoverConfig(value) {
    return this.apiRequest({
      method: "multipleRequest",
      params: {
        requests: [{ method: "setCoverConfig", params: { cover: { cover: { enabled: value ? "on" : "off" } } } }]
      }
    });
  }
  async setHDR(value) {
    return this.apiRequest({
      method: "multipleRequest",
      params: {
        requests: [{ method: "setHDR", params: { video: { set_hdr: { hdr: value ? 1 : 0, secname: "main" } } } }]
      }
    });
  }
  async setRecordPlan(value) {
    return this.apiRequest({
      method: "multipleRequest",
      params: {
        requests: [{ method: "setRecordPlan", params: { record_plan: { chn1_channel: { enabled: value ? "on" : "off" } } } }]
      }
    });
  }
  async setOsd(label) {
    return this.apiRequest({
      method: "multipleRequest",
      params: {
        requests: [
          {
            method: "set",
            params: {
              OSD: {
                label_info_1: { enabled: label ? "on" : "off", text: label || "" }
              }
            }
          }
        ]
      }
    });
  }
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  TAPOCamera
});
//# sourceMappingURL=tapoCamera.js.map
