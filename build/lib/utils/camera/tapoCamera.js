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
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var tapoCamera_exports = {};
__export(tapoCamera_exports, {
  TAPOCamera: () => TAPOCamera
});
module.exports = __toCommonJS(tapoCamera_exports);
var import_node_fetch = __toESM(require("node-fetch"));
var import_https = __toESM(require("https"));
var import_crypto = __toESM(require("crypto"));
var import_onvifCamera = require("./onvifCamera");
const MAX_LOGIN_RETRIES = 3;
const AES_BLOCK_SIZE = 16;
class TAPOCamera extends import_onvifCamera.OnvifCamera {
  constructor(log, config) {
    super(log, config);
    this.log = log;
    this.config = config;
    this.kStreamPort = 554;
    this.passwordEncryptionMethod = null;
    this.isSecureConnectionValue = null;
    this.loginRetryCount = 0;
    this.pendingAPIRequests = /* @__PURE__ */ new Map();
    this.log.debug("Constructing Camera on host: " + config.ipAddress);
    this.httpsAgent = new import_https.default.Agent({
      rejectUnauthorized: false
    });
    this.cnonce = this.generateCnonce();
    this.hashedMD5Password = import_crypto.default.createHash("md5").update(config.password).digest("hex").toUpperCase();
    this.hashedSha256Password = import_crypto.default.createHash("sha256").update(config.password).digest("hex").toUpperCase();
  }
  getUsername() {
    return this.config.username || "admin";
  }
  getHeaders() {
    const headers = {
      Host: `https://${this.config.ipAddress}`,
      Referer: `https://${this.config.ipAddress}`,
      Accept: "application/json",
      "Accept-Encoding": "gzip, deflate",
      "User-Agent": "Tapo CameraClient Android",
      Connection: "close",
      requestByApp: "true",
      "Content-Type": "application/json; charset=UTF-8"
    };
    return headers;
  }
  getHashedPassword() {
    if (this.passwordEncryptionMethod === "md5") {
      return this.hashedMD5Password;
    } else if (this.passwordEncryptionMethod === "sha256") {
      return this.hashedSha256Password;
    } else {
      throw new Error("Unknown password encryption method");
    }
  }
  fetch(url, data) {
    return (0, import_node_fetch.default)(url, {
      agent: this.httpsAgent,
      headers: this.getHeaders(),
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
    const hashedNoncesWithSHA256 = import_crypto.default.createHash("sha256").update(this.cnonce + this.hashedSha256Password + nonce).digest("hex").toUpperCase();
    const hashedNoncesWithMD5 = import_crypto.default.createHash("md5").update(this.cnonce + this.hashedMD5Password + nonce).digest("hex").toUpperCase();
    if (deviceConfirm === hashedNoncesWithSHA256 + nonce + this.cnonce) {
      this.passwordEncryptionMethod = "sha256";
      return true;
    }
    if (deviceConfirm === hashedNoncesWithMD5 + nonce + this.cnonce) {
      this.passwordEncryptionMethod = "md5";
      return true;
    }
    return false;
  }
  async refreshStok(loginRetryCount = 0) {
    var _a, _b, _c, _d, _e, _f, _g, _h, _i, _j, _k, _l, _m;
    const isSecureConnection = await this.isSecureConnection();
    let response = null;
    let responseData = null;
    let fetchParams = {};
    if (isSecureConnection) {
      this.log.debug("StokRefresh: Using secure connection");
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
      this.log.debug("StokRefresh: Using unsecure connection");
      fetchParams = {
        method: "post",
        body: JSON.stringify({
          method: "login",
          params: {
            username: this.getUsername(),
            password: this.getHashedPassword(),
            hashed: true
          }
        })
      };
    }
    response = await this.fetch(`https://${this.config.ipAddress}`, fetchParams);
    responseData = await response.json();
    this.log.debug("StokRefresh: Login response :>> ", response.status, JSON.stringify(responseData));
    if (response.status === 401) {
      if (((_b = (_a = responseData == null ? void 0 : responseData.result) == null ? void 0 : _a.data) == null ? void 0 : _b.code) === 40411) {
        throw new Error("Invalid credentials");
      }
    }
    if (isSecureConnection) {
      this.log.debug("StokRefresh: Using secure connection");
      const nonce = (_d = (_c = responseData == null ? void 0 : responseData.result) == null ? void 0 : _c.data) == null ? void 0 : _d.nonce;
      const deviceConfirm = (_f = (_e = responseData == null ? void 0 : responseData.result) == null ? void 0 : _e.data) == null ? void 0 : _f.device_confirm;
      if (nonce && deviceConfirm && this.validateDeviceConfirm(nonce, deviceConfirm)) {
        const digestPasswd = import_crypto.default.createHash("sha256").update(this.getHashedPassword() + this.cnonce + nonce).digest("hex").toUpperCase();
        const digestPasswdFull = Buffer.concat([
          Buffer.from(digestPasswd, "utf8"),
          Buffer.from(this.cnonce, "utf8"),
          Buffer.from(nonce, "utf8")
        ]).toString("utf8");
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
        this.log.debug("StokRefresh: Start_seq response :>>", response.status, JSON.stringify(responseData));
        if ((_g = responseData == null ? void 0 : responseData.result) == null ? void 0 : _g.start_seq) {
          if (((_h = responseData == null ? void 0 : responseData.result) == null ? void 0 : _h.user_group) !== "root") {
            throw new Error("Incorrect user_group detected");
          }
          this.lsk = this.generateEncryptionToken("lsk", nonce);
          this.ivb = this.generateEncryptionToken("ivb", nonce);
          this.seq = responseData.result.start_seq;
        }
      }
    } else {
      this.passwordEncryptionMethod = "md5";
    }
    if (((_j = (_i = responseData == null ? void 0 : responseData.result) == null ? void 0 : _i.data) == null ? void 0 : _j.sec_left) > 0) {
      throw new Error(`StokRefresh: Temporary Suspension: Try again in ${responseData.result.data.sec_left} seconds`);
    }
    if (((_k = responseData == null ? void 0 : responseData.data) == null ? void 0 : _k.code) == -40404 && ((_l = responseData == null ? void 0 : responseData.data) == null ? void 0 : _l.sec_left) > 0) {
      throw new Error(`StokRefresh: Temporary Suspension: Try again in ${responseData.data.sec_left} seconds`);
    }
    if ((_m = responseData == null ? void 0 : responseData.result) == null ? void 0 : _m.stok) {
      this.stok = responseData.result.stok;
      this.log.debug("StokRefresh: Success :>>", this.stok);
      return this.stok;
    }
    if ((responseData == null ? void 0 : responseData.error_code) === -40413 && loginRetryCount < MAX_LOGIN_RETRIES) {
      this.log.debug(
        `Unexpected response, retrying: ${loginRetryCount}/${MAX_LOGIN_RETRIES}.`,
        response.status,
        JSON.stringify(responseData)
      );
      return this.refreshStok(loginRetryCount + 1);
    }
    throw new Error("Invalid authentication data");
  }
  async isSecureConnection() {
    var _a, _b, _c;
    if (this.isSecureConnectionValue === null) {
      const response = await this.fetch(`https://${this.config.ipAddress}`, {
        method: "post",
        body: JSON.stringify({
          method: "login",
          params: {
            encrypt_type: "3",
            username: this.getUsername()
          }
        })
      });
      this.log.debug(JSON.stringify(response));
      const json = await response.json();
      this.log.debug("isSecureConnection response :>> ", response.status, json);
      this.isSecureConnectionValue = json.error_code == -40413 && ((_c = (_b = (_a = json == null ? void 0 : json.result) == null ? void 0 : _a.data) == null ? void 0 : _b.encrypt_type) == null ? void 0 : _c.includes("3"));
    }
    return this.isSecureConnectionValue;
  }
  getStok(loginRetryCount = 0) {
    if (this.stok) {
      return new Promise((resolve) => resolve(this.stok));
    }
    if (!this.stokPromise) {
      this.stokPromise = () => this.refreshStok(loginRetryCount);
    }
    return this.stokPromise().then(() => {
      return this.stok;
    }).finally(() => {
      this.stokPromise = void 0;
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
      throw new Error("Invalid padding");
    }
    for (let i = text.length - paddingLength; i < text.length; i++) {
      if (text.charCodeAt(i) !== paddingLength) {
        throw new Error("Invalid padding");
      }
    }
    return text.slice(0, text.length - paddingLength).toString();
  }
  getTapoTag(request) {
    const tag = import_crypto.default.createHash("sha256").update(this.getHashedPassword() + this.cnonce).digest("hex").toUpperCase();
    return import_crypto.default.createHash("sha256").update(tag + JSON.stringify(request) + this.seq.toString()).digest("hex").toUpperCase();
  }
  async apiRequest(req, loginRetryCount = 0) {
    const reqJson = JSON.stringify(req);
    if (this.pendingAPIRequests.has(reqJson)) {
      return this.pendingAPIRequests.get(reqJson);
    }
    this.log.debug("API new request", reqJson);
    this.pendingAPIRequests.set(
      reqJson,
      (async () => {
        try {
          const isSecureConnection = await this.isSecureConnection();
          const url = await this.getAuthenticatedAPIURL(loginRetryCount);
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
          const response = await this.fetch(url, fetchParams);
          let json = await response.json();
          if (isSecureConnection) {
            const encryptedResponse = json;
            if (encryptedResponse.result.response) {
              const decryptedResponse = this.decryptResponse(encryptedResponse.result.response);
              json = JSON.parse(decryptedResponse);
            }
          } else {
            json = json;
          }
          this.log.debug(`API response`, response.status, JSON.stringify(json));
          if (isSecureConnection && response.status === 500) {
            this.stok = void 0;
          }
          if (json.error_code === -40401 || json.error_code === -1) {
            this.log.debug("API request failed, reauthenticating");
            this.stok = void 0;
            return this.apiRequest(req, loginRetryCount + 1);
          }
          return json;
        } finally {
          this.pendingAPIRequests.delete(reqJson);
        }
      })()
    );
    return this.pendingAPIRequests.get(reqJson);
  }
  async setLensMaskConfig(value) {
    this.log.debug("Processing setLensMaskConfig", value);
    const json = await this.apiRequest({
      method: "multipleRequest",
      params: {
        requests: [
          {
            method: "setLensMaskConfig",
            params: {
              lens_mask: {
                lens_mask_info: {
                  enabled: value ? "on" : "off"
                }
              }
            }
          }
        ]
      }
    });
    if (json.error_code !== 0) {
      throw new Error("Failed to perform action");
    }
  }
  async setAlertConfig(value) {
    this.log.debug("Processing setAlertConfig", value);
    const json = await this.apiRequest({
      method: "multipleRequest",
      params: {
        requests: [
          {
            method: "setAlertConfig",
            params: {
              msg_alarm: {
                chn1_msg_alarm_info: {
                  enabled: value ? "on" : "off"
                }
              }
            }
          }
        ]
      }
    });
    return json.error_code !== 0;
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
    const json = await this.apiRequest({
      method: "multipleRequest",
      params: {
        requests: [{ method: "do", motor: { movestep: { direction: angle } } }]
      }
    });
    return json.error_code !== 0;
  }
  async moveMotor(x, y) {
    const json = await this.apiRequest({
      method: "multipleRequest",
      params: {
        requests: [{ method: "do", motor: { move: { x_coord: x, y_coord: y } } }]
      }
    });
    return json.error_code !== 0;
  }
  async getBasicInfo() {
    const json = await this.apiRequest({
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
    const info = json.result.responses[0];
    return info.result.device_info.basic_info;
  }
  async getStatus() {
    const json = await this.apiRequest({
      method: "multipleRequest",
      params: {
        requests: [
          {
            method: "getAlertConfig",
            params: {
              msg_alarm: {
                name: "chn1_msg_alarm_info"
              }
            }
          },
          {
            method: "getLensMaskConfig",
            params: {
              lens_mask: {
                name: "lens_mask_info"
              }
            }
          },
          {
            method: "getForceWhitelampState",
            params: {
              image: {
                name: "switch"
              }
            }
          }
        ]
      }
    });
    this.log.debug(`getStatus json: ${JSON.stringify(json)}`);
    if (json.error_code !== 0) {
      throw new Error("Camera replied with error");
    }
    if (!json.result.responses) {
      throw new Error("Camera replied with invalid response");
    }
    const alertConfig = json.result.responses.find((r) => r.method === "getAlertConfig");
    const forceWhitelampState = json.result.responses.find((r) => r.method === "getForceWhitelampState");
    const lensMaskConfig = json.result.responses.find((r) => r.method === "getLensMaskConfig");
    return {
      alert: alertConfig.result.msg_alarm.chn1_msg_alarm_info.enabled === "on",
      lensMask: lensMaskConfig.result.lens_mask.lens_mask_info.enabled === "on",
      forceWhiteLamp: forceWhitelampState.result.image ? forceWhitelampState.result.image.switch.force_wtl_state === "on" : false
    };
  }
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  TAPOCamera
});
//# sourceMappingURL=tapoCamera.js.map
