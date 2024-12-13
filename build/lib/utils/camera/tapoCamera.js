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
var import_crypto = __toESM(require("crypto"));
var import_onvifCamera = require("./onvifCamera");
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
const _TAPOCamera = class extends import_onvifCamera.OnvifCamera {
  constructor(log, config) {
    super(log, config);
    this.log = log;
    this.config = config;
    this.kStreamPort = 554;
    this.passwordEncryptionMethod = null;
    this.isSecureConnectionValue = null;
    this.pendingAPIRequests = /* @__PURE__ */ new Map();
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0;
    this.fetchAgent = new import_undici.Agent({
      connectTimeout: 5e3,
      connect: {
        rejectUnauthorized: false,
        ciphers: "AES256-SHA:AES128-GCM-SHA256"
      }
    });
    (0, import_undici.setGlobalDispatcher)(this.fetchAgent);
    this.cnonce = this.generateCnonce();
    this.hashedPassword = import_crypto.default.createHash("md5").update(config.password).digest("hex").toUpperCase();
    this.hashedSha256Password = import_crypto.default.createHash("sha256").update(config.password).digest("hex").toUpperCase();
  }
  getUsername() {
    return this.config.username || "admin";
  }
  getHeaders() {
    return {
      Host: `https://${this.config.ipAddress}`,
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
    const hashedNoncesWithSHA256 = import_crypto.default.createHash("sha256").update(this.cnonce + this.hashedSha256Password + nonce).digest("hex").toUpperCase();
    if (deviceConfirm === hashedNoncesWithSHA256 + nonce + this.cnonce) {
      this.passwordEncryptionMethod = "sha256";
      return true;
    }
    const hashedNoncesWithMD5 = import_crypto.default.createHash("md5").update(this.cnonce + this.hashedPassword + nonce).digest("hex").toUpperCase();
    if (deviceConfirm === hashedNoncesWithMD5 + nonce + this.cnonce) {
      this.passwordEncryptionMethod = "md5";
      return true;
    }
    this.log.debug('Invalid device confirm, expected "sha256" or "md5" to match, but none found', {
      hashedNoncesWithMD5,
      hashedNoncesWithSHA256,
      deviceConfirm,
      nonce,
      cnonce: this
    });
    return this.passwordEncryptionMethod !== null;
  }
  async refreshStok(loginRetryCount = 0) {
    var _a, _b, _c, _d, _e, _f, _g, _h, _i, _j, _k, _l, _m;
    this.log.debug("refreshStok: Refreshing stok...");
    const isSecureConnection = await this.isSecureConnection();
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
    this.log.debug("refreshStok: Login response", responseLogin.status, responseLoginData);
    if (responseLogin.status === 401 && ((_b = (_a = responseLoginData.result) == null ? void 0 : _a.data) == null ? void 0 : _b.code) === -40411) {
      this.log.debug("refreshStok: invalid credentials, raising exception", responseLogin.status);
      this.log.error("Invalid credentials");
    }
    if (isSecureConnection) {
      const nonce = (_d = (_c = responseLoginData.result) == null ? void 0 : _c.data) == null ? void 0 : _d.nonce;
      const deviceConfirm = (_f = (_e = responseLoginData.result) == null ? void 0 : _e.data) == null ? void 0 : _f.device_confirm;
      if (nonce && deviceConfirm && this.validateDeviceConfirm(nonce, deviceConfirm)) {
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
        if ((_g = responseData.result) == null ? void 0 : _g.start_seq) {
          if (((_h = responseData.result) == null ? void 0 : _h.user_group) !== "root") {
            this.log.debug("refreshStock: Incorrect user_group detected");
            this.log.error("Incorrect user_group detected");
          }
          this.lsk = this.generateEncryptionToken("lsk", nonce);
          this.ivb = this.generateEncryptionToken("ivb", nonce);
          this.seq = responseData.result.start_seq;
        }
      } else {
        if (responseLoginData.error_code === -40413 && loginRetryCount < MAX_LOGIN_RETRIES) {
          this.log.debug(
            `refreshStock: Invalid device confirm, retrying: ${loginRetryCount}/${MAX_LOGIN_RETRIES}.`,
            responseLogin.status,
            responseLoginData
          );
          return this.refreshStok(loginRetryCount + 1);
        }
        this.log.debug(
          "refreshStock: Invalid device confirm and loginRetryCount exhausted, raising exception",
          loginRetryCount,
          responseLoginData
        );
        this.log.error("Invalid device confirm. Please activate 3rd Patry support in the TP App under TP Labor -> 3rd Party Control");
        return;
      }
    } else {
      this.passwordEncryptionMethod = "md5";
      response = responseLogin;
      responseData = responseLoginData;
    }
    if (((_j = (_i = responseData.result) == null ? void 0 : _i.data) == null ? void 0 : _j.sec_left) && responseData.result.data.sec_left > 0) {
      this.log.debug("refreshStok: temporary suspension", responseData);
      this.log.error(`Temporary Suspension: Try again in ${responseData.result.data.sec_left} seconds`);
    }
    if (responseData && responseData.result && responseData.result.responses && responseData.result.responses[0].error_code !== 0) {
      this.log.debug(
        `API request failed with specific error code ${responseData.result.responses[0].error_code}: ${responseData.result.responses[0].error_message}`
      );
    }
    if (((_k = responseData == null ? void 0 : responseData.data) == null ? void 0 : _k.code) === -40404 && ((_l = responseData == null ? void 0 : responseData.data) == null ? void 0 : _l.sec_left) && responseData.data.sec_left > 0) {
      this.log.debug("refreshStok: temporary suspension", responseData);
      this.log.error(`refreshStok: Temporary Suspension: Try again in ${responseData.data.sec_left} seconds`);
    }
    if ((_m = responseData == null ? void 0 : responseData.result) == null ? void 0 : _m.stok) {
      this.stok = responseData.result.stok;
      this.log.debug("refreshStok: Success in obtaining STOK", this.stok);
      return;
    }
    if ((responseData == null ? void 0 : responseData.error_code) === -40413 && loginRetryCount < MAX_LOGIN_RETRIES) {
      this.log.debug(
        `refreshStock: Unexpected response, retrying: ${loginRetryCount}/${MAX_LOGIN_RETRIES}.`,
        response.status,
        responseData
      );
      return this.refreshStok(loginRetryCount + 1);
    }
    this.log.debug("refreshStock: Unexpected end of flow, raising exception");
    this.log.error("Invalid authentication data");
  }
  async isSecureConnection() {
    var _a, _b, _c;
    if (this.isSecureConnectionValue === null) {
      this.log.debug("isSecureConnection: Checking secure connection...");
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
      const responseData = await response.json();
      this.log.debug("isSecureConnection response", response.status, JSON.stringify(responseData));
      this.isSecureConnectionValue = (responseData == null ? void 0 : responseData.error_code) == -40413 && ((_c = String(((_b = (_a = responseData.result) == null ? void 0 : _a.data) == null ? void 0 : _b.encrypt_type) || "")) == null ? void 0 : _c.includes("3"));
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
          this.log.error("STOK not found");
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
        var _a;
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
            if ((_a = encryptedResponse == null ? void 0 : encryptedResponse.result) == null ? void 0 : _a.response) {
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
  async setStatus(service, value) {
    const responseData = await this.apiRequest({
      method: "multipleRequest",
      params: {
        requests: [_TAPOCamera.SERVICE_MAP[service](value)]
      }
    });
    if (responseData.error_code !== 0) {
      this.log.error(`Failed to perform ${service} action`);
    }
    const method = _TAPOCamera.SERVICE_MAP[service](value).method;
    const operation = responseData.result.responses.find((e) => e.method === method);
    if ((operation == null ? void 0 : operation.error_code) !== 0) {
      this.log.error(`Failed to perform ${service} action`);
    }
    return operation.result;
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
    const responseData = await this.apiRequest({
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
            method: "getMsgPushConfig",
            params: {
              msg_push: {
                name: "chn1_msg_push_info"
              }
            }
          },
          {
            method: "getDetectionConfig",
            params: {
              motion_detection: {
                name: "motion_det"
              }
            }
          },
          {
            method: "getLedStatus",
            params: {
              led: {
                name: "config"
              }
            }
          }
        ]
      }
    });
    if (!responseData || !responseData.result || !responseData.result.responses) {
      this.log.error("No response data found");
      return {
        alarm: void 0,
        eyes: void 0,
        notifications: void 0,
        motionDetection: void 0,
        led: void 0
      };
    }
    const operations = responseData.result.responses;
    const alert = operations.find((r) => r.method === "getAlertConfig");
    const lensMask = operations.find((r) => r.method === "getLensMaskConfig");
    const notifications = operations.find((r) => r.method === "getMsgPushConfig");
    const motionDetection = operations.find((r) => r.method === "getDetectionConfig");
    const led = operations.find((r) => r.method === "getLedStatus");
    if (!alert)
      this.log.debug("No alert config found");
    if (!lensMask)
      this.log.debug("No lens mask config found");
    if (!notifications)
      this.log.debug("No notifications config found");
    if (!motionDetection)
      this.log.debug("No motion detection config found");
    if (!led)
      this.log.debug("No led config found");
    return {
      alarm: alert ? alert.result.msg_alarm.chn1_msg_alarm_info.enabled === "on" : void 0,
      eyes: lensMask ? lensMask.result.lens_mask.lens_mask_info.enabled === "off" : void 0,
      notifications: notifications ? notifications.result.msg_push.chn1_msg_push_info.notification_enabled === "on" : void 0,
      motionDetection: motionDetection ? motionDetection.result.motion_detection.motion_det.enabled === "on" : void 0,
      led: led ? led.result.led.config.enabled === "on" : void 0
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
  async moveMotor(x, y) {
    const json = await this.apiRequest({
      method: "do",
      motor: { move: { x_coord: x, y_coord: y } }
    });
    return json.error_code !== 0;
  }
};
let TAPOCamera = _TAPOCamera;
TAPOCamera.SERVICE_MAP = {
  eyes: (value) => ({
    method: "setLensMaskConfig",
    params: {
      lens_mask: {
        lens_mask_info: {
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
  })
};
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  TAPOCamera
});
//# sourceMappingURL=tapoCamera.js.map
