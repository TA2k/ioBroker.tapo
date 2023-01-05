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
var p100_exports = {};
__export(p100_exports, {
  default: () => P100
});
module.exports = __toCommonJS(p100_exports);
var import_uuid = require("uuid");
var import_tpLinkCipher = __toESM(require("./tpLinkCipher"));
class P100 {
  constructor(log, ipAddress, email, password, timeout) {
    this.log = log;
    this.ipAddress = ipAddress;
    this.email = email;
    this.password = password;
    this.timeout = timeout;
    this.crypto = require("crypto");
    this.axios = require("axios");
    this.ERROR_CODES = {
      "0": "Success",
      "-1010": "Invalid Public Key Length",
      "-1012": "Invalid terminalUUID",
      "-1501": "Invalid Request or Credentials",
      "1002": "Incorrect Request",
      "-1003": "JSON formatting error ",
      "9999": "Session Timeout",
      "-1301": "Device Error",
      "1100": "Handshake Failed",
      "1111": "Login Failed",
      "1112": "Http Transport Failed",
      "1200": "Multiple Requests Failed",
      "-1004": "JSON Encode Failed",
      "-1005": "AES Decode Failed",
      "-1006": "Request Length Error",
      "-2101": "Account Error",
      "-1": "ERR_COMMON_FAILED",
      "1000": "ERR_NULL_TRANSPORT",
      "1001": "ERR_CMD_COMMAND_CANCEL",
      "-1001": "ERR_UNSPECIFIC",
      "-1002": "ERR_UNKNOWN_METHOD",
      "-1007": "ERR_CLOUD_FAILED",
      "-1008": "ERR_PARAMS",
      "-1101": "ERR_SESSION_PARAM",
      "-1201": "ERR_QUICK_SETUP",
      "-1302": "ERR_DEVICE_NEXT_EVENT",
      "-1401": "ERR_FIRMWARE",
      "-1402": "ERR_FIRMWARE_VER_ERROR",
      "-1601": "ERR_TIME",
      "-1602": "ERR_TIME_SYS",
      "-1603": "ERR_TIME_SAVE",
      "-1701": "ERR_WIRELESS",
      "-1702": "ERR_WIRELESS_UNSUPPORTED",
      "-1801": "ERR_SCHEDULE",
      "-1802": "ERR_SCHEDULE_FULL",
      "-1803": "ERR_SCHEDULE_CONFLICT",
      "-1804": "ERR_SCHEDULE_SAVE",
      "-1805": "ERR_SCHEDULE_INDEX",
      "-1901": "ERR_COUNTDOWN",
      "-1902": "ERR_COUNTDOWN_CONFLICT",
      "-1903": "ERR_COUNTDOWN_SAVE",
      "-2001": "ERR_ANTITHEFT",
      "-2002": "ERR_ANTITHEFT_CONFLICT",
      "-2003": "ERR_ANTITHEFT_SAVE",
      "-2201": "ERR_STAT",
      "-2202": "ERR_STAT_SAVE",
      "-2301": "ERR_DST",
      "-2302": "ERR_DST_SAVE"
    };
    this.log.debug("Constructing P100 on host: " + ipAddress);
    this.ip = ipAddress;
    this.encryptCredentials(email, password);
    this.createKeyPair();
    this.terminalUUID = (0, import_uuid.v4)();
    this._reconnect_counter = 0;
    this._timeout = timeout;
  }
  encryptCredentials(email, password) {
    this.encodedPassword = import_tpLinkCipher.default.mime_encoder(password);
    this.encodedEmail = this.sha_digest_username(email);
    this.encodedEmail = import_tpLinkCipher.default.mime_encoder(this.encodedEmail);
  }
  sha_digest_username(data) {
    const digest = this.crypto.createHash("sha1").update(data).digest("hex");
    return digest;
  }
  createKeyPair() {
    const { publicKey, privateKey } = this.crypto.generateKeyPairSync("rsa", {
      publicKeyEncoding: {
        type: "spki",
        format: "pem"
      },
      privateKeyEncoding: {
        type: "pkcs1",
        format: "pem"
      },
      modulusLength: 1024
    });
    this.privateKey = privateKey;
    this.publicKey = publicKey.toString("utf8");
  }
  async handshake() {
    const URL = "http://" + this.ip + "/app";
    const payload = {
      method: "handshake",
      params: {
        key: this.publicKey,
        requestTimeMils: Math.round(Date.now() * 1e3)
      }
    };
    this.log.debug("Handshake P100 on host: " + this.ip);
    const headers = {
      Connection: "Keep-Alive"
    };
    const config = {
      timeout: 5e3,
      headers
    };
    await this.axios.post(URL, payload, config).then((res) => {
      this.log.debug("Received Handshake P100 on host response: " + this.ip);
      if (res.data.error_code) {
        return this.handleError(res.data.error_code, "97");
      }
      try {
        const encryptedKey = res.data.result.key.toString("utf8");
        this.decode_handshake_key(encryptedKey);
        this.cookie = res.headers["set-cookie"][0].split(";")[0];
        return;
      } catch (error) {
        return this.handleError(res.data.error_code, "106");
      }
    }).catch((error) => {
      this.log.error("111 Error: " + error.message);
      return error;
    });
  }
  async login() {
    const URL = "http://" + this.ip + "/app";
    const payload = '{"method": "login_device","params": {"username": "' + this.encodedEmail + '","password": "' + this.encodedPassword + '"},"requestTimeMils": ' + Math.round(Date.now() * 1e3) + "};";
    const headers = {
      Cookie: this.cookie,
      Connection: "Keep-Alive"
    };
    if (this.tpLinkCipher) {
      const encryptedPayload = this.tpLinkCipher.encrypt(payload);
      const securePassthroughPayload = {
        method: "securePassthrough",
        params: {
          request: encryptedPayload
        }
      };
      const config = {
        headers,
        timeout: this._timeout * 1e3
      };
      await this.axios.post(URL, securePassthroughPayload, config).then((res) => {
        if (res.data.error_code) {
          return this.handleError(res.data.error_code, "146");
        }
        const decryptedResponse = this.tpLinkCipher.decrypt(res.data.result.response);
        try {
          const response = JSON.parse(decryptedResponse);
          if (response.error_code !== 0) {
            return this.handleError(res.data.error_code, "152");
          }
          this.token = response.result.token;
          return;
        } catch (error) {
          return this.handleError(JSON.parse(decryptedResponse).error_code, "157");
        }
      }).catch((error) => {
        this.log.error("Error: " + error.message);
        return error;
      });
    }
  }
  decode_handshake_key(key) {
    const buff = Buffer.from(key, "base64");
    const decoded = this.crypto.privateDecrypt(
      {
        key: this.privateKey,
        padding: this.crypto.constants.RSA_PKCS1_PADDING
      },
      buff
    );
    const b_arr = decoded.slice(0, 16);
    const b_arr2 = decoded.slice(16, 32);
    this.tpLinkCipher = new import_tpLinkCipher.default(this.log, b_arr, b_arr2);
  }
  async turnOff() {
    const payload = '{"method": "set_device_info","params": {"device_on": false},"terminalUUID": "' + this.terminalUUID + '","requestTimeMils": ' + Math.round(Date.now() * 1e3) + "};";
    return this.sendRequest(payload);
  }
  async turnOn() {
    const payload = '{"method": "set_device_info","params": {"device_on": true},"terminalUUID": "' + this.terminalUUID + '","requestTimeMils": ' + Math.round(Date.now() * 1e3) + "};";
    return this.sendRequest(payload);
  }
  async setPowerState(state) {
    if (state) {
      return this.turnOn();
    } else {
      return this.turnOff();
    }
  }
  async getDeviceInfo() {
    if (this.getSysInfo() && Date.now() - this.getSysInfo().last_update < 2e3) {
      return new Promise((resolve) => {
        resolve(this.getSysInfo());
      });
    }
    const URL = "http://" + this.ip + "/app?token=" + this.token;
    const payload = '{"method": "get_device_info","requestTimeMils": ' + Math.round(Date.now() * 1e3) + "};";
    const headers = {
      Cookie: this.cookie
    };
    if (this.tpLinkCipher) {
      const encryptedPayload = this.tpLinkCipher.encrypt(payload);
      const securePassthroughPayload = {
        method: "securePassthrough",
        params: {
          request: encryptedPayload
        }
      };
      const config = {
        headers,
        timeout: this._timeout * 1e3
      };
      return this.axios.post(URL, securePassthroughPayload, config).then((res) => {
        this.log.debug(JSON.stringify(res.data));
        if (res.data.error_code) {
          if ((res.data.error_code === "9999" || res.data.error_code === 9999) && this._reconnect_counter <= 3) {
            this.log.debug(" Error Code: " + res.data.error_code + ", " + this.ERROR_CODES[res.data.error_code]);
            this.log.debug("Trying to reconnect...");
            return this.reconnect().then(() => {
              return this.getDeviceInfo();
            });
          }
          this._reconnect_counter = 0;
          return this.handleError(res.data.error_code, "326");
        }
        const decryptedResponse = this.tpLinkCipher.decrypt(res.data.result.response);
        try {
          const response = JSON.parse(decryptedResponse);
          if (response.error_code !== 0) {
            return this.handleError(response.error_code, "333");
          }
          this.setSysInfo(response.result);
          this.log.debug("Device Info: ", response.result);
          return this.getSysInfo();
        } catch (error) {
          this.log.debug(error.stack);
          return this.handleError(JSON.parse(decryptedResponse).error_code, "340");
        }
      }).catch((error) => {
        this.log.debug("371 Error: " + error.message);
        return error;
      });
    } else {
      return new Promise((resolve, reject) => {
        reject();
      });
    }
  }
  get id() {
    if (this.getSysInfo()) {
      return this.getSysInfo().device_id;
    }
    return "";
  }
  get name() {
    if (this.getSysInfo()) {
      return Buffer.from(this.getSysInfo().nickname, "base64").toString("utf8");
    }
    return "";
  }
  get model() {
    if (this.getSysInfo()) {
      return this.getSysInfo().model;
    }
    return "";
  }
  get serialNumber() {
    if (this.getSysInfo()) {
      this.getSysInfo().hw_id;
    }
    return "";
  }
  get firmwareRevision() {
    if (this.getSysInfo()) {
      return this.getSysInfo().fw_ver;
    }
    return "";
  }
  get hardwareRevision() {
    if (this.getSysInfo()) {
      return this.getSysInfo().hw_ver;
    }
    return "";
  }
  setSysInfo(sysInfo) {
    this._plugSysInfo = sysInfo;
    this._plugSysInfo.last_update = Date.now();
  }
  getSysInfo() {
    return this._plugSysInfo;
  }
  handleError(errorCode, line) {
    const errorMessage = this.ERROR_CODES[errorCode];
    this.log.debug(line + " Error Code: " + errorCode + ", " + errorMessage + " " + this.ip);
    return false;
  }
  async sendRequest(payload) {
    return this.handleRequest(payload).then((result) => {
      return result ? true : false;
    }).catch((error) => {
      this.log.debug(JSON.stringify(error));
      if (error && error.message.indexOf("9999") > 0 && this._reconnect_counter <= 3) {
        return this.reconnect().then(() => {
          return this.handleRequest(payload).then((result) => {
            return result ? true : false;
          });
        });
      }
      this._reconnect_counter = 0;
      return false;
    });
  }
  handleRequest(payload) {
    const URL = "http://" + this.ip + "/app?token=" + this.token;
    const headers = {
      Cookie: this.cookie,
      Connection: "Keep-Alive"
    };
    if (this.tpLinkCipher) {
      const encryptedPayload = this.tpLinkCipher.encrypt(payload);
      const securePassthroughPayload = {
        method: "securePassthrough",
        params: {
          request: encryptedPayload
        }
      };
      const config = {
        headers,
        timeout: this._timeout * 1e3
      };
      return this.axios.post(URL, securePassthroughPayload, config).then((res) => {
        if (res.data.error_code) {
          if (res.data.error_code === "9999" || res.data.error_code === 9999 && this._reconnect_counter <= 3) {
            this.log.error(" Error Code: " + res.data.error_code + ", " + this.ERROR_CODES[res.data.error_code]);
            this.log.debug("Trying to reconnect...");
            return this.reconnect().then(() => {
              return this.getDeviceInfo();
            });
          }
          this._reconnect_counter = 0;
          return this.handleError(res.data.error_code, "357");
        }
        const decryptedResponse = this.tpLinkCipher.decrypt(res.data.result.response);
        try {
          const response = JSON.parse(decryptedResponse);
          this.log.debug(response);
          if (response.error_code !== 0) {
            return this.handleError(response.error_code, "364");
          }
          return response;
        } catch (error) {
          return this.handleError(JSON.parse(decryptedResponse).error_code, "368");
        }
      }).catch((error) => {
      });
    }
    return new Promise((resolve, reject) => {
      reject();
    });
  }
  async reconnect() {
    this._reconnect_counter++;
    return this.handshake().then(() => {
      this.login().then(() => {
        return;
      });
    });
  }
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {});
//# sourceMappingURL=p100.js.map
