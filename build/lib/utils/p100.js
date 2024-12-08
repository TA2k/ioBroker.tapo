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
var import_tpLinkCipher = __toESM(require("./tpLinkCipher.js"));
var import_uuid = require("uuid");
var import_newTpLinkCipher = __toESM(require("./newTpLinkCipher.js"));
var import_axios2 = __toESM(require("axios"));
var import_crypto = __toESM(require("crypto"));
var import_utf8 = __toESM(require("utf8"));
var import_http = __toESM(require("http"));
class P100 {
  constructor(log, ipAddress, email, password, timeout) {
    this.log = log;
    this.ipAddress = ipAddress;
    this.email = email;
    this.password = password;
    this.timeout = timeout;
    this._crypto = import_crypto.default;
    this._axios = import_axios2.default;
    this._utf8 = import_utf8.default;
    this.is_klap = true;
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
      "-2302": "ERR_DST_SAVE",
      "1003": "KLAP"
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
    const digest = this._crypto.createHash("sha1").update(data).digest("hex");
    return digest;
  }
  calc_auth_hash(username, password) {
    const usernameDigest = this._crypto.createHash("sha1").update(Buffer.from(username.normalize("NFKC"))).digest();
    const passwordDigest = this._crypto.createHash("sha1").update(Buffer.from(password.normalize("NFKC"))).digest();
    const digest = this._crypto.createHash("sha256").update(Buffer.concat([usernameDigest, passwordDigest])).digest();
    return digest;
  }
  createKeyPair() {
    const { publicKey, privateKey } = this._crypto.generateKeyPairSync("rsa", {
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
    this.log.debug("Old Handshake P100 on host: " + this.ip);
    const headers = {
      Connection: "Keep-Alive"
    };
    const config = {
      timeout: 5e3,
      headers
    };
    await this._axios.post(URL, payload, config).then((res) => {
      this.log.debug("Received Old Handshake P100 on host response: " + this.ip);
      if (res.data.error_code || res.status !== 200) {
        return this.handleError(res.data.error_code ? res.data.error_code : res.status, "172");
      }
      try {
        const encryptedKey = res.data.result.key.toString("utf8");
        this.decode_handshake_key(encryptedKey);
        if (res.headers["set-cookie"]) {
          this.cookie = res.headers["set-cookie"][0].split(";")[0];
        }
        return;
      } catch (error) {
        return this.handleError(res.data.error_code, "106");
      }
    }).catch((error) => {
      this.log.error("111 Error: " + error ? error.message : "");
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
    this.log.debug("Old Login to P100 with url " + URL);
    this.log.debug("Headers " + JSON.stringify(headers));
    this.log.debug("Cipher: " + this.tpLinkCipher);
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
      this.log.debug("Post request");
      await this._axios.post(URL, securePassthroughPayload, config).then((res) => {
        if (res.data.error_code || res.status !== 200) {
          return this.handleError(res.data.error_code ? res.data.error_code : res.status, "226");
        }
        const decryptedResponse = this.tpLinkCipher.decrypt(res.data.result.response);
        this.log.debug("Decrypted Response: " + decryptedResponse);
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
        this.log.error("Error Login: " + error ? error.message : "");
        return error;
      });
    }
  }
  async raw_request(path, data, responseType, params) {
    const URL = "http://" + this.ip + "/app/" + path;
    const headers = {
      Connection: "Keep-Alive",
      Host: this.ip,
      Accept: "*/*",
      "Content-Type": "application/octet-stream"
    };
    if (this.cookie) {
      headers.Cookie = this.cookie;
    }
    const config = {
      timeout: 5e3,
      responseType,
      headers,
      params
    };
    this.log.debug("Raw request to P100 with url " + URL);
    this.log.debug("Data: " + data.toString("hex"));
    this.log.debug("Headers: " + JSON.stringify(headers));
    this.log.debug("Params: " + JSON.stringify(params));
    this.log.debug("Cipher: " + this.tpLinkCipher);
    return this._axios.post(URL, data, config).then((res) => {
      this.log.debug("Received request on host response: " + this.ip);
      if (res.data.error_code || res.status !== 200) {
        return this.handleError(res.data.error_code ? res.data.error_code : res.status, "273");
      }
      try {
        if (res.headers && res.headers["set-cookie"]) {
          this.log.debug("Handshake 1 cookie: " + JSON.stringify(res.headers["set-cookie"][0]));
          this.cookie = res.headers["set-cookie"][0].split(";")[0];
          this.tplink_timeout = Number(res.headers["set-cookie"][0].split(";")[1]);
        }
        return res.data;
      } catch (error) {
        return this.handleError(res.data.error_code, "318");
      }
    }).catch((error) => {
      this.log.error("276 Error: " + error.message);
      if (error.message.indexOf("403") > -1) {
        this.reAuthenticate();
      }
      return error;
    });
  }
  decode_handshake_key(key) {
    const buff = Buffer.from(key, "base64");
    const decoded = this._crypto.privateDecrypt(
      {
        key: this.privateKey,
        padding: this._crypto.constants.RSA_PKCS1_PADDING
      },
      buff
    );
    const b_arr = decoded.slice(0, 16);
    const b_arr2 = decoded.slice(16, 32);
    this.tpLinkCipher = new import_tpLinkCipher.default(this.log, b_arr, b_arr2);
  }
  async handshake_new() {
    this.log.debug("Trying new handshake");
    const local_seed = this._crypto.randomBytes(16);
    const ah = this.calc_auth_hash(this.email, this.password);
    const options = {
      method: "POST",
      hostname: this.ip,
      path: "/app/handshake1",
      headers: {
        Connection: "Keep-Alive",
        "Content-Type": "application/octet-stream",
        "Content-Length": local_seed.length
      },
      httpAgent: new import_http.default.Agent({
        keepAlive: true
      }),
      agent: new import_http.default.Agent({
        keepAlive: true
      }),
      maxRedirects: 20
    };
    const responsePromise = new Promise((resolve, reject) => {
      const request = import_http.default.request(options, (res) => {
        let chunks = [];
        if (res.headers && res.headers["set-cookie"]) {
          this.cookie = res.headers["set-cookie"][0].split(";")[0];
        }
        res.on("data", (chunk) => {
          chunks.push(chunk);
        });
        res.on("end", (chunk) => {
          var body = Buffer.concat(chunks);
          this.log.debug(body.toString());
          resolve(body);
        });
        res.on("error", (error) => {
          this.log.error(error);
          resolve(Buffer.from(""));
        });
      }).on("error", (error) => {
        this.log.error(error);
        resolve(Buffer.from(""));
      });
      request.write(local_seed);
      request.end();
    });
    let response = await responsePromise;
    if (!response || !response.subarray) {
      this.log.debug("New Handshake 1 failed");
      return;
    }
    this.log.debug("Handshake 1 response: " + response.toString("hex"));
    const remote_seed = response.subarray(0, 16);
    const server_hash = response.subarray(16);
    this.log.debug("remote seed: " + remote_seed.toString("hex"));
    this.log.debug("server hash: " + server_hash.toString("hex"));
    this.log.debug("Extracted hashes");
    let auth_hash = void 0;
    this.log.debug("Calculated auth hash: " + ah.toString("hex"));
    const local_seed_auth_hash = this._crypto.createHash("sha256").update(Buffer.concat([local_seed, remote_seed, ah])).digest();
    this.log.debug("Calculated local seed auth hash: " + local_seed_auth_hash.toString("hex"));
    this.log.debug("Server hash: " + server_hash.toString("hex"));
    if (local_seed_auth_hash.toString("hex") === server_hash.toString("hex")) {
      this.log.debug("New Handshake 1 successful");
      auth_hash = ah;
    } else {
      this.log.debug("New Handshake 1 failed");
      this.log.debug("Local seed auth hash doesnt match server hash");
      auth_hash = ah;
    }
    const req = this._crypto.createHash("sha256").update(Buffer.concat([remote_seed, local_seed, auth_hash])).digest();
    return this.raw_request("handshake2", req, "text").then((res) => {
      this.log.debug("New Handshake 2 successful: " + res);
      this.newTpLinkCipher = new import_newTpLinkCipher.default(local_seed, remote_seed, auth_hash, this.log);
      this.log.debug("New Init cipher successful");
      return;
    });
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
  async getDeviceInfo(force) {
    if (!force) {
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
      return this._axios.post(URL, securePassthroughPayload, config).then((res) => {
        if (res.data.error_code) {
          if ((res.data.error_code === "9999" || res.data.error_code === 9999) && this._reconnect_counter <= 3) {
            this.log.error(" Error Code: " + res.data.error_code + ", " + this.ERROR_CODES[res.data.error_code]);
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
        this.log.error("371 Error: " + error ? error.message : "");
        return error;
      });
    } else if (this.newTpLinkCipher) {
      const data = this.newTpLinkCipher.encrypt(payload);
      const URL2 = "http://" + this.ip + "/app/request";
      const headers2 = {
        Connection: "Keep-Alive",
        Host: this.ip,
        Accept: "*/*",
        "Content-Type": "application/octet-stream"
      };
      if (this.cookie) {
        headers2.Cookie = this.cookie;
      }
      const config = {
        timeout: 5e3,
        responseType: "arraybuffer",
        headers: headers2,
        params: { seq: data.seq.toString() }
      };
      return this._axios.post(URL2, data.encryptedPayload, config).then((res) => {
        if (res.data.error_code) {
          return this.handleError(res.data.error_code, "309");
        }
        try {
          if (res.headers && res.headers["set-cookie"]) {
            this.cookie = res.headers["set-cookie"][0].split(";")[0];
          }
          const response = JSON.parse(this.newTpLinkCipher.decrypt(res.data));
          if (response.error_code !== 0) {
            return this.handleError(response.error_code, "333");
          }
          this.setSysInfo(response.result);
          this.log.debug("Device Info: ", response.result);
          return this.getSysInfo();
        } catch (error) {
          this.log.debug(this.newTpLinkCipher.decrypt(res.data));
          this.log.debug("Status: " + res.status);
          return this.handleError(res.data.error_code, "480");
        }
      }).catch((error) => {
        this.log.debug("469 Error: " + JSON.stringify(error));
        this.log.info("469 Error: " + error.message);
        if (error.message.indexOf("403") > -1) {
          this.reAuthenticate();
        }
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
      return this.getSysInfo().hw_id;
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
    if (typeof errorCode === "number" && errorCode === 1003) {
      this.log.info("Trying KLAP Auth");
      this.is_klap = true;
    } else {
      this.log.error(line + " Error Code: " + errorCode + ", " + errorMessage + " " + this.ip);
    }
    return false;
  }
  async sendRequest(payload) {
    if (this.tpLinkCipher) {
      return this.handleRequest(payload).then((result) => {
        return result ? true : false;
      }).catch((error) => {
        if (error.message && error.message.indexOf("9999") > 0 && this._reconnect_counter <= 3) {
          return this.reconnect().then(() => {
            return this.handleRequest(payload).then((result) => {
              return result ? true : false;
            });
          });
        }
        this._reconnect_counter = 0;
        return false;
      });
    } else {
      return this.handleKlapRequest(payload).then((result) => {
        return result ? true : false;
      }).catch((error) => {
        if (error.message && error.message.indexOf("9999") > 0 && this._reconnect_counter <= 3) {
          return this.newReconnect().then(() => {
            return this.handleKlapRequest(payload).then((result) => {
              return result ? true : false;
            });
          });
        }
        this._reconnect_counter = 0;
        return false;
      });
    }
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
      return this._axios.post(URL, securePassthroughPayload, config).then((res) => {
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
        return this.handleError(error.message, "656");
      });
    }
    return new Promise((resolve, reject) => {
      reject();
    });
  }
  handleKlapRequest(payload) {
    if (this.newTpLinkCipher) {
      const data = this.newTpLinkCipher.encrypt(payload);
      return this.raw_request("request", data.encryptedPayload, "arraybuffer", { seq: data.seq.toString() }).then((res) => {
        return JSON.parse(this.newTpLinkCipher.decrypt(res));
      }).catch((error) => {
        return this.handleError(error.message, "671");
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
  async newReconnect() {
    this._reconnect_counter++;
    return this.handshake_new().then(() => {
      return;
    });
  }
  reAuthenticate() {
    this.log.debug("Reauthenticating");
    if (this.is_klap) {
      this.handshake_new().then(() => {
        this.log.info("KLAP Authenticated successfully");
      }).catch(() => {
        this.log.error("KLAP Handshake New failed");
        this.is_klap = false;
      });
    } else {
      this.handshake().then(() => {
        this.login().then(() => {
          this.log.info("Authenticated successfully");
        }).catch(() => {
          this.log.error("Login failed");
        });
      });
    }
  }
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {});
//# sourceMappingURL=p100.js.map
