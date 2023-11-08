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
var import_https = __toESM(require("https"));
var import_node_fetch = __toESM(require("node-fetch"));
var import_onvifCamera = require("./onvifCamera");
class TAPOCamera extends import_onvifCamera.OnvifCamera {
  constructor(log, config) {
    super(log, config);
    this.log = log;
    this.config = config;
    this.kTokenExpiration = 1e3 * 60 * 60;
    this.kStreamPort = 554;
    this.pendingAPIRequests = /* @__PURE__ */ new Map();
    this.log.debug("Constructing Camera on host: " + config.ipAddress);
    this.httpsAgent = new import_https.default.Agent({
      rejectUnauthorized: false
    });
    this.hashedPassword = import_crypto.default.createHash("md5").update(config.password).digest("hex").toUpperCase();
  }
  fetch(url, data) {
    return (0, import_node_fetch.default)(url, {
      ...data,
      agent: this.httpsAgent
    });
  }
  getTapoAPICredentials() {
    return {
      username: "admin",
      password: this.hashedPassword
    };
  }
  getAuthenticatedStreamUrl(lowQuality) {
    const prefix = `rtsp://${this.config.streamUser}:${this.config.streamPassword}@${this.config.ipAddress}:${this.kStreamPort}`;
    return lowQuality ? `${prefix}/stream2` : `${prefix}/stream1`;
  }
  async fetchToken() {
    this.log.debug(`[${this.config.name}]`, "Fetching new token");
    const response = await this.fetch(`https://${this.config.ipAddress}/`, {
      method: "post",
      body: JSON.stringify({
        method: "login",
        params: this.getTapoAPICredentials()
      }),
      headers: {
        "Content-Type": "application/json"
      }
    });
    const json = await response.json();
    if (!json.result.stok) {
      throw new Error(
        "Unable to find token in response, probably your credentials are not valid. Please make sure you set your TAPO Cloud password"
      );
    }
    return json.result.stok;
  }
  async getToken() {
    if (this.token && this.token[1] + this.kTokenExpiration > Date.now()) {
      return this.token[0];
    }
    if (this.tokenPromise) {
      return this.tokenPromise();
    }
    this.tokenPromise = async () => {
      try {
        this.log.debug(`[${this.config.name}]`, "Token is expired , requesting new one.");
        const token = await this.fetchToken();
        this.token = [token, Date.now()];
        return token;
      } finally {
        this.tokenPromise = void 0;
      }
    };
    return this.tokenPromise();
  }
  async getTAPOCameraAPIUrl() {
    const token = await this.getToken();
    return `https://${this.config.ipAddress}/stok=${token}/ds`;
  }
  async makeTAPOAPIRequest(req) {
    const reqJson = JSON.stringify(req);
    if (this.pendingAPIRequests.has(reqJson)) {
      return this.pendingAPIRequests.get(reqJson);
    }
    this.log.debug(
      `[${this.config.name}]`,
      "Making new request req =",
      req.params.requests.map((e) => e.method)
    );
    this.pendingAPIRequests.set(
      reqJson,
      (async () => {
        try {
          const url = await this.getTAPOCameraAPIUrl();
          const response = await this.fetch(url, {
            method: "post",
            body: JSON.stringify(req),
            headers: {
              "Content-Type": "application/json"
            }
          }).catch((e) => {
            this.log.warn("makeTAPOAPIRequest error: ", e);
            return;
          });
          const json = await response.json();
          this.log.debug(`makeTAPOAPIRequest url: ${url}, json: ${JSON.stringify(json)}`);
          if (json.error_code !== 0) {
            this.log.info("Reset token. error_code: ", json.error_code);
            this.token = void 0;
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
    const json = await this.makeTAPOAPIRequest({
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
    return json.error_code !== 0;
  }
  async setAlertConfig(value) {
    const json = await this.makeTAPOAPIRequest({
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
    const json = await this.makeTAPOAPIRequest({
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
  async getTAPODeviceInfo() {
    const json = await this.makeTAPOAPIRequest({
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
    const json = await this.makeTAPOAPIRequest({
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
