"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
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
var utils = __toESM(require("@iobroker/adapter-core"));
var import_axios = __toESM(require("axios"));
var import_crypto = __toESM(require("crypto"));
var import_https = __toESM(require("https"));
var import_json2iob = __toESM(require("./lib/json2iob"));
var import_l510e = __toESM(require("./lib/utils/l510e"));
var import_l530 = __toESM(require("./lib/utils/l530"));
var import_p100 = __toESM(require("./lib/utils/p100"));
var import_p110 = __toESM(require("./lib/utils/p110"));
class Tapo extends utils.Adapter {
  constructor(options = {}) {
    super({
      ...options,
      name: "tapo"
    });
    this.updateInterval = null;
    this.reLoginTimeout = null;
    this.refreshTokenTimeout = null;
    this.session = {};
    this.on("ready", this.onReady.bind(this));
    this.on("stateChange", this.onStateChange.bind(this));
    this.on("unload", this.onUnload.bind(this));
    this.devices = {};
    this.deviceObjects = {};
    this.json2iob = new import_json2iob.default(this);
    this.requestClient = import_axios.default.create({
      httpsAgent: new import_https.default.Agent({
        rejectUnauthorized: false
      })
    });
    this.secret = Buffer.from([
      54,
      101,
      100,
      55,
      100,
      57,
      55,
      102,
      51,
      101,
      55,
      51,
      52,
      54,
      55,
      102,
      56,
      97,
      53,
      98,
      97,
      98,
      57,
      48,
      98,
      53,
      55,
      55,
      98,
      97,
      52,
      99
    ]);
  }
  async onReady() {
    this.setState("info.connection", false, true);
    if (this.config.interval < 0.5) {
      this.log.info("Set interval to minimum 0.5");
      this.config.interval = 0.5;
    }
    if (!this.config.username || !this.config.password) {
      this.log.error("Please set username and password in the instance settings");
      return;
    }
    this.updateInterval = null;
    this.reLoginTimeout = null;
    this.refreshTokenTimeout = null;
    this.session = {};
    this.subscribeStates("*");
    this.log.info("Login tp TAPO App");
    await this.login();
    if (this.session.token) {
      await this.getDeviceList();
      this.log.info("Wait for connections");
      await this.sleep(1e4);
      await this.updateDevices();
      this.updateInterval = setInterval(async () => {
        await this.updateDevices();
      }, this.config.interval * 1e3);
    }
  }
  async login() {
    let body = JSON.stringify({
      appVersion: "2.8.21",
      refreshTokenNeeded: true,
      platform: "iOS 14.8",
      cloudPassword: this.config.password,
      terminalUUID: "CDE6601E-148C-4CB7-831F-FD587E999D99",
      cloudUserName: this.config.username,
      terminalName: "iPhone",
      terminalMeta: "3",
      appType: "TP-Link_Tapo_iOS"
    });
    let path = "api/v2/account/login";
    const mfaIdState = await this.getStateAsync("mfaId");
    if (mfaIdState && mfaIdState.val) {
      if (!this.config.mfa) {
        this.log.error("Please set mfa in the instance settings");
        return;
      }
      body = JSON.stringify({
        cloudUserName: this.config.username,
        MFAProcessId: mfaIdState.val,
        appType: "TP-Link_Tapo_iOS",
        MFAType: 2,
        code: this.config.mfa,
        terminalBindEnabled: true
      });
      path = "api/v2/account/checkMFACodeAndLogin";
      await this.setStateAsync("mfaId", "", true);
    }
    const md5 = import_crypto.default.createHash("md5").update(body).digest("base64");
    this.log.debug(md5);
    const content = md5 + "\n9999999999\nfee66616-58dd-4bcb-be79-fe092d800a21\n/" + path;
    const signature = import_crypto.default.createHmac("sha1", this.secret).update(content).digest("hex");
    await this.requestClient({
      method: "post",
      url: "https://n-wap-gw.tplinkcloud.com/" + path + "?termID=CDE6601E-148C-4CB7-831F-FD587E954C69&appVer=2.8.21&locale=de_DE&appName=TP-Link_Tapo_iOS&netType=wifi&model=iPhone10%2C5&termName=iPhone&termMeta=3&brand=TPLINK&ospf=iOS%2014.8",
      headers: {
        "Content-Type": "application/json;UTF-8",
        Accept: "*/*",
        "User-Agent": "Tapo/2.8.21 (iPhone; iOS 14.8; Scale/3.00)",
        "Accept-Language": "de-DE;q=1, uk-DE;q=0.9, en-DE;q=0.8",
        "X-Authorization": "Timestamp=9999999999, Nonce=fee66616-58dd-4bcb-be79-fe092d800a21, AccessKey=4d11b6b9d5ea4d19a829adbb9714b057, Signature=" + signature
      },
      data: body
    }).then(async (res) => {
      var _a, _b;
      this.log.debug(JSON.stringify(res.data));
      if (res.data.error_code) {
        this.log.error(JSON.stringify(res.data));
        return;
      }
      if ((_a = res.data.result) == null ? void 0 : _a.MFAProcessId) {
        this.log.info("Found MFA Process please enter MFA in the instance settings");
        await this.setObjectNotExistsAsync("mfaId", {
          type: "state",
          common: {
            name: "MFA Id",
            write: false,
            read: true,
            type: "string",
            role: "text"
          },
          native: {}
        });
        await this.setStateAsync("mfaId", (_b = res.data.result) == null ? void 0 : _b.MFAProcessId, true);
        const body2 = JSON.stringify({
          cloudPassword: this.config.password,
          locale: "de_DE",
          terminalUUID: "CDE6601E-148C-4CB7-831F-FD587E999D99",
          cloudUserName: this.config.username,
          appType: "TP-Link_Tapo_iOS"
        });
        const path2 = "api/v2/account/getEmailVC4TerminalMFA";
        const md52 = import_crypto.default.createHash("md5").update(body2).digest("base64");
        this.log.debug(md52);
        const content2 = md52 + "\n9999999999\nfee66616-58dd-4bcb-be79-fe092d800a21\n/" + path2;
        const signature2 = import_crypto.default.createHmac("sha1", this.secret).update(content2).digest("hex");
        await this.requestClient({
          method: "post",
          url: "https://n-wap-gw.tplinkcloud.com/" + path2 + "?termID=CDE6601E-148C-4CB7-831F-FD587E954C69&appVer=2.8.21&locale=de_DE&appName=TP-Link_Tapo_iOS&netType=wifi&model=iPhone10%2C5&termName=iPhone&termMeta=3&brand=TPLINK&ospf=iOS%2014.8",
          headers: {
            "Content-Type": "application/json;UTF-8",
            Accept: "*/*",
            "User-Agent": "Tapo/2.8.21 (iPhone; iOS 14.8; Scale/3.00)",
            "Accept-Language": "de-DE;q=1, uk-DE;q=0.9, en-DE;q=0.8",
            "X-Authorization": "Timestamp=9999999999, Nonce=fee66616-58dd-4bcb-be79-fe092d800a21, AccessKey=4d11b6b9d5ea4d19a829adbb9714b057, Signature=" + signature2
          },
          data: body2
        }).then(async (res2) => {
          this.log.debug(JSON.stringify(res2.data));
          if (res2.data.error_code) {
            this.log.error(JSON.stringify(res2.data));
            return;
          }
        }).catch((error) => {
          this.log.error(error);
          error.response && this.log.error(JSON.stringify(error.response.data));
        });
        return;
      }
      this.setState("info.connection", true, true);
      this.session = res.data.result;
      return;
    }).catch((error) => {
      this.log.error(error);
      error.response && this.log.error(JSON.stringify(error.response.data));
    });
  }
  async getDeviceList() {
    const body = '{"index":0,"deviceTypeList":["SMART.TAPOBULB","SMART.TAPOPLUG","SMART.IPCAMERA","SMART.TAPOHUB","SMART.TAPOSENSOR","SMART.TAPOSWITCH"],"limit":20}';
    const md5 = import_crypto.default.createHash("md5").update(body).digest("base64");
    this.log.debug(md5);
    const content = md5 + "\n9999999999\nfee66616-58dd-4bcb-be79-fe092d800a21\n/api/v2/common/getDeviceListByPage";
    const signature = import_crypto.default.createHmac("sha1", this.secret).update(content).digest("hex");
    await this.requestClient({
      method: "post",
      url: `https://n-euw1-wap-gw.tplinkcloud.com/api/v2/common/getDeviceListByPage?token=${this.session.token}&termID=CDE6601E-148C-4CB7-831F-FD587E954C69&appVer=2.8.21&locale=de_DE&appName=TP-Link_Tapo_iOS&netType=wifi&model=iPhone10%2C5&termName=iPhone&termMeta=3&brand=TPLINK&ospf=iOS%2014.8`,
      headers: {
        "Content-Type": "application/json;UTF-8",
        "Content-MD5": md5,
        Accept: "*/*",
        "User-Agent": "Tapo/2.8.21 (iPhone; iOS 14.8; Scale/3.00)",
        "Accept-Language": "de-DE;q=1, uk-DE;q=0.9, en-DE;q=0.8",
        "X-Authorization": "Timestamp=9999999999, Nonce=fee66616-58dd-4bcb-be79-fe092d800a21, AccessKey=4d11b6b9d5ea4d19a829adbb9714b057, Signature=" + signature
      },
      data: body
    }).then(async (res) => {
      var _a, _b;
      this.log.debug(JSON.stringify(res.data));
      if (res.data.error_code) {
        this.log.error(JSON.stringify(res.data));
        return;
      }
      this.log.info(`Found ${(_a = res.data.result) == null ? void 0 : _a.totalNum} devices`);
      for (const device of (_b = res.data.result) == null ? void 0 : _b.deviceList) {
        const id = device.deviceId;
        this.devices[id] = device;
        const name = Buffer.from(device.alias, "base64").toString("utf8");
        await this.setObjectNotExistsAsync(id, {
          type: "device",
          common: {
            name
          },
          native: {}
        });
        await this.setObjectNotExistsAsync(id + ".remote", {
          type: "channel",
          common: {
            name: "Remote Controls"
          },
          native: {}
        });
        const remoteArray = [
          { command: "refresh", name: "True = Refresh" },
          { command: "setPowerState", name: "True = On, False = Off" },
          {
            command: "setBrightness",
            name: "Set Brightness for Light devices",
            type: "number",
            role: "level.brightness",
            def: 5
          },
          {
            command: "setColorTemp",
            name: "Set Color Temp for Light devices",
            type: "number",
            role: "level.color.temperature",
            def: 3e3
          },
          {
            command: "setColor",
            name: "Set Color for Light devices (hue, saturation)",
            def: "30, 100",
            type: "string"
          }
        ];
        remoteArray.forEach((remote) => {
          this.setObjectNotExists(id + ".remote." + remote.command, {
            type: "state",
            common: {
              name: remote.name || "",
              type: remote.type || "boolean",
              role: remote.role || "boolean",
              def: remote.def || false,
              write: true,
              read: true
            },
            native: {}
          });
        });
        this.json2iob.parse(id, device);
        const body2 = `{"requestData":{"method":"get_device_info","terminalUUID":"01D6B18A-5514-4C9F-B49C-555E775591B2"},"deviceId":"${id}"}`;
        const md52 = import_crypto.default.createHash("md5").update(body2).digest("base64");
        this.log.debug(md52);
        const content2 = md52 + "\n9999999999\nfee66616-58dd-4bcb-be79-fe092d800a21\n/api/v2/common/passthrough";
        const signature2 = import_crypto.default.createHmac("sha1", this.secret).update(content2).digest("hex");
        await this.requestClient({
          method: "post",
          url: `https://n-euw1-wap-gw.tplinkcloud.com/api/v2/common/passthrough?token=${this.session.token}&termID=CDE6601E-148C-4CB7-831F-FD587E954C69&appVer=2.8.21&locale=de_DE&appName=TP-Link_Tapo_iOS&netType=wifi&model=iPhone10%2C5&termName=iPhone&termMeta=3&brand=TPLINK&ospf=iOS%2014.8`,
          headers: {
            "Content-Type": "application/json;UTF-8",
            "Content-MD5": md52,
            Accept: "*/*",
            "User-Agent": "Tapo/2.8.21 (iPhone; iOS 14.8; Scale/3.00)",
            "Accept-Language": "de-DE;q=1, uk-DE;q=0.9, en-DE;q=0.8",
            "X-Authorization": "Timestamp=9999999999, Nonce=fee66616-58dd-4bcb-be79-fe092d800a21, AccessKey=4d11b6b9d5ea4d19a829adbb9714b057, Signature=" + signature2
          },
          data: body2
        }).then(async (res2) => {
          var _a2, _b2;
          this.log.debug(JSON.stringify(res2.data));
          let result = {};
          if (res2.data.error_code) {
            this.log.error(JSON.stringify(res2.data));
          } else {
            result = (_b2 = (_a2 = res2.data.result) == null ? void 0 : _a2.responseData) == null ? void 0 : _b2.result;
            this.devices[id] = { ...this.devices[id], ...result };
          }
          if (!result.ip) {
            const ipState = await this.getStateAsync(id + ".ip");
            if (ipState && ipState.val) {
              this.devices[id].ip = ipState.val;
            } else {
              await this.setObjectNotExistsAsync(id + ".ip", {
                type: "state",
                common: {
                  name: "IP",
                  write: true,
                  read: true,
                  type: "string",
                  role: "text"
                },
                native: {}
              });
              this.log.warn(`No IP found for ${id} put the device online or set the ip state manually`);
            }
          }
          if (this.devices[id].ip) {
            await this.initDevice(id);
          }
          this.json2iob.parse(id, result);
        }).catch((error) => {
          this.log.error(error);
          error.response && this.log.error(JSON.stringify(error.response.data));
        });
      }
    }).catch((error) => {
      this.log.error(error);
      error.response && this.log.error(JSON.stringify(error.response.data));
    });
  }
  async initDevice(id) {
    const device = this.devices[id];
    this.log.info(`Init device ${id} type ${device.deviceName} with ip ${device.ip}`);
    let deviceObject;
    if (device.deviceName === "P100") {
      deviceObject = new import_p100.default(this.log, device.ip, this.config.username, this.config.password, 2);
    } else if (device.deviceName === "P110") {
      deviceObject = new import_p110.default(this.log, device.ip, this.config.username, this.config.password, 2);
    } else if (device.deviceName === "L530") {
      deviceObject = new import_l530.default(this.log, device.ip, this.config.username, this.config.password, 2);
    } else if (device.deviceName === "L510E") {
      deviceObject = new import_l510e.default(this.log, device.ip, this.config.username, this.config.password, 2);
    } else {
      this.log.info(`Unknown device type ${device.deviceName} init as P100`);
      deviceObject = new import_p100.default(this.log, device.ip, this.config.username, this.config.password, 2);
    }
    this.deviceObjects[id] = deviceObject;
    await deviceObject.handshake().then(() => {
      deviceObject.login().then(() => {
        deviceObject.getDeviceInfo().then((sysInfo) => {
          this.log.debug(JSON.stringify(sysInfo));
          this.json2iob.parse(id, sysInfo);
          const interval = this.config.interval ? this.config.interval * 1e3 : 3e4;
          this.log.debug("interval: " + interval);
          setTimeout(() => {
          }, interval);
        }).catch(() => {
          this.log.error("52 - Get Device Info failed");
        });
      }).catch(() => {
        this.log.error("Login failed");
      });
    }).catch(() => {
      this.log.error("Handshake failed");
    });
  }
  async updateDevices() {
    try {
      for (const deviceId in this.deviceObjects) {
        this.deviceObjects[deviceId].getDeviceInfo().then((sysInfo) => {
          this.log.debug(JSON.stringify(sysInfo));
          this.json2iob.parse(deviceId, sysInfo);
        }).catch((error) => {
          this.log.error(`Get Device Info failed for ${deviceId} - ${error}`);
        });
      }
    } catch (error) {
      this.log.error(error);
    }
  }
  async sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
  async refreshToken() {
    this.log.debug("Refresh token");
  }
  onUnload(callback) {
    try {
      this.setState("info.connection", false, true);
      this.refreshTimeout && clearTimeout(this.refreshTimeout);
      this.reLoginTimeout && clearTimeout(this.reLoginTimeout);
      this.refreshTokenTimeout && clearTimeout(this.refreshTokenTimeout);
      this.updateInterval && clearInterval(this.updateInterval);
      this.refreshTokenInterval && clearInterval(this.refreshTokenInterval);
      callback();
    } catch (e) {
      callback();
    }
  }
  onStateChange(id, state) {
    if (state) {
      if (!state.ack) {
        const deviceId = id.split(".")[2];
        const command = id.split(".")[4];
        if (id.split(".")[3] !== "remote") {
          return;
        }
        if (command === "Refresh") {
          this.deviceObjects[deviceId].getDeviceInfo().then((sysInfo) => {
            this.log.debug(JSON.stringify(sysInfo));
            this.json2iob.parse(deviceId, sysInfo);
          }).catch((error) => {
            this.log.error(`Get Device Info failed for ${deviceId} - ${error}`);
          });
          return;
        }
        try {
          if (this.deviceObjects[deviceId][command]) {
            if (command === "setColor") {
              const valueSplit = state.val.split(", ");
              this.log.info(this.deviceObjects[deviceId][command](valueSplit[0], valueSplit[1]));
            } else {
              this.log.info(this.deviceObjects[deviceId][command](state.val));
            }
          } else {
            this.log.error(`Device ${deviceId} has no command ${command}`);
          }
        } catch (error) {
          this.log.error(error);
        }
      }
    }
  }
}
if (require.main !== module) {
  module.exports = (options) => new Tapo(options);
} else {
  (() => new Tapo())();
}
//# sourceMappingURL=main.js.map
