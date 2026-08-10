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
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var utils = __toESM(require("@iobroker/adapter-core"));
var import_axios = __toESM(require("axios"));
var import_crypto = __toESM(require("crypto"));
var import_https = __toESM(require("https"));
var import_json2iob = __toESM(require("json2iob"));
var import_tapoCamera = require("./lib/utils/camera/tapoCamera");
var import_l510e = __toESM(require("./lib/utils/l510e"));
var import_l520e = __toESM(require("./lib/utils/l520e"));
var import_l530 = __toESM(require("./lib/utils/l530"));
var import_p100 = __toESM(require("./lib/utils/p100"));
var import_p110 = __toESM(require("./lib/utils/p110"));
var import_d100c = __toESM(require("./lib/utils/d100c"));
var import_udpDiscovery = require("./lib/utils/udpDiscovery");
var import_doorbellMonitor = require("./lib/utils/camera/doorbellMonitor");
class Tapo extends utils.Adapter {
  devices;
  deviceObjects;
  json2iob;
  secret;
  requestClient;
  updateInterval = null;
  reLoginTimeout = null;
  refreshTokenTimeout = null;
  session = {};
  refreshTimeout;
  refreshTokenInterval;
  firstStart = true;
  lastBatteryDeviceUpdateTimestamp = 0;
  termId;
  constructor(options = {}) {
    super({
      ...options,
      name: "tapo"
    });
    this.on("ready", this.onReady.bind(this));
    this.on("stateChange", this.onStateChange.bind(this));
    this.on("unload", this.onUnload.bind(this));
    this.devices = {};
    this.deviceObjects = {};
    this.json2iob = new import_json2iob.default(this);
    this.requestClient = import_axios.default.create({
      httpsAgent: new import_https.default.Agent({
        rejectUnauthorized: false,
        secureOptions: import_crypto.default.constants.SSL_OP_LEGACY_SERVER_CONNECT
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
  /**
   * Is called when databases are connected and adapter received configuration.
   */
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
    this.config.username = this.config.username.toLowerCase();
    this.updateInterval = null;
    this.reLoginTimeout = null;
    this.refreshTokenTimeout = null;
    this.session = {};
    this.subscribeStates("*");
    const termIdState = await this.getStateAsync("termId");
    if (termIdState && termIdState.val) {
      this.termId = termIdState.val;
    } else {
      await this.setObjectNotExistsAsync("termId", {
        type: "state",
        common: {
          name: "Terminal ID",
          write: false,
          read: true,
          type: "string",
          role: "text"
        },
        native: {}
      });
      this.termId = import_crypto.default.randomUUID();
      await this.setStateAsync("termId", this.termId, true);
    }
    this.log.info("Login tp TAPO App");
    await this.login();
    if (this.session.token) {
      await this.getDeviceList();
    } else {
      this.log.warn("Login failed using cached device list");
      const deviceListState = await this.getStateAsync("deviceList");
      if (deviceListState && deviceListState.val) {
        this.log.info("Use cached device list");
        this.devices = JSON.parse(deviceListState.val);
        for (const id in this.devices) {
          if (this.devices[id].ip) {
            const initResult = await this.initDevice(id).then(() => {
              this.log.info(`Initialized ${id}`);
            }).catch((e) => {
              this.log.error((e == null ? void 0 : e.message) || e || "initDevice failed");
            });
            this.log.debug(`initResult ${id} ${JSON.stringify(initResult)}`);
          }
        }
      }
    }
    this.log.info("Wait for connections for non camera devices");
    await this.sleep(1e4);
    this.log.info("Start first Update");
    this.updateDevices();
    this.firstStart = false;
    this.updateInterval = setInterval(async () => {
      this.updateDevices();
    }, this.config.interval * 1e3);
  }
  async login() {
    let body = JSON.stringify({
      appVersion: "2.8.21",
      refreshTokenNeeded: true,
      platform: "iOS 14.8",
      cloudPassword: this.config.password,
      terminalUUID: this.termId,
      cloudUserName: this.config.username,
      terminalName: "ioBroker",
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
      url: "https://n-wap-gw.tplinkcloud.com/" + path + "?termID=" + this.termId + "&appVer=2.8.21&locale=de_DE&appName=TP-Link_Tapo_iOS&netType=wifi&model=iPhone10%2C5&termName=iPhone&termMeta=3&brand=TPLINK&ospf=iOS%2014.8",
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
          terminalUUID: this.termId,
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
          url: "https://n-wap-gw.tplinkcloud.com/" + path2 + "?termID=" + this.termId + "&appVer=2.8.21&locale=de_DE&appName=TP-Link_Tapo_iOS&netType=wifi&model=iPhone10%2C5&termName=iPhone&termMeta=3&brand=TPLINK&ospf=iOS%2014.8",
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
      if (!res.data.result || !res.data.result.token) {
        this.log.error("Login failed");
        this.log.error(JSON.stringify(res.data));
        return;
      }
      this.session = res.data.result;
      if (this.session.token) {
        this.log.info("Login succesfull");
        this.setState("info.connection", true, true);
      }
      return;
    }).catch((error) => {
      this.log.error(error);
      error.response && this.log.error(JSON.stringify(error.response.data));
    });
  }
  async getDeviceList() {
    const body = '{"index":0,"deviceTypeList":["SMART.TAPOBULB","SMART.TAPOPLUG","SMART.IPCAMERA","SMART.TAPOHUB","SMART.TAPOSENSOR","SMART.TAPOSWITCH","SMART.TAPODOORBELL","SMART.TAPOCHIME","SMART.TAPOLOCK","SMART.TAPOROBOVAC","SMART.TAPONVR"],"limit":30}';
    const md5 = import_crypto.default.createHash("md5").update(body).digest("base64");
    this.log.debug(md5);
    const content = md5 + "\n9999999999\nfee66616-58dd-4bcb-be79-fe092d800a21\n/api/v2/common/getDeviceListByPage";
    const signature = import_crypto.default.createHmac("sha1", this.secret).update(content).digest("hex");
    await this.requestClient({
      method: "post",
      url: `https://n-euw1-wap-gw.tplinkcloud.com/api/v2/common/getDeviceListByPage?token=${this.session.token}&termID=${this.termId}&appVer=2.8.21&locale=de_DE&appName=TP-Link_Tapo_iOS&netType=wifi&model=iPhone10%2C5&termName=iPhone&termMeta=3&brand=TPLINK&ospf=iOS%2014.8`,
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
      for (const device of ((_b = res.data.result) == null ? void 0 : _b.deviceList) || []) {
        const id = device.deviceId;
        this.devices[id] = device;
        let name = device.alias;
        if (this.isBase64(device.alias)) {
          name = Buffer.from(device.alias, "base64").toString("utf8");
        }
        this.log.debug(`Found device ${id} ${name}`);
        await this.extendObject(id, {
          type: "device",
          common: {
            name
          },
          native: {}
        });
        await this.setObjectNotExistsAsync(id + ".connected", {
          type: "state",
          common: {
            name: "Device connected",
            type: "boolean",
            role: "indicator.reachable",
            read: true,
            write: false,
            def: false
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
        const baseRemotes = [
          { command: "refresh", name: "True = Refresh" },
          { command: "setPowerState", name: "True = On, False = Off" },
          { command: "setLedEnabled", name: "LED Indicator On/Off" },
          { command: "setAutoUpdate", name: "Firmware Auto-Update On/Off" }
        ];
        const plugExtras = [
          { command: "setAutoOff", name: "Auto-Off On/Off" },
          { command: "setAutoOffDelay", name: "Auto-Off Delay (minutes)", type: "number", def: 120, role: "level" },
          { command: "setChildProtection", name: "Button Lock On/Off" }
        ];
        const energyExtras = [
          ...plugExtras,
          { command: "setPowerProtection", name: "Overload Protection On/Off" },
          { command: "setPowerProtectionThreshold", name: "Overload Threshold (Watts)", type: "number", def: 2300, role: "level" }
        ];
        const lightExtras = [
          { command: "setBrightness", name: "Brightness (0-100)", type: "number", role: "level.brightness", def: 5 },
          { command: "setColorTemp", name: "Color Temp (2500-6500K)", type: "number", role: "level.color.temperature", def: 3e3 },
          { command: "setColor", name: "Color (hue, saturation)", def: "30, 100", type: "string" },
          { command: "setLightEffect", name: "Light Effect (id/off)", type: "string", def: "off", role: "text" },
          { command: "setGradualOnOff", name: "Gradual On/Off" }
        ];
        const fanExtras = [
          { command: "setFanSpeedLevel", name: "Fan Speed (0-4)", type: "number", def: 0, role: "level" },
          { command: "setFanSleepMode", name: "Fan Sleep Mode On/Off" }
        ];
        const hubExtras = [
          { command: "setPowerStateChild", name: "childId,true" },
          { command: "playAlarm", name: "True = Play Alarm" },
          { command: "stopAlarm", name: "True = Stop Alarm" },
          { command: "setAlarmVolume", name: "Alarm Volume (mute/low/normal/high)", type: "string", def: "normal", role: "text" },
          { command: "setAlarmDuration", name: "Alarm Duration (seconds)", type: "number", def: 10, role: "level" }
        ];
        const thermostatExtras = [
          { command: "setTargetTemperature", name: "Target Temperature", type: "number", def: 20, role: "level.temperature" },
          { command: "setTemperatureOffset", name: "Temperature Offset (-10..10)", type: "number", def: 0, role: "level" },
          { command: "setFrostProtection", name: "Frost Protection On/Off" }
        ];
        const chimeExtras = [
          { command: "playAlarm", name: "True = Play Chime" },
          { command: "stopAlarm", name: "True = Stop Chime" },
          { command: "setVolume", name: "Chime Volume (1-15)", type: "number", def: 8, role: "level.volume" },
          { command: "setRingType", name: "Ring Type", type: "string", def: "", role: "text" }
        ];
        const cameraRemotes = [
          { command: "refresh", name: "True = Refresh" },
          { command: "setAlertConfig", name: "Alarm On/Off" },
          { command: "setLensMaskConfig", name: "Privacy (Eyes) On/Off" },
          { command: "setForceWhitelampState", name: "Force Whitelamp On/Off" },
          { command: "setLedStatus", name: "LED On/Off" },
          { command: "setMsgPushConfig", name: "Notifications On/Off" },
          { command: "setDetectionConfig", name: "Motion Detection On/Off" },
          { command: "setAutoTrackTarget", name: "Auto Track On/Off" },
          { command: "setPersonDetection", name: "Person Detection On/Off" },
          { command: "setVehicleDetection", name: "Vehicle Detection On/Off" },
          { command: "setPetDetection", name: "Pet Detection On/Off" },
          { command: "setBabyCryDetection", name: "Baby Cry Detection On/Off" },
          { command: "setBarkDetection", name: "Bark Detection On/Off" },
          { command: "setMeowDetection", name: "Meow Detection On/Off" },
          { command: "setGlassBreakDetection", name: "Glass Break Detection On/Off" },
          { command: "setTamperDetection", name: "Tamper Detection On/Off" },
          { command: "setImageFlipVertical", name: "Image Flip On/Off" },
          { command: "setLensDistortionCorrection", name: "Lens Distortion Correction On/Off" },
          { command: "setRecordAudio", name: "Record Audio On/Off" },
          { command: "setAutoUpgrade", name: "Auto Firmware Upgrade On/Off" },
          { command: "setHDR", name: "HDR On/Off" },
          { command: "setCoverConfig", name: "Privacy Zones On/Off" },
          { command: "setRecordPlan", name: "SD Card Recording On/Off" },
          { command: "moveMotor", name: "Move Camera X,Y (-360..360, -45..45)", type: "string", def: "0, 0", role: "text" },
          { command: "moveMotorStep", name: "Angle (0-360)", type: "string", def: "180", role: "text" },
          { command: "moveToPreset", name: "PresetId", type: "string", def: "1", role: "text" },
          { command: "calibrateMotor", name: "True = Calibrate Motor" },
          { command: "savePreset", name: "Save Preset (name)", type: "string", def: "", role: "text" },
          { command: "deletePreset", name: "Delete Preset (id)", type: "string", def: "", role: "text" },
          { command: "setCruise", name: "Patrol (x/y/off)", type: "string", def: "off", role: "text" },
          { command: "startManualAlarm", name: "True = Start Alarm" },
          { command: "stopManualAlarm", name: "True = Stop Alarm" },
          { command: "setAlarmMode", name: "Alarm Mode (both/light/sound/off)", type: "string", def: "off", role: "text" },
          { command: "setDayNightMode", name: "Day/Night Mode (auto/on/off)", type: "string", def: "auto", role: "text" },
          { command: "setLightFrequencyMode", name: "Light Frequency (auto/50/60)", type: "string", def: "auto", role: "text" },
          { command: "setSpeakerVolume", name: "Speaker Volume (0-100)", type: "number", def: 50, role: "level" },
          { command: "setMicrophoneVolume", name: "Microphone Volume (0-100)", type: "number", def: 50, role: "level" },
          { command: "setMotionDetectionSensitivity", name: "Motion Sensitivity (high/normal/low)", type: "string", def: "normal", role: "text" },
          { command: "setPersonDetectionSensitivity", name: "Person Sensitivity (high/normal/low)", type: "string", def: "normal", role: "text" },
          { command: "setOsd", name: "OSD Label Text", type: "string", def: "", role: "text" },
          { command: "reboot", name: "True = Reboot Camera" },
          { command: "formatSdCard", name: "True = Format SD Card" }
        ];
        let remoteArray;
        const dn = device.deviceName || "";
        if (device.deviceType.includes("CAMERA") || device.deviceType.includes("DOORBELL")) {
          remoteArray = cameraRemotes;
        } else if (device.deviceType.includes("CHIME") || dn.startsWith("D100")) {
          remoteArray = [...baseRemotes, ...chimeExtras];
        } else if (dn.startsWith("P110") || dn.startsWith("P115")) {
          remoteArray = [...baseRemotes, ...energyExtras];
        } else if (dn.startsWith("P")) {
          remoteArray = [...baseRemotes, ...plugExtras];
        } else if (dn.startsWith("L") || dn.startsWith("KL")) {
          remoteArray = [...baseRemotes, ...lightExtras];
        } else if (dn.startsWith("F")) {
          remoteArray = [...baseRemotes, ...fanExtras];
        } else if (dn.startsWith("H")) {
          remoteArray = [...baseRemotes, ...hubExtras];
        } else if (dn.startsWith("KE")) {
          remoteArray = [...baseRemotes, ...thermostatExtras];
        } else {
          remoteArray = [...baseRemotes, ...plugExtras];
        }
        remoteArray.forEach((remote) => {
          this.extendObject(id + ".remote." + remote.command, {
            type: "state",
            common: {
              name: remote.name || "",
              type: remote.type || "boolean",
              role: remote.role || "switch",
              def: remote.def != null ? remote.def : false,
              write: true,
              read: true
            },
            native: {}
          });
        });
        this.json2iob.parse(id, device, { channelName: name });
        await this.requestClient({
          method: "get",
          url: "https://euw1-app-server.iot.i.tplinknbu.com/v1/things/" + id + "/details",
          headers: {
            "x-locale": "de",
            Authorization: "ut|" + this.session.token,
            "app-cid": "app:TP-Link_Tapo_iOS:" + this.termId,
            "x-ospf": "iOS 14.8",
            "x-app-name": "TP-Link_Tapo_iOS",
            Accept: "*/*",
            "Accept-Language": "de-DE;q=1, uk-DE;q=0.9, en-DE;q=0.8",
            "Content-Type": "application/json;UTF-8",
            "User-Agent": "Tapo/2.9.7 (iPhone; iOS 14.8; Scale/3.00)",
            "x-term-id": this.termId,
            "x-app-version": "2.9.7",
            "x-net-type": "wifi"
          }
        }).then(async (res2) => {
          this.log.debug(JSON.stringify(res2.data));
          if (res2.data.error_code) {
            this.log.error(JSON.stringify(res2.data));
            return;
          } else {
            this.devices[id] = { ...this.devices[id], ...res2.data };
          }
        }).catch((error) => {
          this.log.warn(error);
          error.response && this.log.error(JSON.stringify(error.response.data));
        });
        if (!this.devices[id].ip) {
          const body2 = `{
              "requestData": {
                "method": "multipleRequest",
                "params": {
                  "requests": [{
                    "method": "getDeviceIpAddress",
                    "params": {
                      "network": {
                        "name": "wan"
                      }
                    }
                  }]
                }
              },
              "deviceId": "${id}"
            }`;
          const md52 = import_crypto.default.createHash("md5").update(body2).digest("base64");
          this.log.debug(md52);
          const content2 = md52 + "\n9999999999\nfee66616-58dd-4bcb-be79-fe092d800a21\n/api/v2/common/passthrough";
          const signature2 = import_crypto.default.createHmac("sha1", this.secret).update(content2).digest("hex");
          await this.requestClient({
            method: "post",
            url: `https://n-euw1-wap-gw.tplinkcloud.com/api/v2/common/passthrough?token=${this.session.token}&termID=${this.termId}&appVer=2.8.21&locale=de_DE&appName=TP-Link_Tapo_iOS&netType=wifi&model=iPhone10%2C5&termName=iPhone&termMeta=3&brand=TPLINK&ospf=iOS%2014.8`,
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
            var _a2, _b2, _c, _d, _e, _f;
            this.log.debug(JSON.stringify(res2.data));
            let result = {};
            if (res2.data.error_code) {
              this.log.error(JSON.stringify(res2.data));
            } else {
              result = (_f = (_e = (_d = (_c = (_b2 = (_a2 = res2.data.result) == null ? void 0 : _a2.responseData) == null ? void 0 : _b2.result) == null ? void 0 : _c.responses[0]) == null ? void 0 : _d.result) == null ? void 0 : _e.network) == null ? void 0 : _f.wan;
              result.ip = result.ipaddr;
              this.log.info(`Device ${id} has IP ${result.ip}`);
              delete result[".name"];
              delete result[".type"];
              this.devices[id] = { ...this.devices[id], ...result };
            }
          }).catch((error) => {
            this.log.warn(error);
            error.response && this.log.error(JSON.stringify(error.response.data));
          });
        }
        if (!this.devices[id].ip) {
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
        this.json2iob.parse(id, this.devices[id]);
        if (this.devices[id].ip) {
          const initResult = await this.initDevice(id).then(() => {
            this.log.info(`Initialized ${id}`);
          }).catch((e) => {
            this.log.error((e == null ? void 0 : e.message) || e || "initDevice failed");
          });
          this.log.debug(`initResult  camera ${id} ${JSON.stringify(initResult)}`);
        }
      }
    }).catch((error) => {
      this.log.warn(error);
      error.response && this.log.error(JSON.stringify(error.response.data));
    });
    await this.setObjectNotExistsAsync("deviceList", {
      type: "state",
      common: {
        name: "Cached device list",
        write: false,
        read: true,
        type: "string",
        role: "json"
      },
      native: {}
    });
    await this.setStateAsync("deviceList", JSON.stringify(this.devices), true);
  }
  async initDevice(id) {
    var _a, _b, _c, _d, _e, _f;
    const device = this.devices[id];
    if (!device.ip) {
      this.log.warn(`No IP found for ${id}`);
      return;
    }
    this.log.info(`Init device ${id} type ${device.deviceName} with ip ${device.ip}`);
    let port;
    let useHttps;
    let discovery = null;
    try {
      this.log.debug(`UDP discovery for ${device.ip} on port 20002`);
      discovery = await (0, import_udpDiscovery.discoverDevice)(device.ip, 3e3);
      if (discovery) {
        port = discovery.http_port;
        useHttps = discovery.https;
        this.log.info(
          `UDP discovery for ${device.ip}: port=${port} https=${useHttps} encrypt=${discovery.encrypt_type} lv=${discovery.login_version} mac=${discovery.mac}`
        );
      } else {
        this.log.debug(`UDP discovery for ${device.ip}: no response (will use default port 80)`);
      }
    } catch (e) {
      this.log.debug(`UDP discovery failed for ${device.ip}: ${(e == null ? void 0 : e.message) || e}`);
    }
    let deviceObject;
    if (device.deviceName === "P100") {
      deviceObject = new import_p100.default(this.log, device.ip, this.config.username, this.config.password, 2, port, useHttps);
    } else if (device.deviceName.startsWith("P110") || device.deviceName.startsWith("P115")) {
      deviceObject = new import_p110.default(this.log, device.ip, this.config.username, this.config.password, 2, port, useHttps);
    } else if (device.deviceName === "L530" || device.deviceName.startsWith("L630")) {
      deviceObject = new import_l530.default(this.log, device.ip, this.config.username, this.config.password, 2, port, useHttps);
    } else if (device.deviceName === "L510E") {
      deviceObject = new import_l510e.default(this.log, device.ip, this.config.username, this.config.password, 2, port, useHttps);
    } else if (device.deviceName === "L520E") {
      deviceObject = new import_l520e.default(this.log, device.ip, this.config.username, this.config.password, 2, port, useHttps);
    } else if (device.deviceName.startsWith("L") || device.deviceName.startsWith("KL")) {
      deviceObject = new import_l510e.default(this.log, device.ip, this.config.username, this.config.password, 2, port, useHttps);
    } else if (((_a = device.deviceType) == null ? void 0 : _a.includes("CAMERA")) || ((_b = device.deviceType) == null ? void 0 : _b.includes("DOORBELL")) || device.deviceName.startsWith("C") || device.deviceName.startsWith("TC")) {
      if (device.deviceName.startsWith("C4") && !this.config.enableBatteryDevices) {
        this.log.warn("Battery device found but ignored. Please enable in settings and check regularly the battery status");
        return;
      }
      if (!this.config.streamusername || !this.config.streampassword) {
        this.log.warn(`No stream username or password. No motion detection available`);
      }
      deviceObject = new import_tapoCamera.TAPOCamera(this.log, {
        name: device.deviceName,
        ipAddress: device.ip,
        password: this.config.password,
        streamUser: this.config.streamusername || "",
        streamPassword: this.config.streampassword || "",
        disableStreaming: true,
        loginVersion: discovery == null ? void 0 : discovery.login_version,
        port,
        useHttps,
        encryptType: discovery == null ? void 0 : discovery.encrypt_type,
        tpapPreferred: discovery == null ? void 0 : discovery.tpap_preferred,
        pake: discovery == null ? void 0 : discovery.pake,
        userHashType: discovery == null ? void 0 : discovery.user_hash_type,
        tpapPort: discovery == null ? void 0 : discovery.tpap_port,
        tpapTls: discovery == null ? void 0 : discovery.tpap_tls,
        mac: discovery == null ? void 0 : discovery.mac
      });
      this.deviceObjects[id] = deviceObject;
      const deviceInfo = await deviceObject.getDeviceInfo(true);
      this.log.info(`${id} Received device info ${JSON.stringify(deviceInfo)}`);
      this.log.debug(JSON.stringify(deviceInfo));
      this.json2iob.parse(id, deviceInfo);
      this.log.debug(`Init event emitter for ${id}`);
      try {
        const eventEmitter = await deviceObject.getEventEmitter();
        await this.setObjectNotExistsAsync(id + ".motionEvent", {
          type: "state",
          common: {
            name: "Motion detected",
            type: "boolean",
            role: "boolean",
            def: false,
            write: false,
            read: true
          },
          native: {}
        });
        this.log.debug('Init event listener for "motion"');
        eventEmitter.addListener("motion", async (motionDetected) => {
          await this.setStateAsync(id + ".motionEvent", motionDetected, true);
          this.log.debug(`[${device.deviceName}] "Motion detected" ${motionDetected}`);
        });
      } catch (e) {
        const msg = (e == null ? void 0 : e.message) || String(e);
        if (msg.includes("ECONNREFUSED")) {
          this.log.info(`ONVIF port 2020 not reachable for ${device.ip}. Enable ONVIF in the Tapo app under camera settings to use motion events.`);
        } else {
          this.log.debug(`ONVIF event emitter failed for ${device.ip}: ${msg}`);
        }
      }
      const isDoorbell = ((_c = device.deviceType) == null ? void 0 : _c.includes("DOORBELL")) || ((_d = device.deviceType) == null ? void 0 : _d.includes("CAMERA")) && ((_e = device.deviceName) == null ? void 0 : _e.startsWith("D")) || String((deviceInfo == null ? void 0 : deviceInfo.model) || "").toUpperCase().startsWith("D");
      if (isDoorbell) {
        await this.setObjectNotExistsAsync(id + ".ringEvent", {
          type: "state",
          common: {
            name: "Doorbell ring",
            type: "boolean",
            role: "sensor",
            def: false,
            write: false,
            read: true
          },
          native: {}
        });
        this.deviceObjects[id].isDoorbell = true;
        import_doorbellMonitor.DoorbellMonitor.register(this.log, device.ip, () => this.fireRingEvent(id));
        this.log.debug(`Doorbell ring detection enabled for ${id} (${device.ip})`);
      }
      return;
    } else if (((_f = device.deviceType) == null ? void 0 : _f.includes("CHIME")) || device.deviceName.startsWith("D100")) {
      deviceObject = new import_d100c.default(this.log, device.ip, this.config.username, this.config.password, 2, port, useHttps);
    } else {
      this.log.info(`Unknown device type ${device.deviceName} init as P100`);
      deviceObject = new import_p100.default(this.log, device.ip, this.config.username, this.config.password, 2, port, useHttps);
    }
    this.deviceObjects[id] = deviceObject;
    try {
      await deviceObject.handshake();
      if (deviceObject.is_klap) {
        this.log.debug("Detected KLAP device");
        try {
          await deviceObject.handshake_new();
        } catch (error) {
          this.log.info("KLAP Handshake failed, trying TPAP/SPAKE2+");
          this.log.debug((error == null ? void 0 : error.message) || error);
          try {
            await deviceObject.handshake_tpap();
            this.log.info("TPAP handshake successful for " + device.ip);
          } catch (tpapError) {
            this.log.debug("TPAP also failed: " + ((tpapError == null ? void 0 : tpapError.message) || tpapError));
            this.log.info("KLAP and TPAP Handshake failed for " + device.ip + ". Try old handshake");
            deviceObject.is_klap = false;
            deviceObject.is_tpap = false;
            try {
              await deviceObject.reAuthenticate();
            } catch {
              this.log.info("All handshakes failed for " + device.ip + ". Will retry on next poll.");
              await this.setDeviceConnected(id, false);
              return;
            }
          }
        }
      } else {
        try {
          await deviceObject.login();
        } catch {
          this.log.info("Login failed for " + device.ip + ". Will retry on next poll.");
          await this.setDeviceConnected(id, false);
          return;
        }
      }
    } catch {
      this.log.info("Device " + device.ip + " not reachable. Will retry on next poll.");
      await this.setDeviceConnected(id, false);
      return;
    }
    try {
      const sysInfo = await deviceObject.getDeviceInfo(true);
      if (!sysInfo || sysInfo.request) {
        this.log.error("Malformed response sysinfo");
        this.log.error(JSON.stringify(sysInfo));
        return;
      }
      this.json2iob.parse(id, sysInfo);
      await this.setDeviceConnected(id, true);
      if (this.deviceObjects[id].getEnergyUsage) {
        this.log.debug("Receive energy usage");
        const energyUsage = await this.deviceObjects[id].getEnergyUsage();
        this.log.debug(JSON.stringify(energyUsage));
        this.json2iob.parse(id, energyUsage);
      }
      const childList = await this.deviceObjects[id].getChildDevices();
      this.log.debug("Childlist: " + JSON.stringify(childList));
      if (childList && childList.error_code === 0) {
        this.json2iob.parse(id + ".childlist", childList);
      }
    } catch (error) {
      this.log.debug("Get Device Info failed for " + device.ip + ": " + ((error == null ? void 0 : error.message) || error));
      await this.setDeviceConnected(id, false);
    }
  }
  ringTimeouts = {};
  /** Pulse the doorbell ringEvent state: set true, then auto-reset to false after 2s. */
  fireRingEvent(id) {
    this.log.debug(`Doorbell ring for ${id}`);
    this.setState(id + ".ringEvent", true, true);
    if (this.ringTimeouts[id]) {
      clearTimeout(this.ringTimeouts[id]);
    }
    this.ringTimeouts[id] = setTimeout(() => {
      this.setState(id + ".ringEvent", false, true);
      delete this.ringTimeouts[id];
    }, 2e3);
  }
  async updateDevices() {
    var _a, _b;
    try {
      for (const deviceId in this.deviceObjects) {
        if (this.deviceObjects[deviceId].getStatus) {
          this.log.debug("Receive camera status");
          const status = await this.deviceObjects[deviceId].getStatus().catch((error) => {
            this.log.debug("Get camera Status failed: " + ((error == null ? void 0 : error.message) || error));
          });
          this.log.debug(JSON.stringify(status));
          if (status && Object.values(status).some((v) => v !== void 0)) {
            this.json2iob.parse(deviceId, status);
            if (!this.deviceObjects[deviceId]._connected) {
              this.log.info("Reconnected to " + this.deviceObjects[deviceId].ip);
            }
            this.deviceObjects[deviceId]._connected = true;
            this.setState(deviceId + ".connected", true, true);
          } else {
            if (this.deviceObjects[deviceId]._connected) {
              this.log.info("Connection lost to " + this.deviceObjects[deviceId].ip);
            }
            this.deviceObjects[deviceId]._connected = false;
            this.setState(deviceId + ".connected", false, true);
            continue;
          }
          const events = await this.deviceObjects[deviceId].getDetectionEvents().catch((e) => {
            this.log.debug("getDetectionEvents not supported: " + ((e == null ? void 0 : e.message) || e));
          });
          if (events && events.length > 0) {
            const now = Math.floor(Date.now() / 1e3);
            const lastEvent = events[events.length - 1];
            const active = now - (lastEvent.end_time || lastEvent.start_time) < 30;
            const reversed = [...events].reverse();
            await this.json2iob.parse(deviceId + ".detection", {
              active,
              eventCount: events.length,
              events: reversed
            });
          } else if (events) {
            await this.json2iob.parse(deviceId + ".detection", {
              active: false,
              eventCount: 0
            });
          }
          const alarmInfo = await this.deviceObjects[deviceId].getLastAlarmInfo().catch((e) => {
            this.log.debug("getLastAlarmInfo not supported: " + ((e == null ? void 0 : e.message) || e));
          });
          if (alarmInfo) {
            await this.json2iob.parse(deviceId + ".alarmInfo", alarmInfo);
            if (this.deviceObjects[deviceId].isDoorbell) {
              const at = String((_a = alarmInfo.alarm_type) != null ? _a : "").toLowerCase();
              const dbgKey = deviceId + "_lastAlarm";
              const marker = JSON.stringify({ at, t: (_b = alarmInfo.start_time) != null ? _b : alarmInfo.alarm_time });
              if ((at.includes("doorbell") || at.includes("button") || at.includes("ring")) && this[dbgKey] !== marker) {
                this[dbgKey] = marker;
                this.fireRingEvent(deviceId);
              }
            }
          }
          const alertTypes = await this.deviceObjects[deviceId].getAlertEventType().catch((e) => {
            this.log.debug("getAlertEventType not supported: " + ((e == null ? void 0 : e.message) || e));
          });
          if (alertTypes && alertTypes.length > 0) {
            const alertObj = {};
            for (const alertType of alertTypes) {
              if (alertType.name) {
                alertObj[alertType.name] = alertType.enabled === "on";
              }
            }
            await this.json2iob.parse(deviceId + ".alertEventTypes", alertObj);
          }
          if (this.deviceObjects[deviceId].stok === void 0) {
            if (this.firstStart) {
              this.log.error("No stok found for: " + deviceId + " Ignore and remove the device until next restart");
              delete this.deviceObjects[deviceId];
            } else {
              this.log.info(
                "No stok found for: " + deviceId + " this means the device is offline or connection lost. No update or commands possible"
              );
              this.deviceObjects[deviceId]._connected = false;
              this.setState(deviceId + ".connected", false, true);
            }
          }
          continue;
        }
        if (!this.deviceObjects[deviceId]._connected) {
          this.log.debug("Device " + deviceId + " not connected, trying reconnect...");
          try {
            await this.deviceObjects[deviceId].reAuthenticate();
          } catch {
            this.log.debug("Reconnect failed for " + this.deviceObjects[deviceId].ip);
            continue;
          }
        }
        this.deviceObjects[deviceId].getDeviceInfo(true).then(async (sysInfo) => {
          this.log.debug(JSON.stringify(sysInfo));
          if (!sysInfo || sysInfo.name === "Error" || sysInfo.request) {
            this.log.debug("Malformed response sysinfo");
            return;
          }
          if (!this.deviceObjects[deviceId]._connected) {
            this.log.info("Reconnected to " + this.deviceObjects[deviceId].ip);
          }
          this.deviceObjects[deviceId]._connected = true;
          await this.setState(deviceId + ".connected", true, true);
          await this.json2iob.parse(deviceId, sysInfo);
          if (this.deviceObjects[deviceId].getEnergyUsage) {
            this.log.debug("Receive energy usage");
            const energyUsage = await this.deviceObjects[deviceId].getEnergyUsage();
            this.log.debug(JSON.stringify(energyUsage));
            if (energyUsage.request) {
              this.log.error("Malformed response getEnergyUsage");
              this.log.error(JSON.stringify(energyUsage));
              return;
            }
            await this.json2iob.parse(deviceId, energyUsage);
            const power_usage = this.deviceObjects[deviceId].getPowerConsumption();
            if (power_usage.request) {
              this.log.error("Malformed response getPowerConsumption");
              this.log.error(JSON.stringify(power_usage));
              return;
            }
            await this.json2iob.parse(deviceId, power_usage);
            if (this.deviceObjects[deviceId].getEmeterData) {
              const emeterData = await this.deviceObjects[deviceId].getEmeterData().catch((e) => {
                this.log.debug("get_emeter_data not supported: " + ((e == null ? void 0 : e.message) || e));
              });
              if (emeterData && !emeterData.request) {
                await this.json2iob.parse(deviceId, emeterData);
              }
            }
          }
        }).catch((error) => {
          this.log.debug(`Get Device Info failed for ${deviceId} - ${error}`);
          if (this.deviceObjects[deviceId]._connected) {
            this.log.info("Connection lost to " + this.deviceObjects[deviceId].ip);
          }
          this.deviceObjects[deviceId]._connected = false;
          this.setState(deviceId + ".connected", false, true);
        });
      }
      this.log.debug("Update done");
    } catch (error) {
      this.log.warn(error);
    }
  }
  async setDeviceConnected(deviceId, connected) {
    this.deviceObjects[deviceId]._connected = connected;
    await this.setState(deviceId + ".connected", connected, true);
  }
  isBase64(str) {
    if (str === "" || str.trim() === "") {
      return false;
    }
    try {
      const strWithoutPadding = str.replace(/=*$/, "");
      return btoa(atob(strWithoutPadding)) === strWithoutPadding || btoa(atob(str)) === str;
    } catch (err) {
      return false;
    }
  }
  async sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
  async refreshToken() {
    this.log.debug("Refresh token");
  }
  /**
   * Is called when adapter shuts down - callback has to be called under any circumstances!
   */
  onUnload(callback) {
    try {
      this.setState("info.connection", false, true);
      this.refreshTimeout && clearTimeout(this.refreshTimeout);
      this.reLoginTimeout && clearTimeout(this.reLoginTimeout);
      this.refreshTokenTimeout && clearTimeout(this.refreshTokenTimeout);
      this.updateInterval && clearInterval(this.updateInterval);
      this.refreshTokenInterval && clearInterval(this.refreshTokenInterval);
      import_doorbellMonitor.DoorbellMonitor.closeAll();
      for (const t of Object.values(this.ringTimeouts)) {
        clearTimeout(t);
      }
      callback();
    } catch (e) {
      callback();
    }
  }
  /**
   * Is called if a subscribed state changes
   */
  async onStateChange(id, state) {
    if (state) {
      if (!state.ack) {
        const deviceId = id.split(".")[2];
        const command = id.split(".")[4];
        if (id.split(".")[3] !== "remote") {
          return;
        }
        if (command === "refresh") {
          if (this.deviceObjects[deviceId].getStatus) {
            this.deviceObjects[deviceId].getStatus().then((status) => {
              this.log.debug(JSON.stringify(status));
              this.json2iob.parse(deviceId, status);
            }).catch((error) => {
              this.log.debug(`Get camera status failed for ${deviceId} - ${error}`);
            });
          } else {
            this.deviceObjects[deviceId].getDeviceInfo(true).then((sysInfo) => {
              this.log.debug(JSON.stringify(sysInfo));
              this.json2iob.parse(deviceId, sysInfo);
            }).catch((error) => {
              this.log.debug(`Get Device Info failed for ${deviceId} - ${error}`);
              if (this.deviceObjects[deviceId]._connected) {
                this.log.info("Connection lost to " + this.deviceObjects[deviceId].ip);
              }
              this.deviceObjects[deviceId]._connected = false;
              this.setState(deviceId + ".connected", false, true);
            });
          }
          return;
        }
        try {
          const cameraCommands = {
            setAlertConfig: "alarm",
            setLensMaskConfig: "eyes",
            setLedStatus: "led",
            setMsgPushConfig: "notifications",
            setDetectionConfig: "motionDetection",
            setAutoTrackTarget: "autoTrack",
            setPersonDetection: "personDetection",
            setVehicleDetection: "vehicleDetection",
            setPetDetection: "petDetection",
            setBabyCryDetection: "babyCryDetection",
            setBarkDetection: "barkDetection",
            setMeowDetection: "meowDetection",
            setGlassBreakDetection: "glassBreakDetection",
            setTamperDetection: "tamperDetection",
            setImageFlipVertical: "imageFlip",
            setLensDistortionCorrection: "ldc",
            setRecordAudio: "recordAudio",
            setAutoUpgrade: "autoUpgrade"
          };
          if (this.deviceObjects[deviceId] && (this.deviceObjects[deviceId][command] || cameraCommands[command])) {
            let result;
            if (cameraCommands[command]) {
              result = await this.deviceObjects[deviceId].setStatus(cameraCommands[command], state.val);
            } else if (command === "setColor" || command === "moveMotor" || command === "setPowerStateChild") {
              const valueSplit = String(state.val).replace(" ", "").split(",");
              result = await this.deviceObjects[deviceId][command](valueSplit[0], valueSplit[1]);
            } else {
              result = await this.deviceObjects[deviceId][command](state.val);
            }
            this.log.info(
              command + " was set to : " + state.val + " for device " + deviceId + " was successful: " + JSON.stringify(result)
            );
            this.refreshTimeout && clearTimeout(this.refreshTimeout);
            this.refreshTimeout = setTimeout(async () => {
              this.updateDevices();
            }, 2 * 1e3);
          } else {
            if (this.deviceObjects[deviceId]) {
              this.log.error(`Device ${deviceId} has no command ${command}`);
            } else {
              this.log.error(`Device ${deviceId} not found`);
            }
          }
        } catch (error) {
          this.log.error(error);
        }
      } else {
        const resultDict = {
          device_on: "setPowerState",
          eyes: "setLensMaskConfig",
          alarm: "setAlertConfig",
          led: "setLedStatus",
          notifications: "setMsgPushConfig",
          motionDetection: "setDetectionConfig",
          autoTrack: "setAutoTrackTarget",
          personDetection: "setPersonDetection",
          vehicleDetection: "setVehicleDetection",
          petDetection: "setPetDetection",
          babyCryDetection: "setBabyCryDetection",
          barkDetection: "setBarkDetection",
          meowDetection: "setMeowDetection",
          glassBreakDetection: "setGlassBreakDetection",
          tamperDetection: "setTamperDetection",
          imageFlip: "setImageFlipVertical",
          ldc: "setLensDistortionCorrection",
          recordAudio: "setRecordAudio",
          autoUpgrade: "setAutoUpgrade"
        };
        const idArray = id.split(".");
        const stateName = idArray[idArray.length - 1];
        const deviceId = id.split(".")[2];
        if (resultDict[stateName]) {
          const remoteState = deviceId + ".remote." + resultDict[stateName];
          const val = typeof state.val === "string" ? state.val === "true" || state.val === "on" : state.val;
          await this.setState(remoteState, val, true);
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
