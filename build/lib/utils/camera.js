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
var camera_exports = {};
__export(camera_exports, {
  default: () => camera
});
module.exports = __toCommonJS(camera_exports);
var import_p100 = __toESM(require("./p100"));
class camera extends import_p100.default {
  constructor(log, ipAddress, email, password, timeout) {
    super(log, ipAddress, email, password, timeout);
    this.log = log;
    this.ipAddress = ipAddress;
    this.email = email;
    this.password = password;
    this.timeout = timeout;
    this.log.debug("Constructing Camera on host: " + ipAddress);
  }
  async getDeviceInfo() {
    return super.getDeviceInfo().then(() => {
      return this.getSysInfo();
    });
  }
  async setAlertConfig(enabled) {
    const enabledString = enabled ? "on" : "off";
    const payload = `{
      "method": "multipleRequest",
      "params": {
        "requests": [
          {
      "method": "setAlertConfig",
      "params": {
        "msg_alarm": {
          "chn1_msg_alarm_info": {
            "alarm_type": "0",
            "alarm_mode": ["sound"],
            "enabled": "${enabledString}",
            "light_type": "1"
          }
        },
        "requestTimeMils": ${Math.round(Date.now() * 1e3)}
      }
    }]}}`;
    return this.sendRequest(payload);
  }
  async setLensMaskConfig(enabled) {
    const enabledString = enabled ? "on" : "off";
    const payload = `{
      "method": "multipleRequest",
      "params": {
        "requests": [
          {
      "method": "setLensMaskConfig",
      "params": {
        "lens_mask": {
          "lens_mask_info": {
            "enabled": "${enabledString}"
          }
        },
        "requestTimeMils": ${Math.round(Date.now() * 1e3)}
      }
    }]}}`;
    return this.sendRequest(payload);
  }
  setSysInfo(sysInfo) {
    this._lightSysInfo = sysInfo;
    this._lightSysInfo.last_update = Date.now();
  }
  getSysInfo() {
    return this._lightSysInfo;
  }
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {});
//# sourceMappingURL=camera.js.map
