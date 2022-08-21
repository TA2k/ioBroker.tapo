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
var l530_exports = {};
__export(l530_exports, {
  default: () => L530
});
module.exports = __toCommonJS(l530_exports);
var import_l510e = __toESM(require("./l510e"));
class L530 extends import_l510e.default {
  constructor(log, ipAddress, email, password, timeout) {
    super(log, ipAddress, email, password, timeout);
    this.log = log;
    this.ipAddress = ipAddress;
    this.email = email;
    this.password = password;
    this.timeout = timeout;
    this.log.debug("Constructing L530 on host: " + ipAddress);
    this._consumption = {
      total: 0,
      current: 0
    };
  }
  async getDeviceInfo() {
    return super.getDeviceInfo().then(() => {
      return this.getSysInfo();
    });
  }
  async setColorTemp(color_temp) {
    const transformedColorTemp = this.transformColorTemp(color_temp);
    this.log.debug("Color Temp Tapo :" + transformedColorTemp);
    const roundedValue = transformedColorTemp > 6500 ? 6500 : transformedColorTemp < 2500 ? 2500 : transformedColorTemp;
    const payload = '{"method": "set_device_info","params": {"hue": 0,"saturation": 0,"color_temp": ' + roundedValue + '},"requestTimeMils": ' + Math.round(Date.now() * 1e3) + "};";
    return this.handleRequest(payload).then(() => {
      return true;
    });
  }
  async setColor(hue, saturation) {
    if (!hue) {
      hue = 0;
    }
    if (!saturation) {
      saturation = 0;
    }
    const payload = '{"method": "set_device_info","params": {"hue": ' + Math.round(hue) + ',"color_temp": 0,"saturation": ' + Math.round(saturation) + '},"requestTimeMils": ' + Math.round(Date.now() * 1e3) + "};";
    return this.sendRequest(payload);
  }
  setSysInfo(sysInfo) {
    this._colorLightSysInfo = sysInfo;
    this._colorLightSysInfo.last_update = Date.now();
  }
  getSysInfo() {
    return this._colorLightSysInfo;
  }
  transformColorTemp(value) {
    return Math.floor(1e6 / value);
  }
  async getColorTemp() {
    return super.getDeviceInfo().then(() => {
      return this.calculateColorTemp(this.getSysInfo().color_temp);
    });
  }
  calculateColorTemp(tapo_color_temp) {
    const newValue = this.transformColorTemp(tapo_color_temp);
    return newValue > 400 ? 400 : newValue < 154 ? 154 : newValue;
  }
  async getEnergyUsage() {
    const payload = '{"method": "get_device_usage","requestTimeMils": ' + Math.round(Date.now() * 1e3) + "};";
    return this.handleRequest(payload).then((response) => {
      if (response && response.result) {
        this._consumption = {
          total: response.result.power_usage.today / 1e3,
          current: this._consumption ? response.result.power_usage.today - this._consumption.current : 0
        };
      } else {
        this._consumption = {
          total: 0,
          current: 0
        };
      }
      return response.result;
    }).catch((error) => {
      if (error.message.indexOf("9999") > 0) {
        return this.reconnect().then(() => {
          return this.handleRequest(payload).then(() => {
            return true;
          });
        });
      }
      return false;
    });
  }
  getPowerConsumption() {
    return this._consumption;
  }
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {});
//# sourceMappingURL=l530.js.map
