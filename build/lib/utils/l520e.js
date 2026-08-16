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
var l520e_exports = {};
__export(l520e_exports, {
  default: () => L520E
});
module.exports = __toCommonJS(l520e_exports);
var import_l510e = __toESM(require("./l510e"));
class L520E extends import_l510e.default {
  constructor(log, ipAddress, email, password, timeout, port, useHttps) {
    super(log, ipAddress, email, password, timeout, port, useHttps);
    this.log = log;
    this.ipAddress = ipAddress;
    this.email = email;
    this.password = password;
    this.timeout = timeout;
    this.log.debug("Constructing L510E on host: " + ipAddress);
  }
  _colorTempSysInfo;
  async getDeviceInfo(force) {
    return super.getDeviceInfo(force).then(() => {
      return this.getSysInfo();
    });
  }
  async setColorTemp(color_temp) {
    const roundedValue = color_temp > 6500 ? 6500 : color_temp < 2500 ? 2500 : Math.round(color_temp);
    this.log.debug("Color Temp Tapo (Kelvin): " + roundedValue);
    const payload = '{"method": "set_device_info","params": {"color_temp": ' + roundedValue + '},"requestTimeMils": ' + Math.round(Date.now() * 1e3) + "};";
    return this.sendRequest(payload);
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
  setSysInfo(sysInfo) {
    this._colorTempSysInfo = sysInfo;
    this._colorTempSysInfo.last_update = Date.now();
  }
  getSysInfo() {
    return this._colorTempSysInfo;
  }
}
//# sourceMappingURL=l520e.js.map
