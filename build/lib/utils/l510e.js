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
var l510e_exports = {};
__export(l510e_exports, {
  default: () => L510E
});
module.exports = __toCommonJS(l510e_exports);
var import_p100 = __toESM(require("./p100.js"));
class L510E extends import_p100.default {
  constructor(log, ipAddress, email, password, timeout, port, useHttps) {
    super(log, ipAddress, email, password, timeout, port, useHttps);
    this.log = log;
    this.ipAddress = ipAddress;
    this.email = email;
    this.password = password;
    this.timeout = timeout;
    this.log.debug("Constructing L510E on host: " + ipAddress);
  }
  _lightSysInfo;
  async getDeviceInfo(force) {
    return super.getDeviceInfo(force).then(() => {
      return this.getSysInfo();
    });
  }
  async setBrightness(brightness) {
    const payload = '{"method": "set_device_info","params": {"brightness": ' + brightness + '},"requestTimeMils": ' + Math.round(Date.now() * 1e3) + "};";
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
//# sourceMappingURL=l510e.js.map
