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
var p110_exports = {};
__export(p110_exports, {
  default: () => P110
});
module.exports = __toCommonJS(p110_exports);
var import_p100 = __toESM(require("./p100"));
class P110 extends import_p100.default {
  constructor(log, ipAddress, email, password, timeout, port, useHttps) {
    super(log, ipAddress, email, password, timeout, port, useHttps);
    this.log = log;
    this.ipAddress = ipAddress;
    this.email = email;
    this.password = password;
    this.timeout = timeout;
    this.log.info("Constructing P110 on host: " + ipAddress);
  }
  _consumption;
  async getEnergyUsage() {
    const response = await this.sendCommand("get_energy_usage");
    if (response && response.current_power !== void 0) {
      this._consumption = {
        current: Math.ceil(response.current_power / 1e3),
        total: response.today_energy / 1e3
      };
    } else {
      this._consumption = {
        current: 0,
        total: 0
      };
    }
    return response;
  }
  getPowerConsumption() {
    return this._consumption;
  }
}
//# sourceMappingURL=p110.js.map
