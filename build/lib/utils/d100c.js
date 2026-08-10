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
var d100c_exports = {};
__export(d100c_exports, {
  default: () => D100C
});
module.exports = __toCommonJS(d100c_exports);
var import_p100 = __toESM(require("./p100.js"));
class D100C extends import_p100.default {
  constructor(log, ipAddress, email, password, timeout, port, useHttps) {
    super(log, ipAddress, email, password, timeout, port, useHttps);
    this.log = log;
    this.ipAddress = ipAddress;
    this.email = email;
    this.password = password;
    this.timeout = timeout;
    this.log.debug("Constructing D100C on host: " + ipAddress);
  }
  /** List of supported ring/alarm types. */
  async getSupportAlarmTypeList() {
    return this.sendCommand("get_support_alarm_type_list");
  }
  /** Play the chime. Optional ring type, volume (1-15) and duration (0 or 5-30 s). */
  async playAlarm(type, volume, duration) {
    const params = {};
    if (type !== void 0 && type !== "" && type !== true && type !== false) params.type = String(type);
    if (volume !== void 0) params.volume = String(volume);
    if (duration !== void 0) params.duration = Number(duration);
    return this.sendCommand("play_alarm", params);
  }
  /** Stop a currently playing chime. */
  async stopAlarm() {
    return this.sendCommand("stop_alarm");
  }
  /** Set the chime volume (1-15). */
  async setVolume(volume) {
    return this.sendCommand("set_volume", { volume: String(volume) });
  }
  /** Set the default ring/alarm type. */
  async setRingType(type) {
    return this.sendCommand("set_chime_alarm_configure", { type: String(type) });
  }
}
//# sourceMappingURL=d100c.js.map
