"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
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
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var onvifCamera_exports = {};
__export(onvifCamera_exports, {
  OnvifCamera: () => OnvifCamera
});
module.exports = __toCommonJS(onvifCamera_exports);
var import_onvif = require("onvif");
var import_stream = require("stream");
class OnvifCamera {
  constructor(log, config) {
    this.log = log;
    this.config = config;
    this.kOnvifPort = 2020;
  }
  async getDevice() {
    return new Promise((resolve, reject) => {
      if (this.device) {
        return resolve(this.device);
      }
      this.log.debug("Connecting to ONVIF device" + JSON.stringify(this.config) + " on port " + this.kOnvifPort);
      const device = new import_onvif.Cam(
        {
          hostname: this.config.ipAddress,
          username: this.config.streamUser,
          password: this.config.streamPassword,
          port: this.kOnvifPort
        },
        (err) => {
          if (err) {
            return reject(err);
          }
          this.device = device;
          return resolve(this.device);
        }
      );
    });
  }
  async getEventEmitter() {
    if (this.events) {
      return this.events;
    }
    this.log.debug("Getting device for event emiiter");
    const onvifDevice = await this.getDevice();
    this.log.debug("Got device for event emiiter" + JSON.stringify(onvifDevice));
    let lastMotionValue = false;
    this.log.debug("Creating event emitter");
    this.events = new import_stream.EventEmitter();
    this.log.debug(`[${this.config.name}]`, "Starting ONVIF listener");
    onvifDevice.on("event", (event) => {
      var _a, _b;
      this.log.debug(`Received event: ${JSON.stringify(event)}`);
      if ((_b = (_a = event == null ? void 0 : event.topic) == null ? void 0 : _a._) == null ? void 0 : _b.match(/RuleEngine\/CellMotionDetector\/Motion$/)) {
        const motion = event.message.message.data.simpleItem.$.Value;
        if (motion !== lastMotionValue) {
          lastMotionValue = motion;
          this.events = this.events || new import_stream.EventEmitter();
          this.events.emit("motion", motion);
        }
      }
    });
    return this.events;
  }
  async getVideoSource() {
    const onvifDevice = await this.getDevice();
    return onvifDevice.videoSources[0];
  }
  async getDeviceInfo() {
    const onvifDevice = await this.getDevice();
    return new Promise((resolve, reject) => {
      this.log.debug("Getting device information ");
      onvifDevice.getDeviceInformation((err, deviceInformation) => {
        this.log.debug("Got device information for " + JSON.stringify(deviceInformation));
        if (err)
          return reject(err);
        resolve(deviceInformation);
      });
    });
  }
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  OnvifCamera
});
//# sourceMappingURL=onvifCamera.js.map
