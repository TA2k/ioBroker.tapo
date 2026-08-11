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
var doorbellMonitor_exports = {};
__export(doorbellMonitor_exports, {
  DoorbellMonitor: () => DoorbellMonitor
});
module.exports = __toCommonJS(doorbellMonitor_exports);
var import_dgram = __toESM(require("dgram"));
const DOORBELL_UDP_PORT = 20005;
class DoorbellMonitor {
  static socket = null;
  static bound = false;
  static bindFailed = false;
  static callbacks = /* @__PURE__ */ new Map();
  static log = console;
  /**
   * Register a doorbell IP with a callback fired on each ring packet.
   * The first registration binds the shared socket.
   */
  static register(log, ip, onRing) {
    DoorbellMonitor.log = log;
    DoorbellMonitor.callbacks.set(ip, onRing);
    DoorbellMonitor.ensureSocket();
  }
  /** Stop dispatching for a doorbell IP; closes the socket when none remain. */
  static unregister(ip) {
    DoorbellMonitor.callbacks.delete(ip);
    if (DoorbellMonitor.callbacks.size === 0) {
      DoorbellMonitor.closeAll();
    }
  }
  /** Close the shared socket and reset state (called on adapter unload). */
  static closeAll() {
    DoorbellMonitor.callbacks.clear();
    if (DoorbellMonitor.socket) {
      try {
        DoorbellMonitor.socket.close();
      } catch {
      }
    }
    DoorbellMonitor.socket = null;
    DoorbellMonitor.bound = false;
    DoorbellMonitor.bindFailed = false;
  }
  static ensureSocket() {
    if (DoorbellMonitor.socket || DoorbellMonitor.bindFailed) {
      return;
    }
    const socket = import_dgram.default.createSocket({ type: "udp4", reuseAddr: true });
    DoorbellMonitor.socket = socket;
    socket.on("error", (err) => {
      DoorbellMonitor.bindFailed = true;
      DoorbellMonitor.log.warn(
        `DoorbellMonitor could not use UDP port ${DOORBELL_UDP_PORT} (${(err == null ? void 0 : err.message) || err}). Doorbell ring events are disabled.`
      );
      try {
        socket.close();
      } catch {
      }
      DoorbellMonitor.socket = null;
      DoorbellMonitor.bound = false;
    });
    socket.on("message", (msg, rinfo) => {
      const cb = DoorbellMonitor.callbacks.get(rinfo.address);
      DoorbellMonitor.log.debug(
        `DoorbellMonitor: UDP packet from ${rinfo.address}:${rinfo.port} len=${msg.length} matched=${!!cb} registered=${JSON.stringify([...DoorbellMonitor.callbacks.keys()])}`
      );
      if (cb) {
        cb();
      }
    });
    socket.bind(DOORBELL_UDP_PORT, "0.0.0.0", () => {
      try {
        socket.setBroadcast(true);
      } catch {
      }
      DoorbellMonitor.bound = true;
      DoorbellMonitor.log.debug(`DoorbellMonitor listening on UDP ${DOORBELL_UDP_PORT}`);
    });
  }
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  DoorbellMonitor
});
//# sourceMappingURL=doorbellMonitor.js.map
