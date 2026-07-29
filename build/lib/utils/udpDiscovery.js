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
var udpDiscovery_exports = {};
__export(udpDiscovery_exports, {
  discoverDevice: () => discoverDevice
});
module.exports = __toCommonJS(udpDiscovery_exports);
var import_dgram = __toESM(require("dgram"));
var import_crypto = __toESM(require("crypto"));
const DISCOVERY_PORT = 20002;
const HEADER_SIZE = 16;
const RETRY_COUNT = 8;
const RETRY_INTERVAL_MS = 300;
function buildDiscoveryQuery() {
  const { publicKey } = import_crypto.default.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" }
  });
  const payload = Buffer.from(JSON.stringify({ params: { rsa_key: publicKey } }), "utf8");
  const secret = import_crypto.default.randomBytes(4);
  const deviceSerial = secret.readUInt32BE(0);
  const header = Buffer.alloc(HEADER_SIZE);
  header.writeUInt8(2, 0);
  header.writeUInt8(0, 1);
  header.writeUInt16BE(1, 2);
  header.writeUInt16BE(payload.length, 4);
  header.writeUInt8(33, 6);
  header.writeUInt8(0, 7);
  header.writeUInt32BE(deviceSerial, 8);
  header.writeUInt32BE(1516993677, 12);
  const packet = Buffer.concat([header, payload]);
  const crc = crc32(packet);
  packet.writeUInt32BE(crc, 12);
  return packet;
}
const CRC_TABLE = (() => {
  const t = [];
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 3988292384 ^ c >>> 1 : c >>> 1;
    }
    t[n] = c >>> 0;
  }
  return t;
})();
function crc32(buf) {
  let c = 4294967295;
  for (let i = 0; i < buf.length; i++) {
    c = CRC_TABLE[(c ^ buf[i]) & 255] ^ c >>> 8;
  }
  return (c ^ 4294967295) >>> 0;
}
async function discoverDevice(ip, timeout = 3e3) {
  return new Promise((resolve) => {
    const socket = import_dgram.default.createSocket("udp4");
    let resolved = false;
    let retryTimer = null;
    const finish = (result) => {
      if (resolved) return;
      resolved = true;
      if (retryTimer) clearInterval(retryTimer);
      try {
        socket.close();
      } catch {
      }
      resolve(result);
    };
    const timer = setTimeout(() => finish(null), timeout);
    socket.on("error", () => {
      clearTimeout(timer);
      finish(null);
    });
    socket.on("message", (msg) => {
      clearTimeout(timer);
      try {
        if (msg.length < HEADER_SIZE) return finish(null);
        const json = JSON.parse(msg.slice(HEADER_SIZE).toString("utf8"));
        const result = json.result || {};
        const schm = result.mgt_encrypt_schm || {};
        const tpap = result.tpap || {};
        finish({
          ip,
          device_id: result.device_id,
          device_type: result.device_type,
          device_model: result.device_model,
          mac: result.mac,
          http_port: schm.http_port || 80,
          https: !!schm.is_support_https,
          encrypt_type: schm.encrypt_type,
          login_version: schm.lv,
          tpap_preferred: !!result.tpap_preferred,
          pake: Array.isArray(tpap.pake) ? tpap.pake : void 0,
          user_hash_type: tpap.user_hash_type,
          tpap_port: tpap.port,
          tpap_tls: tpap.tls,
          raw: result
        });
      } catch {
        finish(null);
      }
    });
    const sendOne = () => {
      if (resolved) return;
      try {
        const query = buildDiscoveryQuery();
        socket.send(query, DISCOVERY_PORT, ip, (err) => {
          if (err && !resolved) {
            clearTimeout(timer);
            finish(null);
          }
        });
      } catch {
        clearTimeout(timer);
        finish(null);
      }
    };
    sendOne();
    let sentCount = 1;
    retryTimer = setInterval(() => {
      if (resolved || sentCount >= RETRY_COUNT) {
        if (retryTimer) clearInterval(retryTimer);
        return;
      }
      sentCount++;
      sendOne();
    }, RETRY_INTERVAL_MS);
  });
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  discoverDevice
});
//# sourceMappingURL=udpDiscovery.js.map
