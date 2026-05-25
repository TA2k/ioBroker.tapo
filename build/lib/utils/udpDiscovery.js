"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.discoverDevice = discoverDevice;
const dgram_1 = __importDefault(require("dgram"));
const crypto_1 = __importDefault(require("crypto"));
const DISCOVERY_PORT = 20002;
const HEADER_SIZE = 16;
const RETRY_COUNT = 8;
const RETRY_INTERVAL_MS = 300;
function buildDiscoveryQuery() {
    const { publicKey } = crypto_1.default.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    const payload = Buffer.from(JSON.stringify({ params: { rsa_key: publicKey } }), 'utf8');
    const secret = crypto_1.default.randomBytes(4);
    const deviceSerial = secret.readUInt32BE(0);
    const header = Buffer.alloc(HEADER_SIZE);
    header.writeUInt8(2, 0);
    header.writeUInt8(0, 1);
    header.writeUInt16BE(1, 2);
    header.writeUInt16BE(payload.length, 4);
    header.writeUInt8(0x21, 6);
    header.writeUInt8(0, 7);
    header.writeUInt32BE(deviceSerial, 8);
    header.writeUInt32BE(0x5a6b7c8d, 12);
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
            c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
        }
        t[n] = c >>> 0;
    }
    return t;
})();
function crc32(buf) {
    let c = 0xffffffff;
    for (let i = 0; i < buf.length; i++) {
        c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
    }
    return (c ^ 0xffffffff) >>> 0;
}
async function discoverDevice(ip, timeout = 3000) {
    return new Promise((resolve) => {
        const socket = dgram_1.default.createSocket('udp4');
        let resolved = false;
        let retryTimer = null;
        const finish = (result) => {
            if (resolved)
                return;
            resolved = true;
            if (retryTimer)
                clearInterval(retryTimer);
            try {
                socket.close();
            }
            catch {
                /* ignore */
            }
            resolve(result);
        };
        const timer = setTimeout(() => finish(null), timeout);
        socket.on('error', () => {
            clearTimeout(timer);
            finish(null);
        });
        socket.on('message', (msg) => {
            clearTimeout(timer);
            try {
                if (msg.length < HEADER_SIZE)
                    return finish(null);
                const json = JSON.parse(msg.slice(HEADER_SIZE).toString('utf8'));
                const result = json.result || {};
                const schm = result.mgt_encrypt_schm || {};
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
                    raw: result,
                });
            }
            catch {
                finish(null);
            }
        });
        const sendOne = () => {
            if (resolved)
                return;
            try {
                const query = buildDiscoveryQuery();
                socket.send(query, DISCOVERY_PORT, ip, (err) => {
                    if (err && !resolved) {
                        clearTimeout(timer);
                        finish(null);
                    }
                });
            }
            catch {
                clearTimeout(timer);
                finish(null);
            }
        };
        sendOne();
        let sentCount = 1;
        retryTimer = setInterval(() => {
            if (resolved || sentCount >= RETRY_COUNT) {
                if (retryTimer)
                    clearInterval(retryTimer);
                return;
            }
            sentCount++;
            sendOne();
        }, RETRY_INTERVAL_MS);
    });
}
//# sourceMappingURL=udpDiscovery.js.map