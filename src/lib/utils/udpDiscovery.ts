import dgram from 'dgram';
import crypto from 'crypto';

const DISCOVERY_PORT = 20002;
const HEADER_SIZE = 16;

export interface DiscoveryResult {
  ip: string;
  device_id?: string;
  device_type?: string;
  device_model?: string;
  mac?: string;
  http_port: number;
  https: boolean;
  encrypt_type?: string;
  login_version?: number;
  raw: any;
}

function buildDiscoveryQuery(): Buffer {
  const { publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const payload = Buffer.from(JSON.stringify({ params: { rsa_key: publicKey } }), 'utf8');
  const secret = crypto.randomBytes(4);
  const deviceSerial = secret.readUInt32BE(0);

  const header = Buffer.alloc(HEADER_SIZE);
  header.writeUInt8(2, 0);
  header.writeUInt8(0, 1);
  header.writeUInt16BE(1, 2);
  header.writeUInt16BE(payload.length, 4);
  header.writeUInt8(17, 6);
  header.writeUInt8(0, 7);
  header.writeUInt32BE(deviceSerial, 8);
  header.writeUInt32BE(0x5a6b7c8d, 12);

  const packet = Buffer.concat([header, payload]);
  const crc = crc32(packet);
  packet.writeUInt32BE(crc, 12);
  return packet;
}

const CRC_TABLE: number[] = (() => {
  const t: number[] = [];
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf: Buffer): number {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

export async function discoverDevice(ip: string, timeout = 3000): Promise<DiscoveryResult | null> {
  return new Promise((resolve) => {
    const socket = dgram.createSocket('udp4');
    let resolved = false;

    const finish = (result: DiscoveryResult | null): void => {
      if (resolved) return;
      resolved = true;
      try {
        socket.close();
      } catch {
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
        if (msg.length < HEADER_SIZE) return finish(null);
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
      } catch {
        finish(null);
      }
    });

    try {
      const query = buildDiscoveryQuery();
      socket.send(query, DISCOVERY_PORT, ip, (err) => {
        if (err) {
          clearTimeout(timer);
          finish(null);
        }
      });
    } catch {
      clearTimeout(timer);
      finish(null);
    }
  });
}
