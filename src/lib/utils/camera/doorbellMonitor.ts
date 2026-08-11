import dgram from 'dgram';

/**
 * Tapo video doorbells (D-series, e.g. D235) broadcast a UDP packet on port 20005
 * when the doorbell button is pressed. This monitor binds a single shared UDP socket
 * on that port and dispatches to a per-IP callback when a packet from a registered
 * doorbell arrives. The packet payload is not parsed - any packet from the device IP
 * is treated as a ring event (matches HomeAssistant-Tapo-Control behaviour).
 *
 * Port 20005 can only be bound once per host, so this is a process-wide singleton:
 * all doorbells register on the same socket.
 */
const DOORBELL_UDP_PORT = 20005;

export class DoorbellMonitor {
  private static socket: dgram.Socket | null = null;
  private static bound = false;
  private static bindFailed = false;
  private static readonly callbacks = new Map<string, () => void>();
  private static log: any = console;

  /**
   * Register a doorbell IP with a callback fired on each ring packet.
   * The first registration binds the shared socket.
   */
  static register(log: any, ip: string, onRing: () => void): void {
    DoorbellMonitor.log = log;
    DoorbellMonitor.callbacks.set(ip, onRing);
    DoorbellMonitor.ensureSocket();
  }

  /** Stop dispatching for a doorbell IP; closes the socket when none remain. */
  static unregister(ip: string): void {
    DoorbellMonitor.callbacks.delete(ip);
    if (DoorbellMonitor.callbacks.size === 0) {
      DoorbellMonitor.closeAll();
    }
  }

  /** Close the shared socket and reset state (called on adapter unload). */
  static closeAll(): void {
    DoorbellMonitor.callbacks.clear();
    if (DoorbellMonitor.socket) {
      try {
        DoorbellMonitor.socket.close();
      } catch {
        /* ignore */
      }
    }
    DoorbellMonitor.socket = null;
    DoorbellMonitor.bound = false;
    DoorbellMonitor.bindFailed = false;
  }

  private static ensureSocket(): void {
    if (DoorbellMonitor.socket || DoorbellMonitor.bindFailed) {
      return;
    }
    const socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    DoorbellMonitor.socket = socket;

    socket.on('error', (err: any) => {
      // EADDRINUSE etc.: disable the feature, log once, and free the socket.
      DoorbellMonitor.bindFailed = true;
      DoorbellMonitor.log.warn(
        `DoorbellMonitor could not use UDP port ${DOORBELL_UDP_PORT} (${err?.message || err}). ` +
          `Doorbell ring events are disabled.`,
      );
      try {
        socket.close();
      } catch {
        /* ignore */
      }
      DoorbellMonitor.socket = null;
      DoorbellMonitor.bound = false;
    });

    socket.on('message', (msg: Buffer, rinfo: dgram.RemoteInfo) => {
      const cb = DoorbellMonitor.callbacks.get(rinfo.address);
      const registered = [...DoorbellMonitor.callbacks.keys()];
      DoorbellMonitor.log.debug(
        `DoorbellMonitor: UDP packet from ${rinfo.address}:${rinfo.port} len=${msg.length} matched=${!!cb} ` +
          `registered=${JSON.stringify(registered)}`,
      );
      if (cb) {
        // Exact match: the packet came from the doorbell's own IP (standalone doorbell).
        cb();
      } else if (DoorbellMonitor.callbacks.size > 0) {
        // No exact match, but doorbells are registered. Hub-paired battery doorbells
        // (e.g. D210 + H200) broadcast the ring from the HUB's IP, not the doorbell's
        // (matches HomeAssistant-Tapo-Control, which monitors the parent/hub IP).
        // Port 20005 traffic is doorbell-ring specific, so treat it as a ring for all
        // registered doorbells.
        DoorbellMonitor.log.debug(
          `DoorbellMonitor: unmatched source ${rinfo.address}, firing all registered doorbells (hub-sourced ring)`,
        );
        for (const fire of DoorbellMonitor.callbacks.values()) {
          fire();
        }
      }
    });

    socket.bind(DOORBELL_UDP_PORT, '0.0.0.0', () => {
      try {
        socket.setBroadcast(true);
      } catch {
        /* ignore */
      }
      DoorbellMonitor.bound = true;
      DoorbellMonitor.log.debug(`DoorbellMonitor listening on UDP ${DOORBELL_UDP_PORT}`);
    });
  }
}
