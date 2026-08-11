import { DeviceInformation, VideoSource, NotificationMessage } from './types/onvif';
// @ts-ignore
import { Cam } from 'onvif';
import { EventEmitter } from 'stream';
type CameraConfig = {
  name: string;
  ipAddress: string;
  username?: string;
  password: string;
  streamUser: string;
  streamPassword: string;

  pullInterval?: number;
  disableStreaming?: boolean;
  disablePrivacyAccessory?: boolean;
  disableAlarmAccessory?: boolean;
  disableMotionAccessory?: boolean;
  lowQuality?: boolean;

  privacyAccessoryName?: string;
  alarmAccessoryName?: string;
};
export class OnvifCamera {
  private events: EventEmitter | undefined;
  private device: any;

  private readonly kOnvifPort = 2020;

  constructor(protected readonly log: any, protected readonly config: CameraConfig) {}

  /** IP of the camera. Mirrors the P100 `ip` field so main.ts logging/reconnect
   * (which reads deviceObject.ip) shows the address instead of "undefined". */
  get ip(): string {
    return this.config.ipAddress;
  }

  private async getDevice(): Promise<any> {
    return new Promise((resolve, reject) => {
      if (this.device) {
        return resolve(this.device);
      }

      let settled = false;
      const device = new Cam(
        {
          hostname: this.config.ipAddress,
          username: this.config.streamUser,
          password: this.config.streamPassword,
          port: this.kOnvifPort,
        },
        (err?: Error) => {
          if (settled) return;
          settled = true;
          if (err) {
            return reject(err);
          }
          this.device = device;
          return resolve(this.device);
        },
      );
      // The onvif Cam emits socket errors (EHOSTUNREACH/ETIMEDOUT) as 'error'
      // events that are not routed through the constructor callback. Without a
      // listener these surface as noisy top-level errors, so capture and reject.
      (device as any).on('error', (err: Error) => {
        if (settled) return;
        settled = true;
        reject(err);
      });
    });
  }

  async getEventEmitter() {
    if (this.events) {
      return this.events;
    }

    const onvifDevice = await this.getDevice();

    let lastMotionValue = false;

    this.events = new EventEmitter();

    onvifDevice.on('event', (event: NotificationMessage) => {
      if (event?.topic?._?.match(/RuleEngine\/CellMotionDetector\/Motion$/)) {
        const motion = event.message.message.data.simpleItem.$.Value;
        if (motion !== lastMotionValue) {
          lastMotionValue = Boolean(motion);
          this.events = this.events || new EventEmitter();
          this.events.emit('motion', motion);
        }
      }
    });

    return this.events;
  }

  async getVideoSource(): Promise<VideoSource> {
    const onvifDevice = await this.getDevice();
    return onvifDevice.videoSources[0];
  }

  async getDeviceInfo(): Promise<DeviceInformation> {
    const onvifDevice = await this.getDevice();
    return new Promise((resolve, reject) => {
      onvifDevice.getDeviceInformation((err: any, deviceInformation: any) => {
        if (err) return reject(err);
        resolve(deviceInformation);
      });
    });
  }
}
