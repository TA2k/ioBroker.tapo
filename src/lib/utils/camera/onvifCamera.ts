import { DeviceInformation, VideoSource, NotificationMessage, Cam as ICam } from "./types/onvif";
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import { Cam } from "onvif";
import { EventEmitter } from "stream";
type CameraConfig = {
  name: string;
  ipAddress: string;
  username: string;
  password: string;
  streamUser: string;
  streamPassword: string;

  pullInterval?: number;
  disableStreaming?: boolean;
  disablePrivacyAccessory?: boolean;
  disableAlarmAccessory?: boolean;
  disableMotionAccessory?: boolean;
  lowQuality?: boolean;

  videoConfig?: VideoConfig;

  privacyAccessoryName?: string;
  alarmAccessoryName?: string;
};
export class OnvifCamera {
  private events: EventEmitter | undefined;
  private device: Cam | undefined;

  private readonly kOnvifPort = 2020;

  constructor(protected readonly config: CameraConfig) {}

  private async getDevice(): Promise<ICam> {
    return new Promise((resolve, reject) => {
      if (this.device) {
        return resolve(this.device);
      }

      const device: ICam = new Cam(
        {
          hostname: this.config.ipAddress,
          username: this.config.streamUser,
          password: this.config.streamPassword,
          port: this.kOnvifPort,
        },
        (err: Error) => {
          if (err) {
            return reject(err);
          }
          this.device = device;
          return resolve(this.device);
        },
      );
    });
  }

  async getEventEmitter() {
    if (this.events) {
      return this.events;
    }

    const onvifDevice = await this.getDevice();

    let lastMotionValue = false;

    this.events = new EventEmitter();

    onvifDevice.on("event", (event: NotificationMessage) => {
      if (event?.topic?._?.match(/RuleEngine\/CellMotionDetector\/Motion$/)) {
        const motion = event.message.message.data.simpleItem.$.Value;
        if (motion !== lastMotionValue) {
          lastMotionValue = Boolean(motion);
          this.events = this.events || new EventEmitter();
          this.events.emit("motion", motion);
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
      onvifDevice.getDeviceInformation((err, deviceInformation) => {
        if (err) return reject(err);
        resolve(deviceInformation);
      });
    });
  }
}
