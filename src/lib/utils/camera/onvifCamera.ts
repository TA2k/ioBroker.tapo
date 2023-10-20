import { Cam, NotificationMessage } from "onvif";
import { EventEmitter } from "stream";
type CameraConfig = {
  name: string;
  ipAddress: string;
  password: string;
  streamUser: string;
  streamPassword: string;

  pullInterval?: number;
  disableStreaming?: boolean;
  disablePrivacyAccessory?: boolean;
  disableAlarmAccessory?: boolean;
  disableMotionAccessory?: boolean;
  lowQuality?: boolean;
};
export class OnvifCamera {
  private events: EventEmitter | undefined;
  private device: Cam | undefined;

  private readonly kOnvifPort = 2020;

  constructor(protected readonly log: any, protected readonly config: CameraConfig) {}

  private async getDevice(): Promise<Cam> {

    return new Promise((resolve, reject) => {
      if (this.device) {
        return resolve(this.device);
      }
      this.log.debug("Connecting to ONVIF device" + JSON.stringify(this.config) + " on port " + this.kOnvifPort);
      const device: Cam = new Cam(
        {
          hostname: this.config.ipAddress,
          username: this.config.streamUser,
          password: this.config.streamPassword,
          port: this.kOnvifPort,
        },
        (err) => {
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
    this.log.debug("Getting device for event emiiter");
    const onvifDevice = await this.getDevice();
    this.log.debug("Got device for event emiiter" + JSON.stringify(onvifDevice));
    let lastMotionValue = false;
    this.log.debug("Creating event emitter");
    this.events = new EventEmitter();
    this.log.debug(`[${this.config.name}]`, "Starting ONVIF listener");

    onvifDevice.on("event", (event: NotificationMessage) => {
      this.log.debug(`Received event: ${JSON.stringify(event)}`);
      if (event?.topic?._?.match(/RuleEngine\/CellMotionDetector\/Motion$/)) {
        const motion = event.message.message.data.simpleItem.$.Value;
        if (motion !== lastMotionValue) {
          lastMotionValue = motion;
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
      this.log.debug("Getting device information ");
      onvifDevice.getDeviceInformation((err, deviceInformation) => {
        this.log.debug("Got device information for " + JSON.stringify(deviceInformation));
        if (err) return reject(err);
        resolve(deviceInformation);
      });
    });
  }
}
