"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.OnvifCamera = void 0;
// @ts-ignore
const onvif_1 = require("onvif");
const stream_1 = require("stream");
class OnvifCamera {
    log;
    config;
    events;
    device;
    kOnvifPort = 2020;
    constructor(log, config) {
        this.log = log;
        this.config = config;
    }
    async getDevice() {
        return new Promise((resolve, reject) => {
            if (this.device) {
                return resolve(this.device);
            }
            const device = new onvif_1.Cam({
                hostname: this.config.ipAddress,
                username: this.config.streamUser,
                password: this.config.streamPassword,
                port: this.kOnvifPort,
            }, (err) => {
                if (err) {
                    return reject(err);
                }
                this.device = device;
                return resolve(this.device);
            });
        });
    }
    async getEventEmitter() {
        if (this.events) {
            return this.events;
        }
        const onvifDevice = await this.getDevice();
        let lastMotionValue = false;
        this.events = new stream_1.EventEmitter();
        onvifDevice.on('event', (event) => {
            if (event?.topic?._?.match(/RuleEngine\/CellMotionDetector\/Motion$/)) {
                const motion = event.message.message.data.simpleItem.$.Value;
                if (motion !== lastMotionValue) {
                    lastMotionValue = Boolean(motion);
                    this.events = this.events || new stream_1.EventEmitter();
                    this.events.emit('motion', motion);
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
            onvifDevice.getDeviceInformation((err, deviceInformation) => {
                if (err)
                    return reject(err);
                resolve(deviceInformation);
            });
        });
    }
}
exports.OnvifCamera = OnvifCamera;
//# sourceMappingURL=onvifCamera.js.map