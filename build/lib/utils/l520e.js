"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const l510e_1 = __importDefault(require("./l510e"));
class L520E extends l510e_1.default {
    log;
    ipAddress;
    email;
    password;
    timeout;
    _colorTempSysInfo;
    constructor(log, ipAddress, email, password, timeout) {
        super(log, ipAddress, email, password, timeout);
        this.log = log;
        this.ipAddress = ipAddress;
        this.email = email;
        this.password = password;
        this.timeout = timeout;
        this.log.debug('Constructing L510E on host: ' + ipAddress);
    }
    async getDeviceInfo(force) {
        return super.getDeviceInfo(force).then(() => {
            return this.getSysInfo();
        });
    }
    async setColorTemp(color_temp) {
        const transformedColorTemp = this.transformColorTemp(color_temp);
        this.log.debug('Color Temp Tapo :' + transformedColorTemp);
        const roundedValue = transformedColorTemp > 6500 ? 6500 : transformedColorTemp < 2500 ?
            2500 : transformedColorTemp;
        const payload = '{' +
            '"method": "set_device_info",' +
            '"params": {' +
            '"hue": 0,' +
            '"saturation": 0,' +
            '"color_temp": ' + roundedValue +
            '},' +
            '"requestTimeMils": ' + Math.round(Date.now() * 1000) + '' +
            '};';
        return this.sendRequest(payload);
    }
    transformColorTemp(value) {
        return Math.floor(1000000 / value);
    }
    async getColorTemp() {
        return super.getDeviceInfo().then(() => {
            return this.calculateColorTemp(this.getSysInfo().color_temp);
        });
    }
    calculateColorTemp(tapo_color_temp) {
        const newValue = this.transformColorTemp(tapo_color_temp);
        return newValue > 400 ? 400 : (newValue < 154 ? 154 : newValue);
    }
    setSysInfo(sysInfo) {
        this._colorTempSysInfo = sysInfo;
        this._colorTempSysInfo.last_update = Date.now();
    }
    getSysInfo() {
        return this._colorTempSysInfo;
    }
}
exports.default = L520E;
//# sourceMappingURL=l520e.js.map