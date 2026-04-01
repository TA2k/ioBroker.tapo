"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const p100_js_1 = __importDefault(require("./p100.js"));
class L510E extends p100_js_1.default {
    log;
    ipAddress;
    email;
    password;
    timeout;
    _lightSysInfo;
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
    async setBrightness(brightness) {
        const payload = '{' +
            '"method": "set_device_info",' +
            '"params": {' +
            '"brightness": ' +
            brightness +
            '},' +
            '"requestTimeMils": ' +
            Math.round(Date.now() * 1000) +
            '' +
            '};';
        return this.sendRequest(payload);
    }
    setSysInfo(sysInfo) {
        this._lightSysInfo = sysInfo;
        this._lightSysInfo.last_update = Date.now();
    }
    getSysInfo() {
        return this._lightSysInfo;
    }
}
exports.default = L510E;
//# sourceMappingURL=l510e.js.map