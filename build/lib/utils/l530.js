"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const l520e_1 = __importDefault(require("./l520e"));
class L530 extends l520e_1.default {
    log;
    ipAddress;
    email;
    password;
    timeout;
    _colorLightSysInfo;
    _consumption;
    constructor(log, ipAddress, email, password, timeout) {
        super(log, ipAddress, email, password, timeout);
        this.log = log;
        this.ipAddress = ipAddress;
        this.email = email;
        this.password = password;
        this.timeout = timeout;
        this.log.debug('Constructing L530 on host: ' + ipAddress);
        this._consumption = {
            total: 0,
            current: 0,
        };
    }
    async getDeviceInfo(force) {
        return super.getDeviceInfo(force).then(() => {
            return this.getSysInfo();
        });
    }
    async setColor(hue, saturation) {
        if (!hue) {
            hue = 0;
        }
        if (!saturation) {
            saturation = 0;
        }
        this.log.debug('Setting color: ' + hue + ', ' + saturation);
        const payload = '{' +
            '"method": "set_device_info",' +
            '"params": {' +
            '"hue": ' + Math.round(hue) + ',' +
            '"color_temp": 0,' +
            '"saturation": ' + Math.round(saturation) +
            '},' +
            '"requestTimeMils": ' + Math.round(Date.now() * 1000) + '' +
            '};';
        return this.sendRequest(payload);
    }
    setSysInfo(sysInfo) {
        this._colorLightSysInfo = sysInfo;
        this._colorLightSysInfo.last_update = Date.now();
    }
    getSysInfo() {
        return this._colorLightSysInfo;
    }
    async getEnergyUsage() {
        const payload = '{' +
            '"method": "get_device_usage",' +
            '"requestTimeMils": ' + Math.round(Date.now() * 1000) + '' +
            '};';
        this.log.debug('getEnergyUsage called');
        if (this.is_klap) {
            this.log.debug('getEnergyUsage is klap');
            return this.handleKlapRequest(payload).then((response) => {
                this.log.debug('Consumption: ' + JSON.stringify(response));
                if (response && response.result) {
                    this._consumption = {
                        total: response.result.power_usage.today / 1000,
                        current: this._consumption ? response.result.power_usage.today / this.toHours(response.result.time_usage.today) : 0,
                    };
                }
                else {
                    this._consumption = {
                        total: 0,
                        current: 0,
                    };
                }
                return response.result;
            }).catch((error) => {
                if (error.message && error.message.indexOf('9999') > 0) {
                    return this.reconnect().then(() => {
                        return this.handleKlapRequest(payload).then(() => {
                            return true;
                        });
                    });
                }
                return false;
            });
        }
        else {
            return this.handleRequest(payload).then((response) => {
                this.log.debug('Consumption: ' + response);
                if (response && response.result) {
                    this._consumption = {
                        total: response.result.power_usage.today / 1000,
                        current: this._consumption ? response.result.power_usage.today / this.toHours(response.result.time_usage.today) : 0,
                    };
                }
                else {
                    this._consumption = {
                        total: 0,
                        current: 0,
                    };
                }
                return response.result;
            }).catch((error) => {
                if (error.message && error.message.indexOf('9999') > 0) {
                    return this.reconnect().then(() => {
                        return this.handleRequest(payload).then(() => {
                            return true;
                        });
                    });
                }
                return false;
            });
        }
    }
    getPowerConsumption() {
        if (!this.getSysInfo().device_on) {
            return {
                total: this._consumption.total,
                current: 0,
            };
        }
        return this._consumption;
    }
    toHours(minutes) {
        return minutes / 60;
    }
}
exports.default = L530;
//# sourceMappingURL=l530.js.map