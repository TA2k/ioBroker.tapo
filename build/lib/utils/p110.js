"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const p100_1 = __importDefault(require("./p100"));
class P110 extends p100_1.default {
    log;
    ipAddress;
    email;
    password;
    timeout;
    _consumption;
    constructor(log, ipAddress, email, password, timeout) {
        super(log, ipAddress, email, password, timeout);
        this.log = log;
        this.ipAddress = ipAddress;
        this.email = email;
        this.password = password;
        this.timeout = timeout;
        this.log.info('Constructing P110 on host: ' + ipAddress);
    }
    async getEnergyUsage() {
        const payload = '{' +
            '"method": "get_energy_usage",' +
            '"requestTimeMils": ' + Math.round(Date.now() * 1000) + '' +
            '};';
        if (this.is_klap) {
            return this.handleKlapRequest(payload).then((response) => {
                if (response && response.result) {
                    this._consumption = {
                        current: Math.ceil(response.result.current_power / 1000),
                        total: response.result.today_energy / 1000,
                    };
                }
                else {
                    this._consumption = {
                        current: 0,
                        total: 0,
                    };
                }
                return response.result;
            });
        }
        else {
            return this.handleRequest(payload).then((response) => {
                if (response && response.result) {
                    this._consumption = {
                        current: Math.ceil(response.result.current_power / 1000),
                        total: response.result.today_energy / 1000,
                    };
                }
                else {
                    this._consumption = {
                        current: 0,
                        total: 0,
                    };
                }
                return response.result;
            });
        }
    }
    getPowerConsumption() {
        return this._consumption;
    }
}
exports.default = P110;
//# sourceMappingURL=p110.js.map