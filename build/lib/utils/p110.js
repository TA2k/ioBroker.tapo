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
        const response = await this.sendCommand('get_energy_usage');
        if (response && response.current_power !== undefined) {
            this._consumption = {
                current: Math.ceil(response.current_power / 1000),
                total: response.today_energy / 1000,
            };
        }
        else {
            this._consumption = {
                current: 0,
                total: 0,
            };
        }
        return response;
    }
    getPowerConsumption() {
        return this._consumption;
    }
}
exports.default = P110;
//# sourceMappingURL=p110.js.map