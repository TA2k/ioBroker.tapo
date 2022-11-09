import P100 from "./p100";
import { LightSysinfo } from "./types";

export default class camera extends P100 {
  constructor(
    public readonly log: any,
    public readonly ipAddress: string,
    public readonly email: string,
    public readonly password: string,
    public readonly timeout: number,
  ) {
    super(log, ipAddress, email, password, timeout);
    this.log.debug("Constructing Camera on host: " + ipAddress);
  }

  async getDeviceInfo(): Promise<LightSysinfo> {
    return super.getDeviceInfo().then(() => {
      return this.getSysInfo();
    });
  }

  async setAlertConfig(enabled: boolean): Promise<boolean> {
    const enabledString = enabled ? "on" : "off";
    const payload = `
    {
      "method": "setAlertConfig",
      "params": {
        "msg_alarm": {
          "chn1_msg_alarm_info": {
            "alarm_type": "0",
            "alarm_mode": ["sound"],
            "enabled": "${enabledString}",
            "light_type": "1"
          }
        },
        "requestTimeMils": ${Math.round(Date.now() * 1000)}
      }
    }`;
    return this.sendRequest(payload);
  }
  async setLensMaskConfig(enabled: boolean): Promise<boolean> {
    const enabledString = enabled ? "on" : "off";
    const payload = `
    {
      "method": "setLensMaskConfig",
      "params": {
        "lens_mask": {
          "lens_mask_info": {
            "enabled": "${enabledString}"
          }
        },
        "requestTimeMils": ${Math.round(Date.now() * 1000)}
      }
    }`;
    return this.sendRequest(payload);
  }

  protected setSysInfo(sysInfo: LightSysinfo) {
    this._lightSysInfo = sysInfo;
    this._lightSysInfo.last_update = Date.now();
  }

  public getSysInfo(): LightSysinfo {
    return this._lightSysInfo;
  }
}
