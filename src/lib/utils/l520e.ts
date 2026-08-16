import L510E from './l510e';
import { ColorTempLightSysinfo } from './types';

export default class L520E extends L510E {

  private _colorTempSysInfo!:ColorTempLightSysinfo;

  constructor(
    public readonly log: any,
    public readonly ipAddress: string,
    public readonly email: string,
    public readonly password: string,
    public readonly timeout: number,
    port?: number,
    useHttps?: boolean,
  ) {
    super(log, ipAddress, email, password, timeout, port, useHttps);
    this.log.debug('Constructing L510E on host: ' + ipAddress);
  }

  async getDeviceInfo(force?:boolean): Promise<ColorTempLightSysinfo>{
    return super.getDeviceInfo(force).then(() => {
      return this.getSysInfo();
    });
  }

  async setColorTemp(color_temp: number): Promise<boolean> {
    // Tapo expects the color temperature directly in Kelvin (2500-6500), NOT in
    // mired - matching python-kasa's set_color_temp ({color_temp: <kelvin>}).
    // Send ONLY color_temp: sending hue/saturation:0 alongside made the L530
    // briefly apply the temp and then revert to a warm hue.
    const roundedValue = color_temp > 6500 ? 6500 : color_temp < 2500 ? 2500 : Math.round(color_temp);
    this.log.debug('Color Temp Tapo (Kelvin): ' + roundedValue);

    const payload =
      '{' +
      '"method": "set_device_info",' +
      '"params": {' +
      '"color_temp": ' +
      roundedValue +
      '},' +
      '"requestTimeMils": ' +
      Math.round(Date.now() * 1000) +
      '' +
      '};';

    return this.sendRequest(payload);
  }

  private transformColorTemp(value: number):number{
    return Math.floor(1000000 / value);
  }

  async getColorTemp(): Promise<number>{
    return super.getDeviceInfo().then(() => {
      return this.calculateColorTemp(this.getSysInfo().color_temp);
    });
  }

  calculateColorTemp(tapo_color_temp:number):number{
    const newValue = this.transformColorTemp(tapo_color_temp);
    return newValue > 400 ? 400 : (newValue < 154 ? 154 : newValue);
  }

  protected setSysInfo(sysInfo:ColorTempLightSysinfo){
    this._colorTempSysInfo = sysInfo;
    this._colorTempSysInfo.last_update = Date.now();
  }

  public getSysInfo():ColorTempLightSysinfo{
    return this._colorTempSysInfo;
  }
}