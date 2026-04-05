import { EnergyUsage } from './energyUsage';
import P100 from './p100';
import { ConsumptionInfo } from './types';

export default class P110 extends P100 {

  private _consumption!:ConsumptionInfo;

  constructor(
    public readonly log: any,
    public readonly ipAddress: string,
    public readonly email: string,
    public readonly password: string,
    public readonly timeout: number,
  ) {
    super(log, ipAddress, email, password, timeout);
    this.log.info('Constructing P110 on host: ' + ipAddress);
  }

  async getEnergyUsage():Promise<EnergyUsage>{
    const response = await this.sendCommand('get_energy_usage');
    if(response && response.current_power !== undefined){
      this._consumption = {
        current: Math.ceil(response.current_power / 1000),
        total: response.today_energy / 1000,
      };
    } else{
      this._consumption = {
        current: 0,
        total: 0,
      };
    }
    return response;
  }

  public getPowerConsumption():ConsumptionInfo{
    return this._consumption;
  }
}