import P100 from './p100.js';

/**
 * Tapo D100C standalone smart chime. Speaks the plug/TPAP protocol on port 80
 * (discovery: encrypt=TPAP, https=false), NOT the camera protocol, so it extends
 * P100 and uses sendCommand() (which transparently handles TPAP/KLAP/AES).
 *
 * Command names are taken from the Tapo APK (play_alarm, stop_alarm, set_volume,
 * get_support_alarm_type_list, get_chime_alarm_configure/set_chime_alarm_configure)
 * and param shapes from pytapo. The device is not locally testable here, so all
 * commands are defensive: failures are logged and swallowed, never thrown.
 */
export default class D100C extends P100 {
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
    this.log.debug('Constructing D100C on host: ' + ipAddress);
  }

  /** List of supported ring/alarm types. */
  async getSupportAlarmTypeList(): Promise<any> {
    return this.sendCommand('get_support_alarm_type_list');
  }

  /** Play the chime. Optional ring type, volume (1-15) and duration (0 or 5-30 s). */
  async playAlarm(type?: string | number | boolean, volume?: number, duration?: number): Promise<any> {
    const params: Record<string, any> = {};
    // The button state passes boolean true; treat that as "no explicit type".
    if (type !== undefined && type !== '' && type !== true && type !== false) params.type = String(type);
    if (volume !== undefined) params.volume = String(volume);
    if (duration !== undefined) params.duration = Number(duration);
    return this.sendCommand('play_alarm', params);
  }

  /** Stop a currently playing chime. */
  async stopAlarm(): Promise<any> {
    return this.sendCommand('stop_alarm');
  }

  /** Set the chime volume (1-15). */
  async setVolume(volume: number): Promise<any> {
    return this.sendCommand('set_volume', { volume: String(volume) });
  }

  /** Set the default ring/alarm type. */
  async setRingType(type: string | number): Promise<any> {
    return this.sendCommand('set_chime_alarm_configure', { type: String(type) });
  }
}
