import { PlugSysinfo } from './types';
import TpLinkCipher from './tpLinkCipher.js';

import { AxiosResponse } from 'axios';
import NewTpLinkCipher from './newTpLinkCipher.js';
import TpapCipher from './tpapCipher.js';
import { TpLinkAccessory } from './tplinkAccessory.js';
import axios from 'axios';
import crypto from 'crypto';
import utf8 from 'utf8';

import http from 'http';

export default class P100 implements TpLinkAccessory {
  private _crypto = crypto;
  protected _axios = axios;
  private _utf8 = utf8;
  public is_klap = true;
  public is_tpap = false;
  public klap_version = 0; // 0 = unknown, 1 = v1 (md5), 2 = v2 (sha256)
  public deviceMac = '';

  private encodedPassword!: string;
  private encodedEmail!: string;
  private privateKey!: string;
  private publicKey!: string;
  protected ip: string;
  protected cookie!: string;
  protected tplink_timeout!: number;
  protected token!: string;
  protected terminalUUID: string;
  private _plugSysInfo!: PlugSysinfo;
  private _reconnect_counter: number;
  private _lastErrorMessage = '';
  protected _timeout!: number;

  protected tpLinkCipher!: TpLinkCipher;
  protected newTpLinkCipher!: NewTpLinkCipher;
  protected tpapCipher!: TpapCipher;

  protected ERROR_CODES = {
    '0': 'Success',
    '-1010': 'Invalid Public Key Length',
    '-1012': 'Invalid terminalUUID',
    '-1501': 'Invalid Request or Credentials',
    '1002': 'Incorrect Request',
    '-1003': 'JSON formatting error ',
    '9999': 'Session Timeout',
    '-1301': 'Device Error',
    '1100': 'Handshake Failed',
    '1111': 'Login Failed',
    '1112': 'Http Transport Failed',
    '1200': 'Multiple Requests Failed',
    '-1004': 'JSON Encode Failed',
    '-1005': 'AES Decode Failed',
    '-1006': 'Request Length Error',
    '-2101': 'Account Error',
    '-1': 'ERR_COMMON_FAILED',
    '1000': 'ERR_NULL_TRANSPORT',
    '1001': 'ERR_CMD_COMMAND_CANCEL',
    '-1001': 'ERR_UNSPECIFIC',
    '-1002': 'ERR_UNKNOWN_METHOD',
    '-1007': 'ERR_CLOUD_FAILED',
    '-1008': 'ERR_PARAMS',
    '-1101': 'ERR_SESSION_PARAM',
    '-1201': 'ERR_QUICK_SETUP',
    '-1302': 'ERR_DEVICE_NEXT_EVENT',
    '-1401': 'ERR_FIRMWARE',
    '-1402': 'ERR_FIRMWARE_VER_ERROR',
    '-1601': 'ERR_TIME',
    '-1602': 'ERR_TIME_SYS',
    '-1603': 'ERR_TIME_SAVE',
    '-1701': 'ERR_WIRELESS',
    '-1702': 'ERR_WIRELESS_UNSUPPORTED',
    '-1801': 'ERR_SCHEDULE',
    '-1802': 'ERR_SCHEDULE_FULL',
    '-1803': 'ERR_SCHEDULE_CONFLICT',
    '-1804': 'ERR_SCHEDULE_SAVE',
    '-1805': 'ERR_SCHEDULE_INDEX',
    '-1901': 'ERR_COUNTDOWN',
    '-1902': 'ERR_COUNTDOWN_CONFLICT',
    '-1903': 'ERR_COUNTDOWN_SAVE',
    '-2001': 'ERR_ANTITHEFT',
    '-2002': 'ERR_ANTITHEFT_CONFLICT',
    '-2003': 'ERR_ANTITHEFT_SAVE',
    '-2201': 'ERR_STAT',
    '-2202': 'ERR_STAT_SAVE',
    '-2301': 'ERR_DST',
    '-2302': 'ERR_DST_SAVE',
    '1003': 'KLAP',
  };

  constructor(
    public readonly log: any,
    public readonly ipAddress: string,
    public email: string,
    public readonly password: string,
    public readonly timeout: number,
  ) {
    this.log.debug('Constructing P100 on host: ' + ipAddress);
    this.ip = ipAddress;
    this.encryptCredentials(email, password);
    this.createKeyPair();
    this.terminalUUID = crypto.randomUUID();
    this._reconnect_counter = 0;
    this._timeout = timeout;
  }

  private encryptCredentials(email: string, password: string) {
    //Password Encoding
    this.encodedPassword = TpLinkCipher.mime_encoder(password);

    //Email Encoding
    this.encodedEmail = this.sha_digest_username(email);
    this.encodedEmail = TpLinkCipher.mime_encoder(this.encodedEmail);
  }

  private sha_digest_username(data: string): string {
    const digest = this._crypto.createHash('sha1').update(data).digest('hex');

    return digest;
  }

  private calc_auth_hash(username: string, password: string): Buffer {
    this.log.debug('calc_auth_hash v2: username="' + username + '" length=' + username.length + ' password_length=' + password.length);
    const usernameDigest = this._crypto
      .createHash('sha1')
      .update(Buffer.from(username.normalize('NFKC')))
      .digest();
    const passwordDigest = this._crypto
      .createHash('sha1')
      .update(Buffer.from(password.normalize('NFKC')))
      .digest();
    return this._crypto
      .createHash('sha256')
      .update(Buffer.concat([usernameDigest, passwordDigest]))
      .digest();
  }

  private calc_auth_hash_v1(username: string, password: string): Buffer {
    this.log.debug('calc_auth_hash v1: username="' + username + '" length=' + username.length + ' password_length=' + password.length);
    const usernameMd5 = this._crypto
      .createHash('md5')
      .update(Buffer.from(username.normalize('NFKC')))
      .digest();
    const passwordMd5 = this._crypto
      .createHash('md5')
      .update(Buffer.from(password.normalize('NFKC')))
      .digest();
    return this._crypto
      .createHash('md5')
      .update(Buffer.concat([usernameMd5, passwordMd5]))
      .digest();
  }

  private createKeyPair() {
    // Including publicKey and  privateKey from
    // generateKeyPairSync() method with its
    // parameters
    const { publicKey, privateKey } = this._crypto.generateKeyPairSync('rsa', {
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs1',
        format: 'pem',
      },
      modulusLength: 1024,
    });

    this.privateKey = privateKey;
    //@ts-ignore
    this.publicKey = publicKey.toString('utf8');
  }

  //old tapo requests
  async handshake(): Promise<void> {
    const URL = 'http://' + this.ip + '/app';
    const payload = {
      method: 'handshake',
      params: {
        key: this.publicKey,
        requestTimeMils: Math.round(Date.now() * 1000),
      },
    };
    this.log.debug('Old Handshake P100 on host: ' + this.ip);

    const headers = {
      Connection: 'Keep-Alive',
    };
    const config = {
      timeout: 5000,
      headers: headers,
    };

    await this._axios
      .post(URL, payload, config)
      .then((res: AxiosResponse) => {
        this.log.debug('Received Old Handshake P100 on host response: ' + this.ip);

        if (res.data.error_code || res.status !== 200) {
          return this.handleError(res.data!.error_code ? res.data.error_code : res.status, '172');
        }

        try {
          const encryptedKey = res.data.result.key.toString('utf8');
          this.decode_handshake_key(encryptedKey);
          if (res.headers['set-cookie']) {
            this.cookie = res.headers['set-cookie'][0].split(';')[0];
          }
          return;
        } catch (error) {
          return this.handleError(res.data.error_code, '106');
        }
      })
      .catch((error: Error) => {
        this.log.error('111 Error: ' + error ? error.message : '');
        return error;
      });
  }

  async login(): Promise<void> {
    const URL = 'http://' + this.ip + '/app';
    const payload =
      '{' +
      '"method": "login_device",' +
      '"params": {' +
      '"username": "' +
      this.encodedEmail +
      '",' +
      '"password": "' +
      this.encodedPassword +
      '"' +
      '},' +
      '"requestTimeMils": ' +
      Math.round(Date.now() * 1000) +
      '' +
      '};';

    const headers = {
      Cookie: this.cookie,
      Connection: 'Keep-Alive',
    };

    this.log.debug('Old Login to P100 with url ' + URL);
    this.log.debug('Headers ' + JSON.stringify(headers));
    this.log.debug('Cipher: ' + this.tpLinkCipher);
    if (this.tpLinkCipher) {
      const encryptedPayload = this.tpLinkCipher.encrypt(payload);

      const securePassthroughPayload = {
        method: 'securePassthrough',
        params: {
          request: encryptedPayload,
        },
      };

      const config = {
        headers: headers,
        timeout: this._timeout * 1000,
      };
      this.log.debug('Post request');
      await this._axios
        .post(URL, securePassthroughPayload, config)
        .then((res: AxiosResponse) => {
          if (res.data.error_code || res.status !== 200) {
            return this.handleError(res.data!.error_code ? res.data.error_code : res.status, '226');
          }
          const decryptedResponse = this.tpLinkCipher.decrypt(res.data.result.response);
          this.log.debug('Decrypted Response: ' + decryptedResponse);
          try {
            const response = JSON.parse(decryptedResponse);
            if (response.error_code !== 0) {
              return this.handleError(res.data.error_code, '152');
            }
            this.token = response.result.token;
            return;
          } catch (error) {
            return this.handleError(JSON.parse(decryptedResponse).error_code, '157');
          }
        })
        .catch((error: Error) => {
          this.log.error('Error Login: ' + error ? error.message : '');
          return error;
        });
    }
  }

  private async raw_request(path: string, data: Buffer, responseType: string, params?: any): Promise<any> {
    const URL = 'http://' + this.ip + '/app/' + path;

    const headers: Record<string, string> = {
      Connection: 'Keep-Alive',
      Host: this.ip,
      Accept: '*/*',
      'Content-Type': 'application/octet-stream',
    };

    if (this.cookie) {
      headers.Cookie = this.cookie;
    }

    const config: any = {
      timeout: 5000,
      responseType: responseType,
      headers: headers,
      params: params,
    };
    this.log.debug('Raw request to P100 with url ' + URL);
    this.log.debug('Data: ' + data.toString('hex'));
    this.log.debug('Headers: ' + JSON.stringify(headers));
    this.log.debug('Params: ' + JSON.stringify(params));
    this.log.debug('Cipher: ' + this.tpLinkCipher);

    //@ts-ignore
    return this._axios
      .post(URL, data, config)
      .then((res: AxiosResponse) => {
        this.log.debug('Received request on host response: ' + this.ip);
        if (res.data.error_code || res.status !== 200) {
          return this.handleError(res.data!.error_code ? res.data.error_code : res.status, '273');
        }

        try {
          if (res.headers && res.headers['set-cookie']) {
            this.log.debug('Handshake 1 cookie: ' + JSON.stringify(res.headers['set-cookie'][0]));
            this.cookie = res.headers['set-cookie'][0].split(';')[0];
            this.tplink_timeout = Number(res.headers['set-cookie'][0].split(';')[1]);
          }
          return res.data;
        } catch (error) {
          return this.handleError(res.data.error_code, '318');
        }
      })
      .catch((error: Error) => {
        this.log.error('276 Error: ' + error.message + ' ' + this.ip);
        if (error.message.indexOf('403') > -1) {
          this.reAuthenticate();
        }
        return false;
      });
  }

  private decode_handshake_key(key: string) {
    const buff = Buffer.from(key, 'base64');

    const decoded = this._crypto.privateDecrypt(
      {
        key: this.privateKey,
        padding: this._crypto.constants.RSA_PKCS1_PADDING,
      },
      buff,
    );

    const b_arr = decoded.slice(0, 16);
    const b_arr2 = decoded.slice(16, 32);

    this.tpLinkCipher = new TpLinkCipher(this.log, b_arr, b_arr2);
  }

  //new tapo klap requests
  async handshake_new(): Promise<void> {
    this.log.debug('Trying new handshake');

    const local_seed = this._crypto.randomBytes(16);

    //send handshake1 via native http

    const options: http.RequestOptions = {
      method: 'POST',
      hostname: this.ip,
      path: '/app/handshake1',
      headers: {
        Connection: 'Keep-Alive',
        'Content-Type': 'application/octet-stream',
        'Content-Length': local_seed.length,
      },
      agent: new http.Agent({
        keepAlive: true,
      }),
    };
    const response = await new Promise<Buffer>((resolve, reject) => {
      const request = http
        .request(options, (res: any) => {
          const chunks: any = [];
          if (res.headers && res.headers['set-cookie']) {
            this.cookie = res.headers['set-cookie'][0].split(';')[0];
          }
          res.on('data', (chunk: any) => {
            chunks.push(chunk);
          });

          res.on('end', (chunk: any) => {
            const body = Buffer.concat(chunks);
            this.log.debug('handshake1 status=' + res.statusCode + ' body_length=' + body.length);
            if (res.statusCode === 403) {
              this.log.debug('handshake1 ' + this.ip + ': HTTP 403 - device does not support KLAP, will try TPAP');
              resolve(Buffer.from(''));
              return;
            }
            if (res.statusCode !== 200) {
              this.log.error('handshake1 ' + this.ip + ': HTTP ' + res.statusCode);
              resolve(Buffer.from(''));
              return;
            }
            resolve(body);
          });

          res.on('error', (error: any) => {
            this.log.debug('handshake1 response error: ' + error);
            resolve(Buffer.from(''));
          });
        })
        .on('error', (error: any) => {
          this.log.debug('handshake1 connection error: ' + error);
          resolve(Buffer.from(''));
        });
      request.write(local_seed);
      request.end();
    });
    // const response = await this.raw_request("handshake1", local_seed, "arraybuffer").then((res) => {
    //axios not working for handshake1
    if (!response || !response.subarray) {
      this.log.debug('New Handshake 1 failed: empty response from ' + this.ip);
      throw new Error('New Handshake 1 failed: empty response from ' + this.ip);
    }
    this.log.debug('Handshake 1 response: ' + response.toString('hex'));
    const remote_seed: Buffer = response.subarray(0, 16);
    const server_hash: Buffer = response.subarray(16);
    this.log.debug('remote seed: ' + remote_seed.toString('hex'));
    this.log.debug('server hash: ' + server_hash.toString('hex'));
    this.log.debug('Extracted hashes');
    let auth_hash: any = undefined;

    // v2: sha256(local_seed + remote_seed + auth_hash), v1: sha256(local_seed + auth_hash)
    const calcSeedHash = (ah: Buffer, version: number) => {
      const payload = version === 1
        ? Buffer.concat([local_seed, ah])
        : Buffer.concat([local_seed, remote_seed, ah]);
      return this._crypto.createHash('sha256').update(payload).digest();
    };

    const matchesServer = (hash: Buffer): boolean => hash.toString('hex') === server_hash.toString('hex');

    // Try v2 first (newer devices), then v1 (older devices)
    const candidates: Array<[string, string, string, number]> = [
      [this.email, this.password, 'user', 2],
      [this.email, this.password, 'user', 1],
      ['', '', 'empty', 2],
      ['', '', 'empty', 1],
      ['test@tp-link.net', 'test', 'test', 2],
      ['test@tp-link.net', 'test', 'test', 1],
    ];

    let matchedVersion = 0;
    for (const [email, password, label, version] of candidates) {
      const ah = version === 1 ? this.calc_auth_hash_v1(email, password) : this.calc_auth_hash(email, password);
      const hash = calcSeedHash(ah, version);
      const match = matchesServer(hash);
      this.log.debug(
        'Auth candidate ' + this.ip + ': v' + version + ' ' + label + ' hash=' + hash.toString('hex').substring(0, 16) + '... match=' + match,
      );
      if (match) {
        this.log.info('KLAP v' + version + ' handshake successful for ' + this.ip + ' with ' + label);
        auth_hash = ah;
        matchedVersion = version;
        break;
      }
    }

    if (!auth_hash) {
      const msg = 'Handshake 1 failed ' + this.ip + ' server_hash=' + server_hash.toString('hex') + ' response_length=' + response.length;
      this.log.debug(msg);
      throw new Error(msg);
    }

    this.klap_version = matchedVersion;

    // v2: sha256(remote_seed + local_seed + auth_hash), v1: sha256(remote_seed + auth_hash)
    const handshake2Payload = matchedVersion === 1
      ? Buffer.concat([remote_seed, auth_hash])
      : Buffer.concat([remote_seed, local_seed, auth_hash]);
    const req = this._crypto
      .createHash('sha256')
      .update(handshake2Payload)
      .digest();

    return this.raw_request('handshake2', req, 'text').then((res) => {
      this.log.debug('New Handshake 2 successful: ' + res);

      this.newTpLinkCipher = new NewTpLinkCipher(local_seed, remote_seed, auth_hash, this.log);
      this.log.debug('New Init cipher successful');

      return;
    });
    //   });
  }

  //TPAP/SPAKE2+ handshake for newer firmware devices
  async handshake_tpap(): Promise<void> {
    this.log.debug('Trying TPAP/SPAKE2+ handshake for ' + this.ip);
    this.tpapCipher = new TpapCipher(this.log, this.ip, this.email, this.password, this.deviceMac);

    // Discover to get pake list, MAC, user_hash_type
    let pakeList: number[] = [2];
    let userHashType = 0;
    try {
      const discoverRes = await this._axios.post('http://' + this.ip + '/', {
        method: 'login',
        params: { sub_method: 'discover' },
      }, { timeout: 5000 });
      const tpap = discoverRes.data?.result?.tpap;
      if (tpap?.pake) {
        pakeList = tpap.pake;
        if (tpap.mac) {
          this.deviceMac = tpap.mac;
        }
        if (tpap.user_hash_type != null) {
          userHashType = tpap.user_hash_type;
        }
        this.log.debug('TPAP discover: pake=' + JSON.stringify(pakeList) + ' mac=' + this.deviceMac + ' user_hash_type=' + userHashType);
      }
    } catch (e: any) {
      this.log.debug('TPAP discover failed, using defaults: ' + e.message);
    }

    await this.tpapCipher.handshake(pakeList, userHashType);
    this.is_tpap = true;
    this.is_klap = false;
  }

  async turnOff(): Promise<boolean> {
    const payload =
      '{' +
      '"method": "set_device_info",' +
      '"params": {' +
      '"device_on": false' +
      '},' +
      '"terminalUUID": "' +
      this.terminalUUID +
      '",' +
      '"requestTimeMils": ' +
      Math.round(Date.now() * 1000) +
      '' +
      '};';
    return this.sendRequest(payload);
  }

  async turnOn(): Promise<boolean> {
    const payload =
      '{' +
      '"method": "set_device_info",' +
      '"params": {' +
      '"device_on": true' +
      '},' +
      '"terminalUUID": "' +
      this.terminalUUID +
      '",' +
      '"requestTimeMils": ' +
      Math.round(Date.now() * 1000) +
      '' +
      '};';

    return this.sendRequest(payload);
  }
  async getChildDevices(): Promise<boolean> {
    const payload = {
      method: 'getChildDeviceList',
      params: { childControl: { start_index: 0 } },
    };

    return this.sendRequest(JSON.stringify(payload));
  }
  async setPowerStateChild(deviceId: string, state: boolean): Promise<boolean> {
    const payload = {
      method: 'controlChild',
      params: {
        childControl: {
          device_id: deviceId,
          request_data: {
            method: 'set_device_info',
            params: { device_on: state },
            requestTimeMils: Math.round(Date.now() * 1000),
            terminalUUID: this.terminalUUID,
          },
        },
      },
    };

    return this.sendRequest(JSON.stringify(payload));
  }
  async setPowerState(state: boolean): Promise<boolean> {
    if (state) {
      return this.turnOn();
    } else {
      return this.turnOff();
    }
  }

  async getDeviceInfo(force?: boolean): Promise<PlugSysinfo> {
    if (!force) {
      return new Promise((resolve) => {
        resolve(this.getSysInfo());
      });
    }
    const URL = 'http://' + this.ip + '/app?token=' + this.token;

    const payload = '{' + '"method": "get_device_info",' + '"requestTimeMils": ' + Math.round(Date.now() * 1000) + '' + '};';
    const headers = {
      Cookie: this.cookie,
    };

    if (this.tpLinkCipher) {
      const encryptedPayload = this.tpLinkCipher.encrypt(payload);

      const securePassthroughPayload = {
        method: 'securePassthrough',
        params: {
          request: encryptedPayload,
        },
      };

      const config = {
        headers: headers,
        timeout: this._timeout * 1000,
      };
      //@ts-ignore
      return this._axios
        .post(URL, securePassthroughPayload, config)
        .then((res: any) => {
          if (res.data.error_code) {
            if ((res.data.error_code === '9999' || res.data.error_code === 9999) && this._reconnect_counter <= 3) {
              //@ts-ignore
              this.log.error(' Error Code: ' + res.data.error_code + ', ' + this.ERROR_CODES[res.data.error_code]);
              this.log.debug('Trying to reconnect...');
              return this.reconnect().then(() => {
                return this.getDeviceInfo();
              });
            }
            this._reconnect_counter = 0;
            return this.handleError(res.data.error_code, '326');
          }

          const decryptedResponse = this.tpLinkCipher.decrypt(res.data.result.response);
          try {
            const response = JSON.parse(decryptedResponse);
            if (response.error_code !== 0) {
              return this.handleError(response.error_code, '333');
            }
            this.setSysInfo(response.result);
            this.log.debug('Device Info: ', response.result);

            return this.getSysInfo();
          } catch (error: any) {
            this.log.debug(error.stack);
            return this.handleError(JSON.parse(decryptedResponse).error_code, '340');
          }
        })
        .catch((error: Error) => {
          this.log.error('371 Error: ' + error ? error.message : '');
          return error;
        });
    } else if (this.newTpLinkCipher) {
      const data = this.newTpLinkCipher.encrypt(payload);

      const URL = 'http://' + this.ip + '/app/' + 'request';
      const headers = {
        Connection: 'Keep-Alive',
        Host: this.ip,
        Accept: '*/*',
        'Content-Type': 'application/octet-stream',
      };

      if (this.cookie) {
        //@ts-ignore
        headers.Cookie = this.cookie;
      }

      const config: any = {
        timeout: 5000,
        responseType: 'arraybuffer',
        headers: headers,
        params: { seq: data.seq.toString() },
      };
      //@ts-ignore
      return this._axios
        .post(URL, data.encryptedPayload, config)
        .then((res: AxiosResponse) => {
          if (res.data.error_code) {
            return this.handleError(res.data.error_code, '309');
          }

          try {
            if (res.headers && res.headers['set-cookie']) {
              this.cookie = res.headers['set-cookie'][0].split(';')[0];
            }

            const decrypted = this.newTpLinkCipher.decrypt(res.data);
            const response = JSON.parse(decrypted);

            if (response.error_code !== 0) {
              return this.handleError(response.error_code, '333');
            }
            this.setSysInfo(response.result);
            this.log.debug('Device Info: ', response.result);

            return this.getSysInfo();
          } catch (error: any) {
            this.log.debug('Decrypt/parse error: ' + error.message);
            this.log.debug('Status: ' + res.status);
            return this.handleError(res.data?.error_code || error.message, '480');
          }
        })
        .catch((error: Error) => {
          this.log.debug('469 Error: ' + JSON.stringify(error));
          this.log.info('469 Error: ' + error.message);
          if (error.message.indexOf('403') > -1) {
            this.reAuthenticate();
          }
          return error;
        });
    } else if (this.tpapCipher && this.tpapCipher.isReady) {
      //@ts-ignore
      return this.handleTpapRequest(payload)
        .then((response: any) => {
          if (!response || response.error_code !== undefined && response.error_code !== 0) {
            return this.handleError(response?.error_code || 'unknown', 'tpap_getDeviceInfo');
          }
          this.setSysInfo(response.result);
          this.log.debug('Device Info: ', response.result);
          return this.getSysInfo();
        })
        .catch((error: Error) => {
          this.log.error('TPAP getDeviceInfo Error: ' + (error ? error.message : ''));
          return error;
        });
    } else {
      return new Promise<PlugSysinfo>((resolve, reject) => {
        reject();
      });
    }
  }

  /**
   * Cached value of `sysinfo.device_id`  if set.
   */
  get id(): string {
    if (this.getSysInfo()) {
      return this.getSysInfo().device_id;
    }
    return '';
  }

  /**
   * Cached value of `sysinfo.device_id`  if set.
   */
  get name(): string {
    if (this.getSysInfo()) {
      return Buffer.from(this.getSysInfo().nickname, 'base64').toString('utf8');
    }
    return '';
  }

  get model(): string {
    if (this.getSysInfo()) {
      return this.getSysInfo().model;
    }
    return '';
  }

  get serialNumber(): string {
    if (this.getSysInfo()) {
      return this.getSysInfo().hw_id;
    }
    return '';
  }

  get firmwareRevision(): string {
    if (this.getSysInfo()) {
      return this.getSysInfo().fw_ver;
    }
    return '';
  }

  get hardwareRevision(): string {
    if (this.getSysInfo()) {
      return this.getSysInfo().hw_ver;
    }
    return '';
  }

  protected setSysInfo(sysInfo: PlugSysinfo) {
    this._plugSysInfo = sysInfo;
    this._plugSysInfo.last_update = Date.now();
  }

  public getSysInfo(): PlugSysinfo {
    return this._plugSysInfo;
  }

  protected handleError(errorCode: number | string, line: string): boolean {
    //@ts-ignore
    const errorMessage = this.ERROR_CODES[errorCode];
    if (typeof errorCode === 'number' && errorCode === 0) {
      // success — not an error
      return true;
    } else if (typeof errorCode === 'number' && errorCode === 1003) {
      this.log.info('Trying KLAP Auth');
      this.is_klap = true;
    } else {
      const msg = line + ' Error Code: ' + errorCode + ', ' + errorMessage + ' ' + this.ip;
      if (msg === this._lastErrorMessage) {
        this.log.debug(msg);
      } else {
        this._lastErrorMessage = msg;
        this.log.error(msg);
      }
    }
    return false;
  }

  protected async sendRequest(payload: string): Promise<boolean> {
    if (this.tpapCipher && this.tpapCipher.isReady) {
      return this.handleTpapRequest(payload)
        .then((result: any) => {
          return result ? true : false;
        })
        .catch((error: any) => {
          if (error.message && error.message.indexOf('9999') > 0 && this._reconnect_counter <= 3) {
            return this.tpapReconnect().then(() => {
              return this.handleTpapRequest(payload).then((result: any) => {
                return result ? true : false;
              });
            });
          }
          this._reconnect_counter = 0;
          return false;
        });
    } else if (this.tpLinkCipher) {
      return this.handleRequest(payload)
        .then((result) => {
          return result ? true : false;
        })
        .catch((error) => {
          if (error.message && error.message.indexOf('9999') > 0 && this._reconnect_counter <= 3) {
            return this.reconnect().then(() => {
              return this.handleRequest(payload).then((result) => {
                return result ? true : false;
              });
            });
          }
          this._reconnect_counter = 0;
          return false;
        });
    } else {
      return this.handleKlapRequest(payload)
        .then((result) => {
          return result;
        })
        .catch((error) => {
          if (error.message && error.message.indexOf('9999') > 0 && this._reconnect_counter <= 3) {
            return this.newReconnect().then(() => {
              return this.handleKlapRequest(payload).then((result) => {
                return result ? true : false;
              });
            });
          }
          this._reconnect_counter = 0;
          return false;
        });
    }
  }

  protected handleRequest(payload: string): Promise<any> {
    const URL = 'http://' + this.ip + '/app?token=' + this.token;

    const headers = {
      Cookie: this.cookie,
      Connection: 'Keep-Alive',
    };

    if (this.tpLinkCipher) {
      const encryptedPayload = this.tpLinkCipher.encrypt(payload);

      const securePassthroughPayload = {
        method: 'securePassthrough',
        params: {
          request: encryptedPayload,
        },
      };

      const config = {
        headers: headers,
        timeout: this._timeout * 1000,
      };

      return this._axios
        .post(URL, securePassthroughPayload, config)
        .then((res: AxiosResponse) => {
          if (res.data.error_code) {
            if (res.data.error_code === '9999' || (res.data.error_code === 9999 && this._reconnect_counter <= 3)) {
              //@ts-ignore
              this.log.error(' Error Code: ' + res.data.error_code + ', ' + this.ERROR_CODES[res.data.error_code]);
              this.log.debug('Trying to reconnect...');
              return this.reconnect().then(() => {
                return this.getDeviceInfo();
              });
            }
            this._reconnect_counter = 0;
            return this.handleError(res.data.error_code, '357');
          }

          const decryptedResponse = this.tpLinkCipher.decrypt(res.data.result.response);
          try {
            const response = JSON.parse(decryptedResponse);
            this.log.debug(response);
            if (response.error_code !== 0) {
              return this.handleError(response.error_code, '364');
            }
            return response;
          } catch (error) {
            return this.handleError(JSON.parse(decryptedResponse).error_code, '368');
          }
        })
        .catch((error: Error) => {
          return this.handleError(error.message, '656');
        });
    }
    return new Promise<true>((resolve, reject) => {
      reject();
    });
  }

  protected handleKlapRequest(payload: string): Promise<any> {
    if (this.newTpLinkCipher) {
      const data = this.newTpLinkCipher.encrypt(payload);

      return this.raw_request('request', data.encryptedPayload, 'arraybuffer', { seq: data.seq.toString() })
        .then((res) => {
          if (!res || !Buffer.isBuffer(res)) {
            // axios error objects may contain encrypted response data
            const responseData = res?.response?.data;
            if (responseData && Buffer.isBuffer(responseData)) {
              try {
                const decrypted = JSON.parse(this.newTpLinkCipher.decrypt(responseData));
                this.log.debug('KLAP HTTP error but decrypted device response: ' + JSON.stringify(decrypted));
                return this.handleError(decrypted.error_code || res.status || res.message, '671d');
              } catch (e: any) {
                this.log.debug('KLAP could not decrypt error response: ' + e.message);
              }
            }
            this.log.debug('KLAP request returned non-buffer response: ' + typeof res);
            return false;
          }
          return JSON.parse(this.newTpLinkCipher.decrypt(res));
        })
        .catch((error: Error) => {
          return this.handleError(error.message, '671');
        });
    }
    return new Promise<true>((resolve, reject) => {
      reject();
    });
  }

  protected async handleTpapRequest(payload: string): Promise<any> {
    if (!this.tpapCipher || !this.tpapCipher.isReady) {
      throw new Error('TPAP cipher not ready');
    }
    const encrypted = this.tpapCipher.encrypt(payload);
    const url = this.tpapCipher.sessionUrl;

    const config = {
      timeout: this._timeout * 1000,
      responseType: 'arraybuffer' as const,
      headers: {
        'Content-Type': 'application/octet-stream',
        Connection: 'Keep-Alive',
      },
    };

    const res = await this._axios.post(url, encrypted.data, config);
    const responseData = Buffer.isBuffer(res.data) ? res.data : Buffer.from(res.data);
    const decrypted = this.tpapCipher.decrypt(responseData);
    return JSON.parse(decrypted);
  }

  protected async reconnect(): Promise<void> {
    this._reconnect_counter++;
    return this.handshake().then(() => {
      this.login().then(() => {
        return;
      });
    });
  }

  protected async newReconnect(): Promise<void> {
    this._reconnect_counter++;
    return this.handshake_new().then(() => {
      return;
    });
  }

  protected async tpapReconnect(): Promise<void> {
    this._reconnect_counter++;
    return this.handshake_tpap();
  }

  // Generic command method - returns full response
  async sendCommand(method: string, params?: Record<string, any>): Promise<any> {
    const payload = JSON.stringify({
      method,
      params: params || {},
      terminalUUID: this.terminalUUID,
      requestTimeMils: Math.round(Date.now() * 1000),
    });
    const handler = this.tpapCipher && this.tpapCipher.isReady
      ? () => this.handleTpapRequest(payload)
      : this.tpLinkCipher
        ? () => this.handleRequest(payload)
        : () => this.handleKlapRequest(payload);
    const doReconnect = this.tpapCipher && this.tpapCipher.isReady
      ? () => this.tpapReconnect()
      : this.tpLinkCipher
        ? () => this.reconnect()
        : () => this.newReconnect();
    try {
      const response = await handler();
      return response?.result ?? response;
    } catch (error: any) {
      const shouldReconnect =
        error.message?.includes('9999') ||
        error.response?.status === 401 ||
        error.message?.includes('TPAP cipher not ready');
      if (shouldReconnect && this._reconnect_counter <= 3) {
        await doReconnect();
        const response = await handler();
        return response?.result ?? response;
      }
      this._reconnect_counter = 0;
      throw error;
    }
  }

  // --- Plug features ---

  async setLedEnabled(enabled: boolean): Promise<any> {
    return this.sendCommand('set_led_info', { led_rule: enabled ? 'always' : 'never' });
  }

  async getLedInfo(): Promise<any> {
    return this.sendCommand('get_led_info');
  }

  async setAutoOff(enabled: boolean): Promise<any> {
    return this.sendCommand('set_auto_off_config', { enable: enabled });
  }

  async setAutoOffDelay(minutes: number): Promise<any> {
    return this.sendCommand('set_auto_off_config', { enable: true, delay_min: minutes });
  }

  async setChildProtection(enabled: boolean): Promise<any> {
    return this.sendCommand('set_child_protection', { enable: enabled });
  }

  async setPowerProtection(enabled: boolean): Promise<any> {
    return this.sendCommand('set_protection_power', { enabled });
  }

  async setPowerProtectionThreshold(watts: number): Promise<any> {
    return this.sendCommand('set_protection_power', { enabled: true, protection_power: watts });
  }

  async getEmeterData(): Promise<any> {
    return this.sendCommand('get_emeter_data');
  }

  // --- Light features ---

  async setLightEffect(effectId: string): Promise<any> {
    if (effectId === 'off' || effectId === 'Off') {
      return this.sendCommand('set_dynamic_light_effect_rule_enable', { enable: false });
    }
    return this.sendCommand('set_dynamic_light_effect_rule_enable', { enable: true, id: effectId });
  }

  async setGradualOnOff(enabled: boolean): Promise<any> {
    return this.sendCommand('set_on_off_gradually_info', {
      on_state: { enable: enabled },
      off_state: { enable: enabled },
    });
  }

  // --- Fan features ---

  async setFanSpeedLevel(level: number): Promise<any> {
    return this.sendCommand('set_device_info', { device_on: level > 0, fan_speed_level: level });
  }

  async setFanSleepMode(enabled: boolean): Promise<any> {
    return this.sendCommand('set_device_info', { fan_sleep_mode_on: enabled });
  }

  // --- Hub alarm ---

  async playAlarm(): Promise<any> {
    return this.sendCommand('play_alarm');
  }

  async stopAlarm(): Promise<any> {
    return this.sendCommand('stop_alarm');
  }

  async setAlarmVolume(volume: string): Promise<any> {
    return this.sendCommand('set_alarm_configure', { volume });
  }

  async setAlarmDuration(duration: number): Promise<any> {
    return this.sendCommand('set_alarm_configure', { duration });
  }

  // --- Thermostat ---

  async setTargetTemperature(temp: number): Promise<any> {
    return this.sendCommand('set_device_info', { target_temp: temp, frost_protection_on: false });
  }

  async setTemperatureOffset(offset: number): Promise<any> {
    return this.sendCommand('set_device_info', { temp_offset: offset });
  }

  async setFrostProtection(enabled: boolean): Promise<any> {
    return this.sendCommand('set_device_info', { frost_protection_on: enabled });
  }

  // --- Firmware ---

  async setAutoUpdate(enabled: boolean): Promise<any> {
    return this.sendCommand('set_auto_update_info', { enable: enabled });
  }

  // --- Generic child device command ---

  async sendChildCommand(deviceId: string, method: string, params?: Record<string, any>): Promise<any> {
    return this.sendCommand('controlChild', {
      childControl: {
        device_id: deviceId,
        request_data: {
          method,
          params: params || {},
          requestTimeMils: Math.round(Date.now() * 1000),
          terminalUUID: this.terminalUUID,
        },
      },
    });
  }

  private reAuthenticate(): void {
    this.log.debug('Reauthenticating ' + this.ip);
    if (this.is_tpap) {
      this.handshake_tpap()
        .then(() => {
          this.log.info('TPAP Authenticated successfully ' + this.ip);
        })
        .catch(() => {
          this.log.debug('TPAP Handshake failed ' + this.ip);
        });
    } else if (this.is_klap) {
      this.handshake_new()
        .then(() => {
          this.log.info('KLAP Authenticated successfully ' + this.ip);
        })
        .catch(() => {
          this.log.debug('KLAP Handshake failed ' + this.ip);
          this.is_klap = false;
        });
    } else {
      this.handshake()
        .then(() => {
          this.login()
            .then(() => {
              this.log.info('Authenticated successfully ' + this.ip);
            })
            .catch(() => {
              this.log.debug('Login failed ' + this.ip);
            });
        })
        .catch(() => {
          this.log.debug('Old handshake failed ' + this.ip);
        });
    }
  }
}
