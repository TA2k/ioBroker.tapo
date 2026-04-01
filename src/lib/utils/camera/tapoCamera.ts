// import https, { Agent } from "https";
import crypto from 'crypto';
import { OnvifCamera } from './onvifCamera';
import type {
  TAPOBasicInfo,
  TAPOCameraEncryptedRequest,
  TAPOCameraEncryptedResponse,
  TAPOCameraLoginResponse,
  TAPOCameraRefreshStokResponse,
  TAPOCameraRequest,
  TAPOCameraResponse,
  TAPOCameraResponseDeviceInfo,
  TAPOCameraSetRequest,
} from './types/tapo';

const MAX_LOGIN_RETRIES = 3;
const AES_BLOCK_SIZE = 16;

import { Agent } from 'undici';

const ERROR_CODES_MAP = {
  '-40401': 'Invalid stok value',
  '-40210': 'Function not supported',
  '-64303': 'Action cannot be done while camera is in patrol mode.',
  '-64324': 'Privacy mode is ON, not able to execute',
  '-64302': 'Preset ID not found',
  '-64321': 'Preset ID was deleted so no longer exists',
  '-40106': 'Parameter to get/do does not exist',
  '-40105': 'Method does not exist',
  '-40101': 'Parameter to set does not exist',
  '-40209': 'Invalid login credentials',
  '-64304': 'Maximum Pan/Tilt range reached',
  '-71103': 'User ID is not authorized',
};

export type Status = {
  eyes: boolean | undefined;
  alarm: boolean | undefined;
  notifications: boolean | undefined;
  motionDetection: boolean | undefined;
  led: boolean | undefined;
  autoTrack: boolean | undefined;
  personDetection: boolean | undefined;
  vehicleDetection: boolean | undefined;
  petDetection: boolean | undefined;
  babyCryDetection: boolean | undefined;
  barkDetection: boolean | undefined;
  meowDetection: boolean | undefined;
  glassBreakDetection: boolean | undefined;
  tamperDetection: boolean | undefined;
  imageFlip: boolean | undefined;
  ldc: boolean | undefined;
  recordAudio: boolean | undefined;
  autoUpgrade: boolean | undefined;
};
type CameraConfig = {
  name: string;
  ipAddress: string;
  username?: string;
  password: string;
  streamUser: string;
  streamPassword: string;

  pullInterval?: number;
  disableStreaming?: boolean;
  disableEyesToggleAccessory?: boolean;
  disableAlarmToggleAccessory?: boolean;
  disableNotificationsToggleAccessory?: boolean;
  disableMotionDetectionToggleAccessory?: boolean;
  disableLEDToggleAccessory?: boolean;

  disableMotionSensorAccessory?: boolean;
  lowQuality?: boolean;

  videoMaxWidth?: number;
  videoMaxHeight?: number;
  videoMaxFPS?: number;
  videoForceMax?: boolean;
  videoMaxBirate?: number;
  videoPacketSize?: number;
  videoCodec?: string;

  eyesToggleAccessoryName?: string;
  alarmToggleAccessoryName?: string;
  notificationsToggleAccessoryName?: string;
  motionDetectionToggleAccessoryName?: string;
  ledToggleAccessoryName?: string;
};
export class TAPOCamera extends OnvifCamera {
  private readonly kStreamPort = 554;
  private readonly fetchAgent: Agent;

  private readonly hashedPassword: string;
  private readonly hashedSha256Password: string;
  private passwordEncryptionMethod: 'md5' | 'sha256' | null = null;

  private isSecureConnectionValue: boolean | null = null;

  private stokPromise: (() => Promise<void>) | undefined;

  private cnonce: string;
  private lsk: Buffer | undefined;
  private ivb: Buffer | undefined;
  private seq: number | undefined;
  private stok: string | undefined;

  constructor(
    protected readonly log: any,
    protected readonly config: CameraConfig,
  ) {
    super(log, config);
    this.fetchAgent = new Agent({
      connectTimeout: 5_000,
      connect: {
        // TAPO devices have self-signed certificates
        rejectUnauthorized: false,
        ciphers: 'ECDHE-RSA-AES128-GCM-SHA256:AES256-GCM-SHA384:AES256-SHA256:AES128-GCM-SHA256:AES128-SHA256:AES256-SHA',
      },
    });

    this.cnonce = this.generateCnonce();

    this.hashedPassword = crypto.createHash('md5').update(config.password).digest('hex').toUpperCase();
    this.hashedSha256Password = crypto.createHash('sha256').update(config.password).digest('hex').toUpperCase();
  }

  private getUsername() {
    return this.config.username || 'admin';
  }

  private getHeaders(): Record<string, string> {
    return {
      Host: `${this.config.ipAddress}`,
      Referer: `https://${this.config.ipAddress}`,
      Accept: 'application/json',
      'Accept-Encoding': 'gzip, deflate',
      'User-Agent': 'Tapo CameraClient Android',
      Connection: 'close',
      requestByApp: 'true',
      'Content-Type': 'application/json; charset=UTF-8',
    };
  }

  private getHashedPassword() {
    if (this.passwordEncryptionMethod === 'md5') {
      return this.hashedPassword;
    } else if (this.passwordEncryptionMethod === 'sha256') {
      return this.hashedSha256Password;
    } else {
      this.log.error('Unknown password encryption method');
    }
  }

  private fetch(url: string, data: RequestInit) {
    return fetch(url, {
      headers: this.getHeaders(),
      // @ts-expect-error Dispatcher type not there
      dispatcher: this.fetchAgent,
      ...data,
    });
  }

  private generateEncryptionToken(tokenType: string, nonce: string): Buffer {
    const hashedKey = crypto
      .createHash('sha256')
      .update(this.cnonce + this.getHashedPassword() + nonce)
      .digest('hex')
      .toUpperCase();
    return crypto
      .createHash('sha256')
      .update(tokenType + this.cnonce + nonce + hashedKey)
      .digest()
      .slice(0, 16);
  }

  getAuthenticatedStreamUrl(lowQuality = false) {
    const prefix = `rtsp://${this.config.streamUser}:${this.config.streamPassword}@${this.config.ipAddress}:${this.kStreamPort}`;
    return lowQuality ? `${prefix}/stream2` : `${prefix}/stream1`;
  }

  private generateCnonce() {
    return crypto.randomBytes(8).toString('hex').toUpperCase();
  }

  private validateDeviceConfirm(nonce: string, deviceConfirm: string) {
    this.passwordEncryptionMethod = null;

    const hashedNoncesWithSHA256 = crypto
      .createHash('sha256')
      .update(this.cnonce + this.hashedSha256Password + nonce)
      .digest('hex')
      .toUpperCase();
    if (deviceConfirm === hashedNoncesWithSHA256 + nonce + this.cnonce) {
      this.passwordEncryptionMethod = 'sha256';
      return true;
    }

    const hashedNoncesWithMD5 = crypto
      .createHash('sha256')
      .update(this.cnonce + this.hashedPassword + nonce)
      .digest('hex')
      .toUpperCase();
    if (deviceConfirm === hashedNoncesWithMD5 + nonce + this.cnonce) {
      this.passwordEncryptionMethod = 'md5';
      return true;
    }

    this.log.debug('Invalid device confirm, expected "sha256" or "md5" to match, but none found', {
      hashedNoncesWithMD5,
      hashedNoncesWithSHA256,
      deviceConfirm,
      nonce,
      cnonce: this,
    });

    return this.passwordEncryptionMethod !== null;
  }

  async refreshStok(loginRetryCount = 0): Promise<void> {
    this.log.debug('refreshStok: Refreshing stok...');

    // Generate fresh cnonce for each handshake attempt (new firmware rejects replayed cnonces)
    this.cnonce = this.generateCnonce();

    const isSecureConnection = await this.isSecureConnection();

    let fetchParams = {};
    if (isSecureConnection) {
      fetchParams = {
        method: 'post',
        body: JSON.stringify({
          method: 'login',
          params: {
            cnonce: this.cnonce,
            encrypt_type: '3',
            username: this.getUsername(),
          },
        }),
      };
    } else {
      fetchParams = {
        method: 'post',
        body: JSON.stringify({
          method: 'login',
          params: {
            username: this.getUsername(),
            password: this.hashedPassword,
            hashed: true,
          },
        }),
      };
    }

    const responseLogin = await this.fetch(`https://${this.config.ipAddress}`, fetchParams).catch((e) => {
      this.log.debug('refreshStok: Error during login', e);
      return null;
    });
    if (!responseLogin) {
      this.log.debug('refreshStok: empty response login, raising exception');
      this.log.error('Empty response login');
      return;
    }
    const responseLoginData = (await responseLogin.json()) as TAPOCameraRefreshStokResponse;

    let response, responseData;

    if (!responseLoginData) {
      this.log.debug('refreshStok: empty response login data, raising exception', responseLogin.status);
      this.log.error('Empty response login data');
    }

    this.log.debug('refreshStok: Login response', responseLogin.status, responseLoginData);

    if (responseLogin.status === 401 && responseLoginData.result?.data?.code === -40411) {
      this.log.debug('refreshStok: invalid credentials, raising exception', responseLogin.status);
      this.log.error('Invalid credentials');
    }

    if (isSecureConnection) {
      const nonce = responseLoginData.result?.data?.nonce;
      const deviceConfirm = responseLoginData.result?.data?.device_confirm;
      if (nonce && deviceConfirm && this.validateDeviceConfirm(nonce, deviceConfirm)) {
        const digestPasswd = crypto
          .createHash('sha256')
          .update(this.getHashedPassword() + this.cnonce + nonce)
          .digest('hex')
          .toUpperCase();

        const digestPasswdFull = Buffer.concat([
          Buffer.from(digestPasswd, 'utf8'),
          Buffer.from(this.cnonce!, 'utf8'),
          Buffer.from(nonce, 'utf8'),
        ]).toString('utf8');

        this.log.debug('refreshStok: sending start_seq request');

        response = await this.fetch(`https://${this.config.ipAddress}`, {
          method: 'POST',
          body: JSON.stringify({
            method: 'login',
            params: {
              cnonce: this.cnonce,
              encrypt_type: '3',
              digest_passwd: digestPasswdFull,
              username: this.getUsername(),
            },
          }),
        });

        responseData = (await response.json()) as TAPOCameraRefreshStokResponse;

        if (!responseData) {
          this.log.debug('refreshStock: empty response start_seq data, raising exception', response.status);
          this.log.error('Empty response start_seq data');
          return;
        }

        this.log.debug('refreshStok: start_seq response', response.status, JSON.stringify(responseData));

        if (responseData.result?.start_seq) {
          if (responseData.result?.user_group !== 'root') {
            this.log.debug('refreshStock: Incorrect user_group detected');

            // # encrypted control via 3rd party account does not seem to be supported
            // # see https://github.com/JurajNyiri/HomeAssistant-Tapo-Control/issues/456
            this.log.error('Incorrect user_group detected');
          }

          this.lsk = this.generateEncryptionToken('lsk', nonce);
          this.ivb = this.generateEncryptionToken('ivb', nonce);
          this.seq = responseData.result.start_seq;
        }
      } else {
        if (
          (responseLoginData.error_code === -40413 || responseLoginData.error_code === -40211) &&
          loginRetryCount < MAX_LOGIN_RETRIES
        ) {
          this.log.debug(
            `refreshStock: Invalid device confirm, retrying: ${loginRetryCount}/${MAX_LOGIN_RETRIES}.`,
            responseLogin.status,
            responseLoginData,
          );
          // Reset secure connection cache so next retry re-probes
          this.isSecureConnectionValue = null;
          return this.refreshStok(loginRetryCount + 1);
        }

        this.log.debug(
          'refreshStock: Invalid device confirm and loginRetryCount exhausted, raising exception',
          loginRetryCount,
          responseLoginData,
        );
        this.isSecureConnectionValue = null;
        this.log.error('Invalid device confirm. Please activate 3rd Patry support in the TP App under TP Labor -> 3rd Party Control');
        return;
      }
    } else {
      this.passwordEncryptionMethod = 'md5';
      response = responseLogin;
      responseData = responseLoginData;
    }

    if (responseData.result?.data?.sec_left && responseData.result.data.sec_left > 0) {
      this.log.debug('refreshStok: temporary suspension', responseData);

      this.log.error(`Temporary Suspension: Try again in ${responseData.result.data.sec_left} seconds`);
    }
    if (responseData && responseData.result && responseData.result.responses && responseData.result.responses[0].error_code !== 0) {
      this.log.debug(
        `API request failed with specific error code ${responseData.result.responses[0].error_code}: ${responseData.result.responses[0].error_message}`,
      );
    }

    if (responseData?.data?.code === -40404 && responseData?.data?.sec_left && responseData.data.sec_left > 0) {
      this.log.debug('refreshStok: temporary suspension', responseData);

      this.log.error(`refreshStok: Temporary Suspension: Try again in ${responseData.data.sec_left} seconds`);
    }

    if (responseData?.result?.stok) {
      this.stok = responseData.result.stok;
      this.log.debug('refreshStok: Success in obtaining STOK', this.stok);
      return;
    }

    if (
      (responseData?.error_code === -40413 || responseData?.error_code === -40211) &&
      loginRetryCount < MAX_LOGIN_RETRIES
    ) {
      this.log.debug(
        `refreshStock: Unexpected response, retrying: ${loginRetryCount}/${MAX_LOGIN_RETRIES}.`,
        response.status,
        responseData,
      );
      this.isSecureConnectionValue = null;
      return this.refreshStok(loginRetryCount + 1);
    }

    this.log.debug('refreshStock: Unexpected end of flow, raising exception');
    this.isSecureConnectionValue = null;
    this.log.error('Invalid authentication data');
  }

  async isSecureConnection() {
    if (this.isSecureConnectionValue === null) {
      this.log.debug('isSecureConnection: Checking secure connection...');

      const response = await this.fetch(`https://${this.config.ipAddress}`, {
        method: 'post',
        headers: this.getHeaders(),
        body: JSON.stringify({
          method: 'login',
          params: {
            encrypt_type: '3',
            username: this.getUsername(),
          },
        }),
      });
      const responseData = (await response.json()) as TAPOCameraLoginResponse;

      this.log.debug('isSecureConnection response', response.status, JSON.stringify(responseData));

      const errorCode = responseData?.error_code;
      const encryptType = String(responseData?.result?.data?.encrypt_type || '');
      const hasNonce = !!responseData?.result?.data?.nonce;

      // -40413 (INVALID_NONCE): standard secure connection indicator
      // -40211 (MISSING_NECESSARY_PARAMS): new firmware secure connection indicator
      // hasNonce: device already returned nonce in probe response
      this.isSecureConnectionValue =
        (errorCode === -40413 && encryptType.includes('3')) || errorCode === -40211 || hasNonce;
    }

    return this.isSecureConnectionValue;
  }

  getStok(loginRetryCount = 0): Promise<string> {
    return new Promise((resolve) => {
      if (this.stok) {
        return resolve(this.stok);
      }

      if (!this.stokPromise) {
        this.stokPromise = () => this.refreshStok(loginRetryCount);
      }

      this.stokPromise()
        .then(() => {
          if (!this.stok) {
            this.log.error('STOK not found');
          }
          resolve(this.stok!);
        })
        .finally(() => {
          this.stokPromise = undefined;
        });
    });
  }

  private async getAuthenticatedAPIURL(loginRetryCount = 0) {
    const token = await this.getStok(loginRetryCount);
    return `https://${this.config.ipAddress}/stok=${token}/ds`;
  }

  encryptRequest(request: string) {
    const cipher = crypto.createCipheriv('aes-128-cbc', this.lsk!, this.ivb!);
    let ct_bytes = cipher.update(this.encryptPad(request, AES_BLOCK_SIZE), 'utf-8', 'hex');
    ct_bytes += cipher.final('hex');
    return Buffer.from(ct_bytes, 'hex');
  }

  private encryptPad(text: string, blocksize: number) {
    const padSize = blocksize - (text.length % blocksize);
    const padding = String.fromCharCode(padSize).repeat(padSize);
    return text + padding;
  }

  private decryptResponse(response: string): string {
    const decipher = crypto.createDecipheriv('aes-128-cbc', this.lsk!, this.ivb!);
    let decrypted = decipher.update(response, 'base64', 'utf-8');
    decrypted += decipher.final('utf-8');
    return this.encryptUnpad(decrypted, AES_BLOCK_SIZE);
  }

  private encryptUnpad(text: string, blockSize: number): string {
    const paddingLength = Number(text[text.length - 1]) || 0;
    if (paddingLength > blockSize || paddingLength > text.length) {
      this.log.error('Invalid padding');
    }
    for (let i = text.length - paddingLength; i < text.length; i++) {
      if (text.charCodeAt(i) !== paddingLength) {
        this.log.error('Invalid padding');
      }
    }
    return text.slice(0, text.length - paddingLength).toString();
  }

  private getTapoTag(request: TAPOCameraEncryptedRequest) {
    const tag = crypto
      .createHash('sha256')
      .update(this.getHashedPassword() + this.cnonce)
      .digest('hex')
      .toUpperCase();
    return crypto
      .createHash('sha256')
      .update(tag + JSON.stringify(request) + this.seq!.toString())
      .digest('hex')
      .toUpperCase();
  }

  private pendingAPIRequests: Map<string, Promise<TAPOCameraResponse>> = new Map();

  private async apiRequest(req: TAPOCameraRequest, loginRetryCount = 0): Promise<TAPOCameraResponse> {
    const reqJson = JSON.stringify(req);

    if (this.pendingAPIRequests.has(reqJson)) {
      this.log.debug('API request already pending', reqJson);
      return this.pendingAPIRequests.get(reqJson) as Promise<TAPOCameraResponse>;
    } else {
      this.log.debug('New API request', reqJson);
    }

    this.pendingAPIRequests.set(
      reqJson,
      (async () => {
        try {
          const isSecureConnection = await this.isSecureConnection();
          const url = await this.getAuthenticatedAPIURL(loginRetryCount);

          const fetchParams: RequestInit = {
            method: 'post',
          };

          if (this.seq && isSecureConnection) {
            const encryptedRequest: TAPOCameraEncryptedRequest = {
              method: 'securePassthrough',
              params: {
                request: Buffer.from(this.encryptRequest(JSON.stringify(req))).toString('base64'),
              },
            };
            fetchParams.headers = {
              ...this.getHeaders(),
              Tapo_tag: this.getTapoTag(encryptedRequest),
              Seq: this.seq.toString(),
            };
            fetchParams.body = JSON.stringify(encryptedRequest);
            this.seq += 1;
          } else {
            fetchParams.body = JSON.stringify(req);
          }

          const response = await this.fetch(url, fetchParams).catch((e) => {
            this.log.debug('Error during camera fetch', e);
            return;
          });
          if (!response) {
            this.log.debug('API request failed, empty response');
            return {} as TAPOCameraResponse;
          }
          const responseDataTmp = await response.json();

          // Apparently the Tapo C200 returns 500 on successful requests,
          // but it's indicating an expiring token, therefore refresh the token next time
          if (isSecureConnection && response.status === 500) {
            this.log.debug('Stok expired, reauthenticating on next request, setting STOK to undefined');
            this.stok = undefined;
          }

          let responseData: TAPOCameraResponse | null = null;

          if (isSecureConnection) {
            const encryptedResponse = responseDataTmp as TAPOCameraEncryptedResponse;
            if (encryptedResponse?.result?.response) {
              const decryptedResponse = this.decryptResponse(encryptedResponse.result.response);
              responseData = JSON.parse(decryptedResponse) as TAPOCameraResponse;
            }
          } else {
            responseData = responseDataTmp as TAPOCameraResponse;
          }

          this.log.debug('API response', response.status, JSON.stringify(responseData));

          // Log error codes
          if (responseData && responseData.error_code !== 0) {
            const errorCode = String(responseData.error_code);
            const errorMessage =
              errorCode in ERROR_CODES_MAP ? ERROR_CODES_MAP[errorCode as keyof typeof ERROR_CODES_MAP] : 'Unknown error';
            this.log.debug(`API request failed with specific error code ${errorCode}: ${errorMessage}`);
          }

          if (!responseData || responseData.error_code === -40401 || responseData.error_code === -1) {
            this.log.debug('API request failed', responseData);
            this.stok = undefined;
            return {} as TAPOCameraResponse;
            //  return this.apiRequest(req, loginRetryCount + 1);
          }

          // Success
          return responseData;
        } finally {
          this.pendingAPIRequests.delete(reqJson);
        }
      })(),
    );

    return this.pendingAPIRequests.get(reqJson) as Promise<TAPOCameraResponse>;
  }

  static SERVICE_MAP: Record<keyof Status, (value: boolean) => TAPOCameraSetRequest> = {
    eyes: (value) => ({
      method: 'setLensMaskConfig',
      params: {
        lens_mask: {
          lens_mask_info: {
            // Watch out for the inversion
            enabled: value ? 'off' : 'on',
          },
        },
      },
    }),
    alarm: (value) => ({
      method: 'setAlertConfig',
      params: {
        msg_alarm: {
          chn1_msg_alarm_info: {
            enabled: value ? 'on' : 'off',
          },
        },
      },
    }),
    notifications: (value) => ({
      method: 'setMsgPushConfig',
      params: {
        msg_push: {
          chn1_msg_push_info: {
            notification_enabled: value ? 'on' : 'off',
            rich_notification_enabled: value ? 'on' : 'off',
          },
        },
      },
    }),
    motionDetection: (value) => ({
      method: 'setDetectionConfig',
      params: {
        motion_detection: {
          motion_det: {
            enabled: value ? 'on' : 'off',
          },
        },
      },
    }),
    led: (value) => ({
      method: 'setLedStatus',
      params: {
        led: {
          config: {
            enabled: value ? 'on' : 'off',
          },
        },
      },
    }),
    autoTrack: (value) => ({
      method: 'setTargetTrackConfig',
      params: {
        target_track: {
          target_track_info: {
            enabled: value ? 'on' : 'off',
          },
        },
      },
    }),
    personDetection: (value) => ({
      method: 'setPersonDetectionConfig',
      params: {
        people_detection: {
          detection: {
            enabled: value ? 'on' : 'off',
          },
        },
      },
    }),
    vehicleDetection: (value) => ({
      method: 'setVehicleDetectionConfig',
      params: {
        vehicle_detection: {
          detection: {
            enabled: value ? 'on' : 'off',
          },
        },
      },
    }),
    petDetection: (value) => ({
      method: 'setPetDetectionConfig',
      params: {
        pet_detection: {
          detection: {
            enabled: value ? 'on' : 'off',
          },
        },
      },
    }),
    babyCryDetection: (value) => ({
      method: 'setBCDConfig',
      params: {
        sound_detection: {
          bcd: {
            enabled: value ? 'on' : 'off',
          },
        },
      },
    }),
    barkDetection: (value) => ({
      method: 'setBarkDetectionConfig',
      params: {
        bark_detection: {
          detection: {
            enabled: value ? 'on' : 'off',
          },
        },
      },
    }),
    meowDetection: (value) => ({
      method: 'setMeowDetectionConfig',
      params: {
        meow_detection: {
          detection: {
            enabled: value ? 'on' : 'off',
          },
        },
      },
    }),
    glassBreakDetection: (value) => ({
      method: 'setGlassDetectionConfig',
      params: {
        glass_detection: {
          detection: {
            enabled: value ? 'on' : 'off',
          },
        },
      },
    }),
    tamperDetection: (value) => ({
      method: 'setTamperDetectionConfig',
      params: {
        tamper_detection: {
          tamper_det: {
            enabled: value ? 'on' : 'off',
          },
        },
      },
    }),
    imageFlip: (value) => ({
      method: 'setLdc',
      params: {
        image: {
          switch: {
            flip_type: value ? 'center' : 'off',
          },
        },
      },
    }),
    ldc: (value) => ({
      method: 'setLdc',
      params: {
        image: {
          switch: {
            ldc: value ? 'on' : 'off',
          },
        },
      },
    }),
    recordAudio: (value) => ({
      method: 'setRecordAudio',
      params: {
        audio_config: {
          record_audio: {
            enabled: value ? 'on' : 'off',
          },
        },
      },
    }),
    autoUpgrade: (value) => ({
      method: 'setFirmwareAutoUpgradeConfig',
      params: {
        auto_upgrade: {
          common: {
            enabled: value ? 'on' : 'off',
          },
        },
      },
    }),
  };

  async setStatus(service: keyof Status, value: boolean) {
    const responseData = await this.apiRequest({
      method: 'multipleRequest',
      params: {
        requests: [TAPOCamera.SERVICE_MAP[service](value)],
      },
    });

    if (responseData.error_code !== 0) {
      this.log.error(`Failed to perform ${service} action`);
    }

    const method = TAPOCamera.SERVICE_MAP[service](value).method;
    const operation = responseData.result.responses.find((e) => e.method === method);
    if (operation?.error_code !== 0) {
      this.log.error(`Failed to perform ${service} action`);
    }

    return operation?.result;
  }

  async getBasicInfo(): Promise<TAPOBasicInfo> {
    const responseData = await this.apiRequest({
      method: 'multipleRequest',
      params: {
        requests: [
          {
            method: 'getDeviceInfo',
            params: {
              device_info: {
                name: ['basic_info'],
              },
            },
          },
        ],
      },
    });

    const info = responseData.result.responses[0] as TAPOCameraResponseDeviceInfo;
    return info.result.device_info.basic_info;
  }

  async getStatus(): Promise<Status> {
    const responseData = await this.apiRequest({
      method: 'multipleRequest',
      params: {
        requests: [
          { method: 'getAlertConfig', params: { msg_alarm: { name: 'chn1_msg_alarm_info' } } },
          { method: 'getLensMaskConfig', params: { lens_mask: { name: 'lens_mask_info' } } },
          { method: 'getMsgPushConfig', params: { msg_push: { name: 'chn1_msg_push_info' } } },
          { method: 'getDetectionConfig', params: { motion_detection: { name: 'motion_det' } } },
          { method: 'getLedStatus', params: { led: { name: 'config' } } },
          { method: 'getTargetTrackConfig', params: { target_track: { name: ['target_track_info'] } } },
          { method: 'getPersonDetectionConfig', params: { people_detection: { name: ['detection'] } } },
          { method: 'getVehicleDetectionConfig', params: { vehicle_detection: { name: ['detection'] } } },
          { method: 'getPetDetectionConfig', params: { pet_detection: { name: ['detection'] } } },
          { method: 'getBCDConfig', params: { sound_detection: { name: ['bcd'] } } },
          { method: 'getBarkDetectionConfig', params: { bark_detection: { name: ['detection'] } } },
          { method: 'getMeowDetectionConfig', params: { meow_detection: { name: ['detection'] } } },
          { method: 'getGlassDetectionConfig', params: { glass_detection: { name: ['detection'] } } },
          { method: 'getTamperDetectionConfig', params: { tamper_detection: { name: ['tamper_det'] } } },
          { method: 'getRotationStatus', params: { image: { name: ['switch'] } } },
          { method: 'getLdc', params: { image: { name: ['switch'] } } },
          { method: 'getAudioConfig', params: { audio_config: { name: ['record_audio'] } } },
          { method: 'getFirmwareAutoUpgradeConfig', params: { auto_upgrade: { name: ['common'] } } },
        ],
      },
    });

    if (!responseData || !responseData.result || !responseData.result.responses) {
      this.log.error('No response data found');
      return {
        alarm: undefined,
        eyes: undefined,
        notifications: undefined,
        motionDetection: undefined,
        led: undefined,
        autoTrack: undefined,
        personDetection: undefined,
        vehicleDetection: undefined,
        petDetection: undefined,
        babyCryDetection: undefined,
        barkDetection: undefined,
        meowDetection: undefined,
        glassBreakDetection: undefined,
        tamperDetection: undefined,
        imageFlip: undefined,
        ldc: undefined,
        recordAudio: undefined,
        autoUpgrade: undefined,
      };
    }
    const ops = responseData.result.responses;
    const find = (m: string) => ops.find((r: any) => r.method === m);

    const alert = find('getAlertConfig');
    const lensMask = find('getLensMaskConfig');
    const notifications = find('getMsgPushConfig');
    const motionDetection = find('getDetectionConfig');
    const led = find('getLedStatus');
    const autoTrack = find('getTargetTrackConfig');
    const personDet = find('getPersonDetectionConfig');
    const vehicleDet = find('getVehicleDetectionConfig');
    const petDet = find('getPetDetectionConfig');
    const babyCry = find('getBCDConfig');
    const bark = find('getBarkDetectionConfig');
    const meow = find('getMeowDetectionConfig');
    const glass = find('getGlassDetectionConfig');
    const tamper = find('getTamperDetectionConfig');
    const rotation = find('getRotationStatus');
    const ldcResp = find('getLdc');
    const audio = find('getAudioConfig');
    const autoUpg = find('getFirmwareAutoUpgradeConfig');

    return {
      alarm: alert?.result?.msg_alarm?.chn1_msg_alarm_info?.enabled === 'on' ? true : alert ? false : undefined,
      eyes: lensMask?.result?.lens_mask?.lens_mask_info?.enabled === 'off' ? true : lensMask ? false : undefined,
      notifications:
        notifications?.result?.msg_push?.chn1_msg_push_info?.notification_enabled === 'on'
          ? true
          : notifications
            ? false
            : undefined,
      motionDetection:
        motionDetection?.result?.motion_detection?.motion_det?.enabled === 'on' ? true : motionDetection ? false : undefined,
      led: led?.result?.led?.config?.enabled === 'on' ? true : led ? false : undefined,
      autoTrack:
        autoTrack?.result?.target_track?.target_track_info?.enabled === 'on' ? true : autoTrack ? false : undefined,
      personDetection:
        personDet?.result?.people_detection?.detection?.enabled === 'on' ? true : personDet ? false : undefined,
      vehicleDetection:
        vehicleDet?.result?.vehicle_detection?.detection?.enabled === 'on' ? true : vehicleDet ? false : undefined,
      petDetection: petDet?.result?.pet_detection?.detection?.enabled === 'on' ? true : petDet ? false : undefined,
      babyCryDetection:
        babyCry?.result?.sound_detection?.bcd?.enabled === 'on' ? true : babyCry ? false : undefined,
      barkDetection: bark?.result?.bark_detection?.detection?.enabled === 'on' ? true : bark ? false : undefined,
      meowDetection: meow?.result?.meow_detection?.detection?.enabled === 'on' ? true : meow ? false : undefined,
      glassBreakDetection:
        glass?.result?.glass_detection?.detection?.enabled === 'on' ? true : glass ? false : undefined,
      tamperDetection:
        tamper?.result?.tamper_detection?.tamper_det?.enabled === 'on' ? true : tamper ? false : undefined,
      imageFlip: rotation?.result?.image?.switch?.flip_type === 'center' ? true : rotation ? false : undefined,
      ldc: ldcResp?.result?.image?.switch?.ldc === 'on' ? true : ldcResp ? false : undefined,
      recordAudio: audio?.result?.audio_config?.record_audio?.enabled === 'on' ? true : audio ? false : undefined,
      autoUpgrade: autoUpg?.result?.auto_upgrade?.common?.enabled === 'on' ? true : autoUpg ? false : undefined,
    };
  }
  async setForceWhitelampState(value: boolean) {
    const json = await this.apiRequest({
      method: 'multipleRequest',
      params: {
        requests: [
          {
            method: 'setForceWhitelampState',
            params: {
              image: {
                switch: {
                  force_wtl_state: value ? 'on' : 'off',
                },
              },
            },
          },
        ],
      },
    });

    return json.error_code !== 0;
  }
  async moveMotorStep(angle: string) {
    angle = angle.toString();
    const json = await this.apiRequest({ method: 'do', motor: { movestep: { direction: angle } } });

    return json.error_code !== 0;
  }
  async moveToPreset(presetId: string) {
    const json = await this.apiRequest({
      method: 'multipleRequest',
      params: { requests: [{ method: 'motorMoveToPreset', params: { goto_preset: { id: presetId } } }] },
    });

    return json.error_code !== 0;
  }

  async moveMotor(x: string, y: string) {
    const json = await this.apiRequest({
      method: 'do',
      motor: { move: { x_coord: x, y_coord: y } },
    });

    return json.error_code !== 0;
  }

  // --- Detection event polling ---

  async getLastAlarmInfo(): Promise<any> {
    const response = await this.apiRequest({
      method: 'multipleRequest',
      params: {
        requests: [{ method: 'getLastAlarmInfo', params: { msg_alarm: { name: ['chn1_msg_alarm_info'] } } }],
      },
    });
    const ops = response?.result?.responses;
    if (!ops?.length) return null;
    return ops[0]?.result?.msg_alarm?.chn1_msg_alarm_info ?? null;
  }

  async getDetectionEvents(startTime?: number, endTime?: number): Promise<any[]> {
    const now = Math.floor(Date.now() / 1000);
    const response = await this.apiRequest({
      method: 'multipleRequest',
      params: {
        requests: [
          {
            method: 'searchDetectionList',
            params: {
              playback: {
                search_detection_list: {
                  start_index: 0,
                  channel: 0,
                  start_time: startTime || now - 600,
                  end_time: endTime || now + 60,
                  end_index: 99,
                },
              },
            },
          },
        ],
      },
    });
    const ops = response?.result?.responses;
    if (!ops?.length) return [];
    return ops[0]?.result?.playback?.search_detection_list ?? [];
  }

  async getAlertEventType(): Promise<any[]> {
    const response = await this.apiRequest({
      method: 'multipleRequest',
      params: {
        requests: [{ method: 'getAlertEventType', params: { msg_alarm: { table: 'msg_alarm_type' } } }],
      },
    });
    const ops = response?.result?.responses;
    if (!ops?.length) return [];
    return ops[0]?.result?.msg_alarm?.msg_alarm_type ?? [];
  }

  // --- Action methods ---

  async calibrateMotor() {
    return this.apiRequest({ method: 'do', motor: { manual_cali: '' } });
  }

  async startManualAlarm() {
    return this.apiRequest({ method: 'do', msg_alarm: { manual_msg_alarm: { action: 'start' } } });
  }

  async stopManualAlarm() {
    return this.apiRequest({ method: 'do', msg_alarm: { manual_msg_alarm: { action: 'stop' } } });
  }

  async reboot() {
    return this.apiRequest({
      method: 'multipleRequest',
      params: { requests: [{ method: 'rebootDevice', params: { system: { reboot: 'null' } } }] },
    });
  }

  async formatSdCard() {
    return this.apiRequest({
      method: 'multipleRequest',
      params: { requests: [{ method: 'formatSdCard', params: { harddisk_manage: { format_hd: '1' } } }] },
    });
  }

  async savePreset(name: string) {
    return this.apiRequest({
      method: 'multipleRequest',
      params: { requests: [{ method: 'addMotorPostion', params: { preset: { set_preset: { name, save_ptz: '1' } } } }] },
    });
  }

  async deletePreset(id: string) {
    return this.apiRequest({
      method: 'multipleRequest',
      params: { requests: [{ method: 'deletePreset', params: { preset: { remove_preset: { id: [id] } } } }] },
    });
  }

  async setCruise(mode: string) {
    if (mode === 'off') {
      return this.apiRequest({ method: 'do', motor: { cruise_stop: {} } });
    }
    return this.apiRequest({ method: 'do', motor: { cruise: { coord: mode } } });
  }

  async setDayNightMode(mode: string) {
    return this.apiRequest({
      method: 'multipleRequest',
      params: {
        requests: [{ method: 'setNightVisionModeConfig', params: { image: { switch: { night_vision_mode: mode } } } }],
      },
    });
  }

  async setLightFrequencyMode(mode: string) {
    return this.apiRequest({
      method: 'multipleRequest',
      params: {
        requests: [{ method: 'setLightFrequencyInfo', params: { image: { common: { light_freq_mode: mode } } } }],
      },
    });
  }

  async setAlarmMode(mode: string) {
    const enabled = mode !== 'off';
    const soundEnabled = mode === 'both' || mode === 'sound';
    const lightEnabled = mode === 'both' || mode === 'light';
    const alarmMode: string[] = [];
    if (soundEnabled) alarmMode.push('sound');
    if (lightEnabled) alarmMode.push('light');

    return this.apiRequest({
      method: 'multipleRequest',
      params: {
        requests: [
          {
            method: 'setAlertConfig',
            params: {
              msg_alarm: {
                chn1_msg_alarm_info: {
                  enabled: enabled ? 'on' : 'off',
                  alarm_mode: alarmMode,
                },
              },
            },
          },
        ],
      },
    });
  }

  async setSpeakerVolume(volume: number) {
    return this.apiRequest({
      method: 'multipleRequest',
      params: { requests: [{ method: 'setSpeakerVolume', params: { audio_config: { speaker: { volume } } } }] },
    });
  }

  async setMicrophoneVolume(volume: number) {
    return this.apiRequest({
      method: 'multipleRequest',
      params: { requests: [{ method: 'setMicrophoneVolume', params: { audio_config: { microphone: { volume } } } }] },
    });
  }

  async setMotionDetectionSensitivity(sensitivity: string) {
    return this.apiRequest({
      method: 'multipleRequest',
      params: {
        requests: [
          { method: 'setDetectionConfig', params: { motion_detection: { motion_det: { sensitivity } } } },
        ],
      },
    });
  }

  async setPersonDetectionSensitivity(sensitivity: string) {
    return this.apiRequest({
      method: 'multipleRequest',
      params: {
        requests: [
          { method: 'setPersonDetectionConfig', params: { people_detection: { detection: { sensitivity } } } },
        ],
      },
    });
  }

  async setCoverConfig(value: boolean) {
    return this.apiRequest({
      method: 'multipleRequest',
      params: {
        requests: [{ method: 'setCoverConfig', params: { cover: { cover: { enabled: value ? 'on' : 'off' } } } }],
      },
    });
  }

  async setHDR(value: boolean) {
    return this.apiRequest({
      method: 'multipleRequest',
      params: {
        requests: [{ method: 'setHDR', params: { video: { set_hdr: { hdr: value ? 1 : 0, secname: 'main' } } } }],
      },
    });
  }

  async setRecordPlan(value: boolean) {
    return this.apiRequest({
      method: 'multipleRequest',
      params: {
        requests: [{ method: 'setRecordPlan', params: { record_plan: { chn1_channel: { enabled: value ? 'on' : 'off' } } } }],
      },
    });
  }

  async setOsd(label: string) {
    return this.apiRequest({
      method: 'multipleRequest',
      params: {
        requests: [
          {
            method: 'set',
            params: {
              OSD: {
                label_info_1: { enabled: label ? 'on' : 'off', text: label || '' },
              },
            },
          },
        ],
      },
    });
  }
}
