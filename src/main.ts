/*
 * Created with @iobroker/create-adapter v2.1.1
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
import * as utils from "@iobroker/adapter-core";
import axios, { AxiosInstance } from "axios";
import crypto from "crypto";
import https from "https";
import { v4 as uuidv4 } from "uuid";
import Json2iob from "json2iob";
import { TAPOCamera } from "./lib/utils/camera/tapoCamera";
import L510E from "./lib/utils/l510e";
import L520E from "./lib/utils/l520e";
import L530 from "./lib/utils/l530";
import P100 from "./lib/utils/p100";
import P110 from "./lib/utils/p110";
class Tapo extends utils.Adapter {
  private devices: { [key: string]: any };
  private deviceObjects: { [key: string]: any };
  private json2iob: Json2iob;
  private secret: Buffer;
  private requestClient: AxiosInstance;
  updateInterval: any = null;
  reLoginTimeout: any = null;
  refreshTokenTimeout: any = null;
  session: any = {};
  refreshTimeout: any;
  refreshTokenInterval: any;
  private firstStart: boolean = true;
  private lastBatteryDeviceUpdateTimestamp: number = 0;

  termId: any;
  public constructor(options: Partial<utils.AdapterOptions> = {}) {
    super({
      ...options,
      name: "tapo",
    });
    this.on("ready", this.onReady.bind(this));
    this.on("stateChange", this.onStateChange.bind(this));
    this.on("unload", this.onUnload.bind(this));
    this.devices = {};
    this.deviceObjects = {};
    this.json2iob = new Json2iob(this);
    this.requestClient = axios.create({
      httpsAgent: new https.Agent({
        rejectUnauthorized: false,
        secureOptions: crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT,
      }),
    });
    this.secret = Buffer.from([
      54, 101, 100, 55, 100, 57, 55, 102, 51, 101, 55, 51, 52, 54, 55, 102, 56, 97, 53, 98, 97, 98, 57, 48, 98, 53, 55, 55, 98, 97, 52, 99,
    ]);
  }

  /**
   * Is called when databases are connected and adapter received configuration.
   */
  private async onReady(): Promise<void> {
    this.setState("info.connection", false, true);
    if (this.config.interval < 0.5) {
      this.log.info("Set interval to minimum 0.5");
      this.config.interval = 0.5;
    }
    if (!this.config.username || !this.config.password) {
      this.log.error("Please set username and password in the instance settings");
      return;
    }

    this.updateInterval = null;
    this.reLoginTimeout = null;
    this.refreshTokenTimeout = null;
    this.session = {};
    this.subscribeStates("*");

    const termIdState = await this.getStateAsync("termId");
    if (termIdState && termIdState.val) {
      this.termId = termIdState.val;
    } else {
      await this.setObjectNotExistsAsync("termId", {
        type: "state",
        common: {
          name: "Terminal ID",
          write: false,
          read: true,
          type: "string",
          role: "text",
        },
        native: {},
      });
      this.termId = uuidv4();
      await this.setStateAsync("termId", this.termId, true);
    }

    this.log.info("Login tp TAPO App");
    await this.login();
    if (this.session.token) {
      await this.getDeviceList();
    } else {
      this.log.warn("Login failed using cached device list");
      const deviceListState = await this.getStateAsync("deviceList");
      if (deviceListState && deviceListState.val) {
        this.log.info("Use cached device list");
        this.devices = JSON.parse(deviceListState.val);
        for (const id in this.devices) {
          if (this.devices[id].ip) {
            const initResult = await this.initDevice(id)
              .then(() => {
                this.log.info(`Initialized ${id}`);
              })
              .catch((e) => {
                this.log.error(e);
              });
            this.log.debug(`initResult ${id} ${JSON.stringify(initResult)}`);
          }
        }
      }
    }

    this.log.info("Wait for connections for non camera devices");
    await this.sleep(10000);
    this.log.info("Start first Update");
    this.updateDevices();
    this.firstStart = false;
    this.updateInterval = setInterval(async () => {
      this.updateDevices();
    }, this.config.interval * 1000);
  }
  async login(): Promise<void> {
    let body = JSON.stringify({
      appVersion: "2.8.21",
      refreshTokenNeeded: true,
      platform: "iOS 14.8",
      cloudPassword: this.config.password,
      terminalUUID: this.termId,
      cloudUserName: this.config.username,
      terminalName: "ioBroker",
      terminalMeta: "3",
      appType: "TP-Link_Tapo_iOS",
    });
    let path = "api/v2/account/login";
    const mfaIdState = await this.getStateAsync("mfaId");
    if (mfaIdState && mfaIdState.val) {
      if (!this.config.mfa) {
        this.log.error("Please set mfa in the instance settings");
        return;
      }

      body = JSON.stringify({
        cloudUserName: this.config.username,
        MFAProcessId: mfaIdState.val,
        appType: "TP-Link_Tapo_iOS",
        MFAType: 2,
        code: this.config.mfa,
        terminalBindEnabled: true,
      });
      path = "api/v2/account/checkMFACodeAndLogin";
      await this.setStateAsync("mfaId", "", true);
    }
    const md5 = crypto.createHash("md5").update(body).digest("base64");
    this.log.debug(md5);
    const content = md5 + "\n9999999999\nfee66616-58dd-4bcb-be79-fe092d800a21\n/" + path;
    const signature = crypto.createHmac("sha1", this.secret).update(content).digest("hex");
    await this.requestClient({
      method: "post",
      url:
        "https://n-wap-gw.tplinkcloud.com/" +
        path +
        "?termID=" +
        this.termId +
        "&appVer=2.8.21&locale=de_DE&appName=TP-Link_Tapo_iOS&netType=wifi&model=iPhone10%2C5&termName=iPhone&termMeta=3&brand=TPLINK&ospf=iOS%2014.8",
      headers: {
        "Content-Type": "application/json;UTF-8",
        Accept: "*/*",
        "User-Agent": "Tapo/2.8.21 (iPhone; iOS 14.8; Scale/3.00)",
        "Accept-Language": "de-DE;q=1, uk-DE;q=0.9, en-DE;q=0.8",
        "X-Authorization":
          "Timestamp=9999999999, Nonce=fee66616-58dd-4bcb-be79-fe092d800a21, AccessKey=4d11b6b9d5ea4d19a829adbb9714b057, Signature=" +
          signature,
      },
      data: body,
    })
      .then(async (res) => {
        this.log.debug(JSON.stringify(res.data));
        if (res.data.error_code) {
          this.log.error(JSON.stringify(res.data));
          return;
        }
        if (res.data.result?.MFAProcessId) {
          this.log.info("Found MFA Process please enter MFA in the instance settings");
          await this.setObjectNotExistsAsync("mfaId", {
            type: "state",
            common: {
              name: "MFA Id",
              write: false,
              read: true,
              type: "string",
              role: "text",
            },
            native: {},
          });
          await this.setStateAsync("mfaId", res.data.result?.MFAProcessId, true);

          const body = JSON.stringify({
            cloudPassword: this.config.password,
            locale: "de_DE",
            terminalUUID: this.termId,
            cloudUserName: this.config.username,
            appType: "TP-Link_Tapo_iOS",
          });

          const path = "api/v2/account/getEmailVC4TerminalMFA";

          const md5 = crypto.createHash("md5").update(body).digest("base64");
          this.log.debug(md5);
          const content = md5 + "\n9999999999\nfee66616-58dd-4bcb-be79-fe092d800a21\n/" + path;
          const signature = crypto.createHmac("sha1", this.secret).update(content).digest("hex");
          await this.requestClient({
            method: "post",
            url:
              "https://n-wap-gw.tplinkcloud.com/" +
              path +
              "?termID=" +
              this.termId +
              "&appVer=2.8.21&locale=de_DE&appName=TP-Link_Tapo_iOS&netType=wifi&model=iPhone10%2C5&termName=iPhone&termMeta=3&brand=TPLINK&ospf=iOS%2014.8",
            headers: {
              "Content-Type": "application/json;UTF-8",
              Accept: "*/*",
              "User-Agent": "Tapo/2.8.21 (iPhone; iOS 14.8; Scale/3.00)",
              "Accept-Language": "de-DE;q=1, uk-DE;q=0.9, en-DE;q=0.8",
              "X-Authorization":
                "Timestamp=9999999999, Nonce=fee66616-58dd-4bcb-be79-fe092d800a21, AccessKey=4d11b6b9d5ea4d19a829adbb9714b057, Signature=" +
                signature,
            },
            data: body,
          })
            .then(async (res) => {
              this.log.debug(JSON.stringify(res.data));
              if (res.data.error_code) {
                this.log.error(JSON.stringify(res.data));
                return;
              }
            })
            .catch((error) => {
              this.log.error(error);
              error.response && this.log.error(JSON.stringify(error.response.data));
            });
          return;
        }

        if (!res.data.result || !res.data.result.token) {
          this.log.error("Login failed");
          this.log.error(JSON.stringify(res.data));
          return;
        }
        this.session = res.data.result;
        if (this.session.token) {
          this.log.info("Login succesfull");
          this.setState("info.connection", true, true);
        }
        return;
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
  }

  async getDeviceList(): Promise<void> {
    const body =
      '{"index":0,"deviceTypeList":["SMART.TAPOBULB","SMART.TAPOPLUG","SMART.IPCAMERA","SMART.TAPOHUB","SMART.TAPOSENSOR","SMART.TAPOSWITCH"],"limit":30}';
    const md5 = crypto.createHash("md5").update(body).digest("base64");
    this.log.debug(md5);
    const content = md5 + "\n9999999999\nfee66616-58dd-4bcb-be79-fe092d800a21\n/api/v2/common/getDeviceListByPage";
    const signature = crypto.createHmac("sha1", this.secret).update(content).digest("hex");
    await this.requestClient({
      method: "post",
      url: `https://n-euw1-wap-gw.tplinkcloud.com/api/v2/common/getDeviceListByPage?token=${this.session.token}&termID=${this.termId}&appVer=2.8.21&locale=de_DE&appName=TP-Link_Tapo_iOS&netType=wifi&model=iPhone10%2C5&termName=iPhone&termMeta=3&brand=TPLINK&ospf=iOS%2014.8`,
      headers: {
        "Content-Type": "application/json;UTF-8",
        "Content-MD5": md5,
        Accept: "*/*",
        "User-Agent": "Tapo/2.8.21 (iPhone; iOS 14.8; Scale/3.00)",
        "Accept-Language": "de-DE;q=1, uk-DE;q=0.9, en-DE;q=0.8",
        "X-Authorization":
          "Timestamp=9999999999, Nonce=fee66616-58dd-4bcb-be79-fe092d800a21, AccessKey=4d11b6b9d5ea4d19a829adbb9714b057, Signature=" +
          signature,
      },
      data: body,
    })
      .then(async (res) => {
        this.log.debug(JSON.stringify(res.data));
        if (res.data.error_code) {
          this.log.error(JSON.stringify(res.data));
          return;
        }
        this.log.info(`Found ${res.data.result?.totalNum} devices`);

        for (const device of res.data.result?.deviceList) {
          const id = device.deviceId;
          this.devices[id] = device;
          let name = device.alias;

          if (this.isBase64(device.alias)) {
            name = Buffer.from(device.alias, "base64").toString("utf8");
          }
          this.log.debug(`Found device ${id} ${name}`);
          await this.extendObject(id, {
            type: "device",
            common: {
              name: name,
            },
            native: {},
          });
          await this.setObjectNotExistsAsync(id + ".remote", {
            type: "channel",
            common: {
              name: "Remote Controls",
            },
            native: {},
          });

          let remoteArray = [
            { command: "refresh", name: "True = Refresh" },
            { command: "setPowerState", name: "True = On, False = Off" },
            { command: "setPowerStateChild", name: "childId,true" },

            {
              command: "setBrightness",
              name: "Set Brightness for Light devices",
              type: "number",
              role: "level.brightness",
              def: 5,
            },
            {
              command: "setColorTemp",
              name: "Set Color Temp for Light devices",
              type: "number",
              role: "level.color.temperature",
              def: 3e3,
            },
            {
              command: "setColor",
              name: "Set Color for Light devices (hue, saturation)",
              def: "30, 100",
              type: "string",
            },
          ];
          if (device.deviceType.includes("CAMERA")) {
            remoteArray = [
              { command: "refresh", name: "True = Refresh" },
              { command: "setAlertConfig", name: "True = On, False = Off" },
              { command: "setLensMaskConfig", name: "True = On, False = Off" },
              { command: "setForceWhitelampState", name: "True = On, False = Off" },
              { command: "setLedStatus", name: "True = On, False = Off" },
              { command: "setMsgPushConfig", name: "True = On, False = Off" },
              { command: "setDetectionConfig", name: "True = On, False = Off" },
              { command: "moveMotor", name: "move Camera to X (-360,360), Y(-45,45)", type: "string", def: "0, 0", role: "text" },
              { command: "moveMotorStep", name: "Angle (0-360)", type: "string", def: "180", role: "text" },
              { command: "moveToPreset", name: "PresetId", type: "string", def: "1", role: "text" },
            ];
          }
          remoteArray.forEach((remote) => {
            this.extendObject(id + ".remote." + remote.command, {
              type: "state",
              common: {
                name: remote.name || "",
                type: remote.type || "boolean",
                role: remote.role || "switch",
                def: remote.def != null ? remote.def : false,
                write: true,
                read: true,
              },
              native: {},
            });
          });
          this.json2iob.parse(id, device, { channelName: name });

          //try new API

          await this.requestClient({
            method: "get",
            url: "https://euw1-app-server.iot.i.tplinknbu.com/v1/things/" + id + "/details",
            headers: {
              "x-locale": "de",
              Authorization: "ut|" + this.session.token,
              "app-cid": "app:TP-Link_Tapo_iOS:" + this.termId,
              "x-ospf": "iOS 14.8",
              "x-app-name": "TP-Link_Tapo_iOS",
              Accept: "*/*",
              "Accept-Language": "de-DE;q=1, uk-DE;q=0.9, en-DE;q=0.8",
              "Content-Type": "application/json;UTF-8",
              "User-Agent": "Tapo/2.9.7 (iPhone; iOS 14.8; Scale/3.00)",
              "x-term-id": this.termId,
              "x-app-version": "2.9.7",
              "x-net-type": "wifi",
            },
          })
            .then(async (res) => {
              this.log.debug(JSON.stringify(res.data));
              if (res.data.error_code) {
                this.log.error(JSON.stringify(res.data));
                return;
              } else {
                this.devices[id] = { ...this.devices[id], ...res.data };
              }
            })
            .catch((error) => {
              this.log.warn(error);
              error.response && this.log.error(JSON.stringify(error.response.data));
            });
          //no ip via new API try old api
          if (!this.devices[id].ip) {
            const body = `{
              "requestData": {
                "method": "multipleRequest",
                "params": {
                  "requests": [{
                    "method": "getDeviceIpAddress",
                    "params": {
                      "network": {
                        "name": "wan"
                      }
                    }
                  }]
                }
              },
              "deviceId": "${id}"
            }`;
            const md5 = crypto.createHash("md5").update(body).digest("base64");
            this.log.debug(md5);
            const content = md5 + "\n9999999999\nfee66616-58dd-4bcb-be79-fe092d800a21\n/api/v2/common/passthrough";
            const signature = crypto.createHmac("sha1", this.secret).update(content).digest("hex");
            await this.requestClient({
              method: "post",
              url: `https://n-euw1-wap-gw.tplinkcloud.com/api/v2/common/passthrough?token=${this.session.token}&termID=${this.termId}&appVer=2.8.21&locale=de_DE&appName=TP-Link_Tapo_iOS&netType=wifi&model=iPhone10%2C5&termName=iPhone&termMeta=3&brand=TPLINK&ospf=iOS%2014.8`,
              headers: {
                "Content-Type": "application/json;UTF-8",
                "Content-MD5": md5,
                Accept: "*/*",
                "User-Agent": "Tapo/2.8.21 (iPhone; iOS 14.8; Scale/3.00)",
                "Accept-Language": "de-DE;q=1, uk-DE;q=0.9, en-DE;q=0.8",
                "X-Authorization":
                  "Timestamp=9999999999, Nonce=fee66616-58dd-4bcb-be79-fe092d800a21, AccessKey=4d11b6b9d5ea4d19a829adbb9714b057, Signature=" +
                  signature,
              },
              data: body,
            })
              .then(async (res) => {
                this.log.debug(JSON.stringify(res.data));
                let result: any = {};
                if (res.data.error_code) {
                  this.log.error(JSON.stringify(res.data));
                } else {
                  result = res.data.result?.responseData?.result?.responses[0]?.result?.network?.wan;
                  result.ip = result.ipaddr;
                  this.log.info(`Device ${id} has IP ${result.ip}`);
                  delete result[".name"];
                  delete result[".type"];
                  // result = res.data.result?.responseData?.result;
                  this.devices[id] = { ...this.devices[id], ...result };
                }
              })
              .catch((error) => {
                this.log.warn(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
              });
          }
          if (!this.devices[id].ip) {
            const ipState = await this.getStateAsync(id + ".ip");
            if (ipState && ipState.val) {
              this.devices[id].ip = ipState.val;
            } else {
              await this.setObjectNotExistsAsync(id + ".ip", {
                type: "state",
                common: {
                  name: "IP",
                  write: true,
                  read: true,
                  type: "string",
                  role: "text",
                },
                native: {},
              });
              this.log.warn(`No IP found for ${id} put the device online or set the ip state manually`);
            }
          }
          this.json2iob.parse(id, this.devices[id]);
          if (this.devices[id].ip) {
            const initResult = await this.initDevice(id)
              .then(() => {
                this.log.info(`Initialized ${id}`);
              })
              .catch((e) => {
                this.log.error(e);
              });
            this.log.debug(`initResult  camera ${id} ${JSON.stringify(initResult)}`);
          }
        }
      })
      .catch((error) => {
        this.log.warn(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });

    await this.setObjectNotExistsAsync("deviceList", {
      type: "state",
      common: {
        name: "Cached device list",
        write: false,
        read: true,
        type: "string",
        role: "json",
      },
      native: {},
    });

    await this.setStateAsync("deviceList", JSON.stringify(this.devices), true);
  }
  async initDevice(id: string): Promise<void> {
    const device = this.devices[id];
    if (!device.ip) {
      this.log.warn(`No IP found for ${id}`);
      return;
    }
    this.log.info(`Init device ${id} type ${device.deviceName} with ip ${device.ip}`);
    let deviceObject: any;
    if (device.deviceName === "P100") {
      deviceObject = new P100(this.log, device.ip, this.config.username, this.config.password, 2);
    } else if (device.deviceName.startsWith("P110") || device.deviceName.startsWith("P115")) {
      deviceObject = new P110(this.log, device.ip, this.config.username, this.config.password, 2);
    } else if (device.deviceName === "L530" || device.deviceName.startsWith("L630")) {
      deviceObject = new L530(this.log, device.ip, this.config.username, this.config.password, 2);
    } else if (device.deviceName === "L510E") {
      deviceObject = new L510E(this.log, device.ip, this.config.username, this.config.password, 2);
    } else if (device.deviceName === "L520E") {
      deviceObject = new L520E(this.log, device.ip, this.config.username, this.config.password, 2);
    } else if (device.deviceName.startsWith("L") || device.deviceName.startsWith("KL")) {
      deviceObject = new L510E(this.log, device.ip, this.config.username, this.config.password, 2);
    } else if (device.deviceName.startsWith("C") || device.deviceName.startsWith("TC")) {
      if (device.deviceName.startsWith("C42")) {
        this.log.warn("Battery device found a high update rate can prevent standby and leads to high battery drain");
        this.log.warn("Minium update interval is 30 minutes");
      }
      if (!this.config.streamusername || !this.config.streampassword) {
        this.log.warn(`No stream username or password. No motion detection available`);
      }
      deviceObject = new TAPOCamera(this.log, {
        name: device.deviceName,
        ipAddress: device.ip,
        password: this.config.password,
        streamUser: this.config.streamusername,
        streamPassword: this.config.streampassword,
        disableStreaming: true,
      });

      //new Camera(this.log, device.ip, this.config.username, this.config.password, 2);

      this.deviceObjects[id] = deviceObject;
      const deviceInfo = await deviceObject.getDeviceInfo(true);
      this.log.info(`${id} Received device info ${JSON.stringify(deviceInfo)}`);
      this.log.debug(JSON.stringify(deviceInfo));
      this.json2iob.parse(id, deviceInfo);
      this.log.debug(`Init event emitter for ${id}`);
      const eventEmitter = await deviceObject.getEventEmitter();
      await this.setObjectNotExistsAsync(id + ".motionEvent", {
        type: "state",
        common: {
          name: "Motion detected",
          type: "boolean",
          role: "boolean",
          def: false,
          write: false,
          read: true,
        },
        native: {},
      });
      this.log.debug('Init event listener for "motion"');
      eventEmitter.addListener("motion", async (motionDetected: any) => {
        await this.setStateAsync(id + ".motionEvent", motionDetected, true);
        this.log.debug(`[${device.deviceName}] "Motion detected" ${motionDetected}`);
      });
      return;
    } else {
      this.log.info(`Unknown device type ${device.deviceName} init as P100`);
      deviceObject = new P100(this.log, device.ip, this.config.username, this.config.password, 2);
    }
    this.deviceObjects[id] = deviceObject;
    await deviceObject
      .handshake()
      .then(async () => {
        if (deviceObject.is_klap) {
          this.log.debug("Detected KLAP device");
          await deviceObject.handshake_new().catch(async (error: any) => {
            this.log.error(error);
            this.log.error(error.stack);
            this.log.error("KLAP Handshake failed. Try old handshake");
            deviceObject.is_klap = false;
            await deviceObject.reAuthenticate().catch(() => {
              this.log.error("Login failed");
              this.deviceObjects[id]._connected = false;
            });
          });
        } else {
          await deviceObject.login().catch(() => {
            this.log.error("Login failed");
            this.deviceObjects[id]._connected = false;
          });
        }
        deviceObject
          .getDeviceInfo(true)
          .then(async (sysInfo: any) => {
            this.log.debug(JSON.stringify(sysInfo));
            if (sysInfo.request) {
              this.log.error("Malformed response sysinfo");
              this.log.error(JSON.stringify(sysInfo));
              return;
            }
            this.json2iob.parse(id, sysInfo);

            this.deviceObjects[id]._connected = true;
            if (this.deviceObjects[id].getEnergyUsage) {
              this.log.debug("Receive energy usage");
              const energyUsage = await this.deviceObjects[id].getEnergyUsage();
              this.log.debug(JSON.stringify(energyUsage));
              this.json2iob.parse(id, energyUsage);
            }
            const childList = await this.deviceObjects[id].getChildDevices();
            this.log.debug("Childlist: " + JSON.stringify(childList));
            if (childList && childList.error_code === 0) {
              this.json2iob.parse(id + ".childlist", childList);
            }
          })
          .catch((error: any) => {
            this.log.error(JSON.stringify(error));
            this.log.error("52 - Get Device Info failed");

            this.deviceObjects[id]._connected = false;
          });
      })
      .catch(() => {
        this.log.error("Handshake failed");
        this.deviceObjects[id]._connected = false;
      });
  }

  async updateDevices(): Promise<void> {
    try {
      for (const deviceId in this.deviceObjects) {
        //check for C4 device and last timestampe update
        if (
          this.deviceObjects[deviceId]?.deviceName?.startsWith("C4") &&
          this.lastBatteryDeviceUpdateTimestamp + 30 * 60 * 1000 > Date.now()
        ) {
          this.log.debug("Skip update for battery device last update was less than 30 minutes ago : " + deviceId);
          continue;
        }
        if (this.deviceObjects[deviceId].getStatus) {
          this.log.debug("Receive camera status");
          const status = await this.deviceObjects[deviceId].getStatus().catch((error: any) => {
            this.log.info("Get camera Status failed");
            this.log.debug(JSON.stringify(error));
          });
          this.log.debug(JSON.stringify(status));
          this.json2iob.parse(deviceId, status);
          if (this.deviceObjects[deviceId].stok === undefined) {
            if (this.firstStart) {
              this.log.error("No stok found for: " + deviceId + " Ignore and remove the device until next restart");

              delete this.deviceObjects[deviceId];
            } else {
              this.log.info(
                "No stok found for: " + deviceId + " this means the device is offline or connection lost. No update or commands possible",
              );
            }
          }
          continue;
        }
        if (!this.deviceObjects[deviceId]._connected) {
          continue;
        }

        this.deviceObjects[deviceId]
          .getDeviceInfo(true)
          .then(async (sysInfo: any) => {
            this.log.debug(JSON.stringify(sysInfo));
            if (!sysInfo || sysInfo.name === "Error" || sysInfo.request) {
              this.log.debug("Malformed response sysinfo");
              // this.log.error(JSON.stringify(sysInfo));
              return;
            }
            await this.json2iob.parse(deviceId, sysInfo);
            if (this.deviceObjects[deviceId].getEnergyUsage) {
              this.log.debug("Receive energy usage");
              const energyUsage = await this.deviceObjects[deviceId].getEnergyUsage();
              this.log.debug(JSON.stringify(energyUsage));
              if (energyUsage.request) {
                this.log.error("Malformed response getEnergyUsage");
                this.log.error(JSON.stringify(energyUsage));
                return;
              }
              await this.json2iob.parse(deviceId, energyUsage);
              const power_usage = this.deviceObjects[deviceId].getPowerConsumption();
              if (power_usage.request) {
                this.log.error("Malformed response getPowerConsumption");
                this.log.error(JSON.stringify(power_usage));
                return;
              }
              await this.json2iob.parse(deviceId, power_usage);
            }
          })
          .catch((error: any) => {
            this.log.error(`Get Device Info failed for ${deviceId} - ${error}`);
          });
      }
      this.log.debug("Update done");
    } catch (error: any) {
      this.log.warn(error);
    }
  }

  isBase64(str: string): boolean {
    if (str === "" || str.trim() === "") {
      return false;
    }
    try {
      const strWithoutPadding = str.replace(/=*$/, "");
      return btoa(atob(strWithoutPadding)) === strWithoutPadding || btoa(atob(str)) === str;
    } catch (err) {
      return false;
    }
  }
  async sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
  async refreshToken(): Promise<void> {
    this.log.debug("Refresh token");
  }
  /**
   * Is called when adapter shuts down - callback has to be called under any circumstances!
   */
  private onUnload(callback: () => void): void {
    try {
      this.setState("info.connection", false, true);
      this.refreshTimeout && clearTimeout(this.refreshTimeout);
      this.reLoginTimeout && clearTimeout(this.reLoginTimeout);
      this.refreshTokenTimeout && clearTimeout(this.refreshTokenTimeout);
      this.updateInterval && clearInterval(this.updateInterval);
      this.refreshTokenInterval && clearInterval(this.refreshTokenInterval);

      callback();
    } catch (e) {
      callback();
    }
  }

  /**
   * Is called if a subscribed state changes
   */
  private async onStateChange(id: string, state: ioBroker.State | null | undefined): Promise<void> {
    if (state) {
      if (!state.ack) {
        const deviceId = id.split(".")[2];
        const command = id.split(".")[4];
        if (id.split(".")[3] !== "remote") {
          return;
        }

        if (command === "Refresh") {
          this.deviceObjects[deviceId]
            .getDeviceInfo(true)
            .then((sysInfo: any) => {
              this.log.debug(JSON.stringify(sysInfo));
              this.json2iob.parse(deviceId, sysInfo);
            })
            .catch((error) => {
              this.log.error(`Get Device Info failed for ${deviceId} - ${error}`);
            });

          return;
        }
        try {
          const cameraCommands: { [key: string]: string } = {
            setAlertConfig: "alarm",
            setLensMaskConfig: "eyes",
            setLedStatus: "led",
            setMsgPushConfig: "notifications",
            setDetectionConfig: "motionDetection",
          };
          if (this.deviceObjects[deviceId] && (this.deviceObjects[deviceId][command] || cameraCommands[command])) {
            let result;
            if (cameraCommands[command]) {
              result = await this.deviceObjects[deviceId].setStatus(cameraCommands[command], state.val);
            } else if (command === "setColor" || command === "moveMotor" || command === "setPowerStateChild") {
              const valueSplit = state.val.replace(" ", "").split(",");
              result = await this.deviceObjects[deviceId][command](valueSplit[0], valueSplit[1]);
            } else {
              result = await this.deviceObjects[deviceId][command](state.val);
            }
            this.log.info(
              command + " was set to : " + state.val + " for device " + deviceId + " was successful: " + JSON.stringify(result),
            );
            this.refreshTimeout && clearTimeout(this.refreshTimeout);
            this.refreshTimeout = setTimeout(async () => {
              this.updateDevices();
            }, 2 * 1000);
          } else {
            if (this.deviceObjects[deviceId]) {
              this.log.error(`Device ${deviceId} has no command ${command}`);
            } else {
              this.log.error(`Device ${deviceId} not found`);
            }
          }
        } catch (error) {
          this.log.error(error);
        }
      } else {
        const resultDict: { [key: string]: string } = {
          device_on: "setPowerState",
          eyes: "setLensMaskConfig",
          alarm: "setAlertConfig",
          led: "setLedStatus",
          notifications: "setMsgPushConfig",
          motionDetection: "setDetectionConfig",
        };
        const idArray = id.split(".");
        const stateName = idArray[idArray.length - 1];
        const deviceId = id.split(".")[2];
        if (resultDict[stateName]) {
          await this.setState(deviceId + ".remote." + resultDict[stateName], state.val, true);
        }
      }
    }
  }
}

if (require.main !== module) {
  // Export the constructor in compact mode
  module.exports = (options: Partial<utils.AdapterOptions> | undefined) => new Tapo(options);
} else {
  // otherwise start the instance directly
  (() => new Tapo())();
}
