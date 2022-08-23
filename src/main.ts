/*
 * Created with @iobroker/create-adapter v2.1.1
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
import * as utils from "@iobroker/adapter-core";
import axios, { AxiosInstance } from "axios";
import crypto from "crypto";
import https from "https";
import Json2iob from "./lib/json2iob";
import L510E from "./lib/utils/l510e";
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
      }),
    });
    this.secret = Buffer.from([
      54, 101, 100, 55, 100, 57, 55, 102, 51, 101, 55, 51, 52, 54, 55, 102, 56, 97, 53, 98, 97, 98, 57, 48, 98, 53, 55,
      55, 98, 97, 52, 99,
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

    this.log.info("Login tp TAPO App");
    await this.login();
    if (this.session.token) {
      await this.getDeviceList();
      this.log.info("Wait for connections");
      await this.sleep(10000);
      await this.updateDevices();
      this.updateInterval = setInterval(async () => {
        await this.updateDevices();
      }, this.config.interval * 1000);
    }
  }
  async login(): Promise<void> {
    let body = JSON.stringify({
      appVersion: "2.8.21",
      refreshTokenNeeded: true,
      platform: "iOS 14.8",
      cloudPassword: this.config.password,
      terminalUUID: "CDE6601E-148C-4CB7-831F-FD587E999D99",
      cloudUserName: this.config.username,
      terminalName: "iPhone",
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
        "?termID=CDE6601E-148C-4CB7-831F-FD587E954C69&appVer=2.8.21&locale=de_DE&appName=TP-Link_Tapo_iOS&netType=wifi&model=iPhone10%2C5&termName=iPhone&termMeta=3&brand=TPLINK&ospf=iOS%2014.8",
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
            terminalUUID: "CDE6601E-148C-4CB7-831F-FD587E999D99",
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
              "?termID=CDE6601E-148C-4CB7-831F-FD587E954C69&appVer=2.8.21&locale=de_DE&appName=TP-Link_Tapo_iOS&netType=wifi&model=iPhone10%2C5&termName=iPhone&termMeta=3&brand=TPLINK&ospf=iOS%2014.8",
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
        this.setState("info.connection", true, true);
        this.session = res.data.result;
        return;
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
  }

  async getDeviceList(): Promise<void> {
    const body =
      '{"index":0,"deviceTypeList":["SMART.TAPOBULB","SMART.TAPOPLUG","SMART.IPCAMERA","SMART.TAPOHUB","SMART.TAPOSENSOR","SMART.TAPOSWITCH"],"limit":20}';
    const md5 = crypto.createHash("md5").update(body).digest("base64");
    this.log.debug(md5);
    const content = md5 + "\n9999999999\nfee66616-58dd-4bcb-be79-fe092d800a21\n/api/v2/common/getDeviceListByPage";
    const signature = crypto.createHmac("sha1", this.secret).update(content).digest("hex");
    await this.requestClient({
      method: "post",
      url: `https://n-euw1-wap-gw.tplinkcloud.com/api/v2/common/getDeviceListByPage?token=${this.session.token}&termID=CDE6601E-148C-4CB7-831F-FD587E954C69&appVer=2.8.21&locale=de_DE&appName=TP-Link_Tapo_iOS&netType=wifi&model=iPhone10%2C5&termName=iPhone&termMeta=3&brand=TPLINK&ospf=iOS%2014.8`,
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
          const name = Buffer.from(device.alias, "base64").toString("utf8");

          await this.setObjectNotExistsAsync(id, {
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

          const remoteArray = [
            { command: "refresh", name: "True = Refresh" },
            { command: "setPowerState", name: "True = On, False = Off" },
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
              def: 3000,
            },
            {
              command: "setColor",
              name: "Set Color for Light devices (hue, saturation)",
              def: "30, 100",
              type: "string",
            },
          ];
          remoteArray.forEach((remote) => {
            this.setObjectNotExists(id + ".remote." + remote.command, {
              type: "state",
              common: {
                name: remote.name || "",
                type: remote.type || "boolean",
                role: remote.role || "boolean",
                def: remote.def || false,
                write: true,
                read: true,
              },
              native: {},
            });
          });
          this.json2iob.parse(id, device);

          const body = `{"requestData":{"method":"get_device_info","terminalUUID":"01D6B18A-5514-4C9F-B49C-555E775591B2"},"deviceId":"${id}"}`;
          const md5 = crypto.createHash("md5").update(body).digest("base64");
          this.log.debug(md5);
          const content = md5 + "\n9999999999\nfee66616-58dd-4bcb-be79-fe092d800a21\n/api/v2/common/passthrough";
          const signature = crypto.createHmac("sha1", this.secret).update(content).digest("hex");
          await this.requestClient({
            method: "post",
            url: `https://n-euw1-wap-gw.tplinkcloud.com/api/v2/common/passthrough?token=${this.session.token}&termID=CDE6601E-148C-4CB7-831F-FD587E954C69&appVer=2.8.21&locale=de_DE&appName=TP-Link_Tapo_iOS&netType=wifi&model=iPhone10%2C5&termName=iPhone&termMeta=3&brand=TPLINK&ospf=iOS%2014.8`,
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
              let result = {};
              if (res.data.error_code) {
                this.log.error(JSON.stringify(res.data));
              } else {
                result = res.data.result?.responseData?.result;
                this.devices[id] = { ...this.devices[id], ...result };
              }
              if (!result.ip) {
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
              if (this.devices[id].ip) {
                const initResult = await this.initDevice(id)
                  .then(() => {
                    this.log.info(`Initialized ${id}`);
                  })
                  .catch((e) => {
                    this.log.error(e);
                  });
                this.log.debug(`initResult ${id} ${initResult}`);
              }
              this.json2iob.parse(id, result);
            })
            .catch((error) => {
              this.log.error(error);
              error.response && this.log.error(JSON.stringify(error.response.data));
            });
        }
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
  }
  async initDevice(id: string): Promise<void> {
    const device = this.devices[id];
    this.log.info(`Init device ${id} type ${device.deviceName} with ip ${device.ip}`);
    let deviceObject: any;
    if (device.deviceName === "P100") {
      deviceObject = new P100(this.log, device.ip, this.config.username, this.config.password, 2);
    } else if (device.deviceName === "P110" || device.deviceName === "P115") {
      deviceObject = new P110(this.log, device.ip, this.config.username, this.config.password, 2);
    } else if (device.deviceName === "L530") {
      deviceObject = new L530(this.log, device.ip, this.config.username, this.config.password, 2);
    } else if (device.deviceName.startsWith("L") || device.deviceName.startsWith("KL")) {
      deviceObject = new L510E(this.log, device.ip, this.config.username, this.config.password, 2);
    } else {
      this.log.info(`Unknown device type ${device.deviceName} init as P100`);
      deviceObject = new P100(this.log, device.ip, this.config.username, this.config.password, 2);
    }
    this.deviceObjects[id] = deviceObject;
    await deviceObject
      .handshake()
      .then(() => {
        deviceObject
          .login()
          .then(() => {
            deviceObject
              .getDeviceInfo()
              .then(async (sysInfo: any) => {
                this.log.debug(JSON.stringify(sysInfo));
                this.json2iob.parse(id, sysInfo);

                this.deviceObjects[id]._connected = true;
                if (this.deviceObjects[id].getEnergyUsage) {
                  this.log.debug("Receive energy usage");
                  const energyUsage = await this.deviceObjects[id].getEnergyUsage();
                  this.log.debug(JSON.stringify(energyUsage));
                  this.json2iob.parse(id, energyUsage);
                }
              })
              .catch(() => {
                this.log.error("52 - Get Device Info failed");

                this.deviceObjects[id]._connected = false;
              });
          })
          .catch(() => {
            this.log.error("Login failed");
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
        if (!this.deviceObjects[deviceId]._connected) {
          continue;
        }
        this.deviceObjects[deviceId]
          .getDeviceInfo()
          .then(async (sysInfo: any) => {
            this.log.debug(JSON.stringify(sysInfo));
            this.json2iob.parse(deviceId, sysInfo);
            if (this.deviceObjects[deviceId].getEnergyUsage) {
              this.log.debug("Receive energy usage");
              const energyUsage = await this.deviceObjects[deviceId].getEnergyUsage();
              this.log.debug(JSON.stringify(energyUsage));
              this.json2iob.parse(deviceId, energyUsage);
              const power_usage = this.deviceObjects[deviceId].getPowerConsumption();
              this.json2iob.parse(deviceId, power_usage);
            }
          })
          .catch((error) => {
            this.log.error(`Get Device Info failed for ${deviceId} - ${error}`);
          });
      }
    } catch (error) {
      this.log.error(error);
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
            .getDeviceInfo()
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
          if (this.deviceObjects[deviceId][command]) {
            if (command === "setColor") {
              const valueSplit = state.val.split(", ");
              await this.log.info(this.deviceObjects[deviceId][command](valueSplit[0], valueSplit[1]));
            } else {
              await this.log.info(this.deviceObjects[deviceId][command](state.val));
            }
            this.refreshTimeout && clearTimeout(this.refreshTimeout);
            this.refreshTimeout = setTimeout(async () => {
              await this.updateDevices();
            }, 2 * 1000);
          } else {
            this.log.error(`Device ${deviceId} has no command ${command}`);
          }
        } catch (error) {
          this.log.error(error);
        }
      } else {
        const resultDict = { device_on: "setPowerState" };
        const idArray = id.split(".");
        const stateName = idArray[idArray.length - 1];
        const deviceId = id.split(".")[2];
        if (resultDict[stateName]) {
          await this.setStateAsync(deviceId + ".remote." + resultDict[stateName], state.val, true);
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
