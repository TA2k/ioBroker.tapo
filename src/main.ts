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
import P100 from "./lib/utils/p100";

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
  p100: P100;
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
      // await this.updateDevices();
      this.updateInterval = setInterval(async () => {
        //  await this.updateDevices();
      }, this.config.interval * 60 * 1000);
    }
  }
  async login(): Promise<void> {
    const body = JSON.stringify({
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
    const md5 = crypto.createHash("md5").update(body).digest("base64");
    this.log.debug(md5);
    const content = md5 + "\n9999999999\nfee66616-58dd-4bcb-be79-fe092d800a21\n/api/v2/account/login";
    const signature = crypto.createHmac("sha1", this.secret).update(content).digest("hex");
    await this.requestClient({
      method: "post",
      url: "https://n-wap-gw.tplinkcloud.com/api/v2/account/login?termID=CDE6601E-148C-4CB7-831F-FD587E954C69&appVer=2.8.21&locale=de_DE&appName=TP-Link_Tapo_iOS&netType=wifi&model=iPhone10%2C5&termName=iPhone&termMeta=3&brand=TPLINK&ospf=iOS%2014.8",
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
      .then((res) => {
        this.log.debug(JSON.stringify(res.data));
        if (res.data.error_code) {
          this.log.error(JSON.stringify(res.data));
          return;
        }
        this.setState("info.connection", true, true);
        this.session = res.data.result;
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
          //   await this.setObjectNotExistsAsync(id + ".remote", {
          //     type: "channel",
          //     common: {
          //       name: "Remote Controls",
          //     },
          //     native: {},
          //   });

          //   const remoteArray = [{ command: "Refresh", name: "True = Refresh" }];
          //   remoteArray.forEach((remote) => {
          //     this.setObjectNotExists(id + ".remote." + remote.command, {
          //       type: "state",
          //       common: {
          //         name: remote.name || "",
          //         type: remote.type || "boolean",
          //         role: remote.role || "boolean",
          //         def: remote.def || false,
          //         write: true,
          //         read: true,
          //       },
          //       native: {},
          //     });
          //   });
          this.json2iob.parse(id, device);
          if (device.status === 1) {
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

                if (res.data.error_code) {
                  this.log.error(JSON.stringify(res.data));
                  return;
                }
                const result = res.data.result?.responseData?.result;
                this.devices[id] = { ...this.devices[id], result };
                if (result.ip) {
                  this.initDevice(id);
                }
                this.json2iob.parse(id, result);
              })
              .catch((error) => {
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
              });
          }
        }
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
  }
  async initDevice(id: string): Promise<void> {
    const device = this.devices[id];
    if (device.deviceName === "P100") {
      this.p100 = new P100(this.log, device.ip, this.config.username, this.config.password, 2);
      this.deviceObjects[id] = this.p100;
      this.p100
        .handshake()
        .then(() => {
          this.p100
            .login()
            .then(() => {
              this.p100
                .getDeviceInfo()
                .then((sysInfo) => {
                  const interval = this.config.interval ? this.config.interval * 1000 : 30000;
                  this.log.debug("interval: " + interval);

                  setTimeout(() => {
                    // this.updateState(interval);
                  }, interval);
                })
                .catch(() => {
                  this.log.error("52 - Get Device Info failed");
                });
            })
            .catch(() => {
              this.log.error("Login failed");
            });
        })
        .catch(() => {
          this.log.error("Handshake failed");
        });
    }
  }

  async updateDevices(): Promise<void> {
    const statusArray = [
      {
        path: "status",
        url: "",
        desc: "Status",
      },
    ];

    for (const element of statusArray) {
      // const url = element.url.replace("$id", id);

      await this.requestClient({
        method: element.method || "get",
        url: element.url,
        headers: {},
      })
        .then(async (res) => {
          this.log.debug(JSON.stringify(res.data));
          if (!res.data) {
            return;
          }
          const data = res.data;

          const forceIndex = true;
          const preferedArrayName = null;

          this.json2iob.parse(element.path, data, {
            forceIndex: forceIndex,
            preferedArrayName: preferedArrayName,
            channelName: element.desc,
          });
          await this.setObjectNotExistsAsync(element.path + ".json", {
            type: "state",
            common: {
              name: "Raw JSON",
              write: false,
              read: true,
              type: "string",
              role: "json",
            },
            native: {},
          });
          this.setState(element.path + ".json", JSON.stringify(data), true);
        })
        .catch((error) => {
          if (error.response) {
            if (error.response.status === 401) {
              error.response && this.log.debug(JSON.stringify(error.response.data));
              this.log.info(element.path + " receive 401 error. Refresh Token in 60 seconds");
              this.refreshTokenTimeout && clearTimeout(this.refreshTokenTimeout);
              this.refreshTokenTimeout = setTimeout(() => {
                this.refreshToken();
              }, 1000 * 60);

              return;
            }
          }
          this.log.error(element.url);
          this.log.error(error);
          error.response && this.log.error(JSON.stringify(error.response.data));
        });
    }
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
  private onStateChange(id: string, state: ioBroker.State | null | undefined): void {
    if (state) {
      if (!state.ack) {
        const deviceId = id.split(".")[2];
        const command = id.split(".")[4];
        if (id.split(".")[3] !== "remote") {
          return;
        }

        if (command === "Refresh") {
          this.updateDevices();
          return;
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
