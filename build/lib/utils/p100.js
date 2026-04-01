"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const tpLinkCipher_js_1 = __importDefault(require("./tpLinkCipher.js"));
const newTpLinkCipher_js_1 = __importDefault(require("./newTpLinkCipher.js"));
const axios_1 = __importDefault(require("axios"));
const crypto_1 = __importDefault(require("crypto"));
const utf8_1 = __importDefault(require("utf8"));
const http_1 = __importDefault(require("http"));
class P100 {
    log;
    ipAddress;
    email;
    password;
    timeout;
    _crypto = crypto_1.default;
    _axios = axios_1.default;
    _utf8 = utf8_1.default;
    is_klap = true;
    encodedPassword;
    encodedEmail;
    privateKey;
    publicKey;
    ip;
    cookie;
    tplink_timeout;
    token;
    terminalUUID;
    _plugSysInfo;
    _reconnect_counter;
    _timeout;
    tpLinkCipher;
    newTpLinkCipher;
    ERROR_CODES = {
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
    constructor(log, ipAddress, email, password, timeout) {
        this.log = log;
        this.ipAddress = ipAddress;
        this.email = email;
        this.password = password;
        this.timeout = timeout;
        this.log.debug('Constructing P100 on host: ' + ipAddress);
        this.ip = ipAddress;
        this.encryptCredentials(email, password);
        this.createKeyPair();
        this.terminalUUID = crypto_1.default.randomUUID();
        this._reconnect_counter = 0;
        this._timeout = timeout;
    }
    encryptCredentials(email, password) {
        //Password Encoding
        this.encodedPassword = tpLinkCipher_js_1.default.mime_encoder(password);
        //Email Encoding
        this.encodedEmail = this.sha_digest_username(email);
        this.encodedEmail = tpLinkCipher_js_1.default.mime_encoder(this.encodedEmail);
    }
    sha_digest_username(data) {
        const digest = this._crypto.createHash('sha1').update(data).digest('hex');
        return digest;
    }
    calc_auth_hash(username, password) {
        const usernameDigest = this._crypto
            .createHash('sha1')
            .update(Buffer.from(username.normalize('NFKC')))
            .digest();
        const passwordDigest = this._crypto
            .createHash('sha1')
            .update(Buffer.from(password.normalize('NFKC')))
            .digest();
        const digest = this._crypto
            .createHash('sha256')
            .update(Buffer.concat([usernameDigest, passwordDigest]))
            .digest();
        return digest;
    }
    createKeyPair() {
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
    async handshake() {
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
            .then((res) => {
            this.log.debug('Received Old Handshake P100 on host response: ' + this.ip);
            if (res.data.error_code || res.status !== 200) {
                return this.handleError(res.data.error_code ? res.data.error_code : res.status, '172');
            }
            try {
                const encryptedKey = res.data.result.key.toString('utf8');
                this.decode_handshake_key(encryptedKey);
                if (res.headers['set-cookie']) {
                    this.cookie = res.headers['set-cookie'][0].split(';')[0];
                }
                return;
            }
            catch (error) {
                return this.handleError(res.data.error_code, '106');
            }
        })
            .catch((error) => {
            this.log.error('111 Error: ' + error ? error.message : '');
            return error;
        });
    }
    async login() {
        const URL = 'http://' + this.ip + '/app';
        const payload = '{' +
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
                .then((res) => {
                if (res.data.error_code || res.status !== 200) {
                    return this.handleError(res.data.error_code ? res.data.error_code : res.status, '226');
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
                }
                catch (error) {
                    return this.handleError(JSON.parse(decryptedResponse).error_code, '157');
                }
            })
                .catch((error) => {
                this.log.error('Error Login: ' + error ? error.message : '');
                return error;
            });
        }
    }
    async raw_request(path, data, responseType, params) {
        const URL = 'http://' + this.ip + '/app/' + path;
        const headers = {
            Connection: 'Keep-Alive',
            Host: this.ip,
            Accept: '*/*',
            'Content-Type': 'application/octet-stream',
        };
        if (this.cookie) {
            headers.Cookie = this.cookie;
        }
        const config = {
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
            .then((res) => {
            this.log.debug('Received request on host response: ' + this.ip);
            if (res.data.error_code || res.status !== 200) {
                return this.handleError(res.data.error_code ? res.data.error_code : res.status, '273');
            }
            try {
                if (res.headers && res.headers['set-cookie']) {
                    this.log.debug('Handshake 1 cookie: ' + JSON.stringify(res.headers['set-cookie'][0]));
                    this.cookie = res.headers['set-cookie'][0].split(';')[0];
                    this.tplink_timeout = Number(res.headers['set-cookie'][0].split(';')[1]);
                }
                return res.data;
            }
            catch (error) {
                return this.handleError(res.data.error_code, '318');
            }
        })
            .catch((error) => {
            this.log.error('276 Error: ' + error.message);
            if (error.message.indexOf('403') > -1) {
                this.reAuthenticate();
            }
            return error;
        });
    }
    decode_handshake_key(key) {
        const buff = Buffer.from(key, 'base64');
        const decoded = this._crypto.privateDecrypt({
            key: this.privateKey,
            padding: this._crypto.constants.RSA_PKCS1_PADDING,
        }, buff);
        const b_arr = decoded.slice(0, 16);
        const b_arr2 = decoded.slice(16, 32);
        this.tpLinkCipher = new tpLinkCipher_js_1.default(this.log, b_arr, b_arr2);
    }
    //new tapo klap requests
    async handshake_new() {
        this.log.debug('Trying new handshake');
        const local_seed = this._crypto.randomBytes(16);
        const ah = this.calc_auth_hash(this.email, this.password);
        //send handshake1 via native http
        const options = {
            method: 'POST',
            hostname: this.ip,
            path: '/app/handshake1',
            headers: {
                Connection: 'Keep-Alive',
                'Content-Type': 'application/octet-stream',
                'Content-Length': local_seed.length,
            },
            agent: new http_1.default.Agent({
                keepAlive: true,
            }),
        };
        const response = await new Promise((resolve, reject) => {
            const request = http_1.default
                .request(options, (res) => {
                const chunks = [];
                if (res.headers && res.headers['set-cookie']) {
                    this.cookie = res.headers['set-cookie'][0].split(';')[0];
                }
                res.on('data', (chunk) => {
                    chunks.push(chunk);
                });
                res.on('end', (chunk) => {
                    const body = Buffer.concat(chunks);
                    this.log.debug(body.toString());
                    resolve(body);
                });
                res.on('error', (error) => {
                    this.log.error(error);
                    resolve(Buffer.from(''));
                });
            })
                .on('error', (error) => {
                this.log.error(error);
                resolve(Buffer.from(''));
            });
            request.write(local_seed);
            request.end();
        });
        // const response = await this.raw_request("handshake1", local_seed, "arraybuffer").then((res) => {
        //axios not working for handshake1
        if (!response || !response.subarray) {
            this.log.debug('New Handshake 1 failed');
            return;
        }
        this.log.debug('Handshake 1 response: ' + response.toString('hex'));
        const remote_seed = response.subarray(0, 16);
        const server_hash = response.subarray(16);
        this.log.debug('remote seed: ' + remote_seed.toString('hex'));
        this.log.debug('server hash: ' + server_hash.toString('hex'));
        this.log.debug('Extracted hashes');
        let auth_hash = undefined;
        this.log.debug('Calculated auth hash: ' + ah.toString('hex'));
        const calculateAuthHash = (email, password) => {
            return this._crypto
                .createHash('sha256')
                .update(Buffer.concat([local_seed, remote_seed, this.calc_auth_hash(email, password)]))
                .digest();
        };
        const local_seed_auth_hash = calculateAuthHash(this.email, this.password);
        this.log.debug('Calculated local seed auth hash: ' + local_seed_auth_hash.toString('hex'));
        this.log.debug('Server hash: ' + server_hash.toString('hex'));
        const validateAuthHash = (email, password) => {
            const calculatedHash = calculateAuthHash(email, password);
            this.log.debug(`Calculated auth hash for ${email}: ${calculatedHash.toString('hex')}`);
            return calculatedHash.toString('hex') === server_hash.toString('hex');
        };
        if (validateAuthHash(this.email, this.password)) {
            this.log.debug('New Handshake 1 successful');
            auth_hash = ah;
        }
        else if (validateAuthHash(this.email.toLowerCase(), this.password)) {
            this.log.debug('New Handshake 1 successful with lowercase mail');
            auth_hash = ah;
        }
        else if (validateAuthHash('', '')) {
            this.log.debug('New Handshake 1 successful with empty auth hash');
            auth_hash = this.calc_auth_hash('', '');
        }
        else if (validateAuthHash('test@tp-link.net', 'test')) {
            this.log.debug('New Handshake 1 successful with test auth hash');
            auth_hash = this.calc_auth_hash('test@tp-link.net', 'test');
        }
        else {
            this.log.error('New Handshake 1 failed');
            this.log.error("Local seed auth hash doesn't match server hash. Please check if the mail and password are correct. And E-Mail is in same Upper/Lowercase as in the Tapo App");
            auth_hash = ah;
        }
        const req = this._crypto
            .createHash('sha256')
            .update(Buffer.concat([remote_seed, local_seed, auth_hash]))
            .digest();
        return this.raw_request('handshake2', req, 'text').then((res) => {
            this.log.debug('New Handshake 2 successful: ' + res);
            this.newTpLinkCipher = new newTpLinkCipher_js_1.default(local_seed, remote_seed, auth_hash, this.log);
            this.log.debug('New Init cipher successful');
            return;
        });
        //   });
    }
    async turnOff() {
        const payload = '{' +
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
    async turnOn() {
        const payload = '{' +
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
    async getChildDevices() {
        const payload = {
            method: 'getChildDeviceList',
            params: { childControl: { start_index: 0 } },
        };
        return this.sendRequest(JSON.stringify(payload));
    }
    async setPowerStateChild(deviceId, state) {
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
    async setPowerState(state) {
        if (state) {
            return this.turnOn();
        }
        else {
            return this.turnOff();
        }
    }
    async getDeviceInfo(force) {
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
                .then((res) => {
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
                }
                catch (error) {
                    this.log.debug(error.stack);
                    return this.handleError(JSON.parse(decryptedResponse).error_code, '340');
                }
            })
                .catch((error) => {
                this.log.error('371 Error: ' + error ? error.message : '');
                return error;
            });
        }
        else if (this.newTpLinkCipher) {
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
            const config = {
                timeout: 5000,
                responseType: 'arraybuffer',
                headers: headers,
                params: { seq: data.seq.toString() },
            };
            //@ts-ignore
            return this._axios
                .post(URL, data.encryptedPayload, config)
                .then((res) => {
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
                }
                catch (error) {
                    this.log.debug('Decrypt/parse error: ' + error.message);
                    this.log.debug('Status: ' + res.status);
                    return this.handleError(res.data?.error_code || error.message, '480');
                }
            })
                .catch((error) => {
                this.log.debug('469 Error: ' + JSON.stringify(error));
                this.log.info('469 Error: ' + error.message);
                if (error.message.indexOf('403') > -1) {
                    this.reAuthenticate();
                }
                return error;
            });
        }
        else {
            return new Promise((resolve, reject) => {
                reject();
            });
        }
    }
    /**
     * Cached value of `sysinfo.device_id`  if set.
     */
    get id() {
        if (this.getSysInfo()) {
            return this.getSysInfo().device_id;
        }
        return '';
    }
    /**
     * Cached value of `sysinfo.device_id`  if set.
     */
    get name() {
        if (this.getSysInfo()) {
            return Buffer.from(this.getSysInfo().nickname, 'base64').toString('utf8');
        }
        return '';
    }
    get model() {
        if (this.getSysInfo()) {
            return this.getSysInfo().model;
        }
        return '';
    }
    get serialNumber() {
        if (this.getSysInfo()) {
            return this.getSysInfo().hw_id;
        }
        return '';
    }
    get firmwareRevision() {
        if (this.getSysInfo()) {
            return this.getSysInfo().fw_ver;
        }
        return '';
    }
    get hardwareRevision() {
        if (this.getSysInfo()) {
            return this.getSysInfo().hw_ver;
        }
        return '';
    }
    setSysInfo(sysInfo) {
        this._plugSysInfo = sysInfo;
        this._plugSysInfo.last_update = Date.now();
    }
    getSysInfo() {
        return this._plugSysInfo;
    }
    handleError(errorCode, line) {
        //@ts-ignore
        const errorMessage = this.ERROR_CODES[errorCode];
        if (typeof errorCode === 'number' && errorCode === 0) {
            // success — not an error
            return true;
        }
        else if (typeof errorCode === 'number' && errorCode === 1003) {
            this.log.info('Trying KLAP Auth');
            this.is_klap = true;
        }
        else {
            this.log.error(line + ' Error Code: ' + errorCode + ', ' + errorMessage + ' ' + this.ip);
        }
        return false;
    }
    async sendRequest(payload) {
        if (this.tpLinkCipher) {
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
        }
        else {
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
    handleRequest(payload) {
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
                .then((res) => {
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
                }
                catch (error) {
                    return this.handleError(JSON.parse(decryptedResponse).error_code, '368');
                }
            })
                .catch((error) => {
                return this.handleError(error.message, '656');
            });
        }
        return new Promise((resolve, reject) => {
            reject();
        });
    }
    handleKlapRequest(payload) {
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
                        }
                        catch (e) {
                            this.log.debug('KLAP could not decrypt error response: ' + e.message);
                        }
                    }
                    this.log.debug('KLAP request returned non-buffer response: ' + typeof res);
                    return false;
                }
                return JSON.parse(this.newTpLinkCipher.decrypt(res));
            })
                .catch((error) => {
                return this.handleError(error.message, '671');
            });
        }
        return new Promise((resolve, reject) => {
            reject();
        });
    }
    async reconnect() {
        this._reconnect_counter++;
        return this.handshake().then(() => {
            this.login().then(() => {
                return;
            });
        });
    }
    async newReconnect() {
        this._reconnect_counter++;
        return this.handshake_new().then(() => {
            return;
        });
    }
    // Generic command method - returns full response
    async sendCommand(method, params) {
        const payload = JSON.stringify({
            method,
            params: params || {},
            terminalUUID: this.terminalUUID,
            requestTimeMils: Math.round(Date.now() * 1000),
        });
        const handler = this.tpLinkCipher
            ? () => this.handleRequest(payload)
            : () => this.handleKlapRequest(payload);
        const doReconnect = this.tpLinkCipher
            ? () => this.reconnect()
            : () => this.newReconnect();
        try {
            const response = await handler();
            return response?.result ?? response;
        }
        catch (error) {
            if (error.message?.includes('9999') && this._reconnect_counter <= 3) {
                await doReconnect();
                const response = await handler();
                return response?.result ?? response;
            }
            this._reconnect_counter = 0;
            throw error;
        }
    }
    // --- Plug features ---
    async setLedEnabled(enabled) {
        return this.sendCommand('set_led_info', { led_rule: enabled ? 'always' : 'never' });
    }
    async getLedInfo() {
        return this.sendCommand('get_led_info');
    }
    async setAutoOff(enabled) {
        return this.sendCommand('set_auto_off_config', { enable: enabled });
    }
    async setAutoOffDelay(minutes) {
        return this.sendCommand('set_auto_off_config', { enable: true, delay_min: minutes });
    }
    async setChildProtection(enabled) {
        return this.sendCommand('set_child_protection', { enable: enabled });
    }
    async setPowerProtection(enabled) {
        return this.sendCommand('set_protection_power', { enabled });
    }
    async setPowerProtectionThreshold(watts) {
        return this.sendCommand('set_protection_power', { enabled: true, protection_power: watts });
    }
    async getEmeterData() {
        return this.sendCommand('get_emeter_data');
    }
    // --- Light features ---
    async setLightEffect(effectId) {
        if (effectId === 'off' || effectId === 'Off') {
            return this.sendCommand('set_dynamic_light_effect_rule_enable', { enable: false });
        }
        return this.sendCommand('set_dynamic_light_effect_rule_enable', { enable: true, id: effectId });
    }
    async setGradualOnOff(enabled) {
        return this.sendCommand('set_on_off_gradually_info', {
            on_state: { enable: enabled },
            off_state: { enable: enabled },
        });
    }
    // --- Fan features ---
    async setFanSpeedLevel(level) {
        return this.sendCommand('set_device_info', { device_on: level > 0, fan_speed_level: level });
    }
    async setFanSleepMode(enabled) {
        return this.sendCommand('set_device_info', { fan_sleep_mode_on: enabled });
    }
    // --- Hub alarm ---
    async playAlarm() {
        return this.sendCommand('play_alarm');
    }
    async stopAlarm() {
        return this.sendCommand('stop_alarm');
    }
    async setAlarmVolume(volume) {
        return this.sendCommand('set_alarm_configure', { volume });
    }
    async setAlarmDuration(duration) {
        return this.sendCommand('set_alarm_configure', { duration });
    }
    // --- Thermostat ---
    async setTargetTemperature(temp) {
        return this.sendCommand('set_device_info', { target_temp: temp, frost_protection_on: false });
    }
    async setTemperatureOffset(offset) {
        return this.sendCommand('set_device_info', { temp_offset: offset });
    }
    async setFrostProtection(enabled) {
        return this.sendCommand('set_device_info', { frost_protection_on: enabled });
    }
    // --- Firmware ---
    async setAutoUpdate(enabled) {
        return this.sendCommand('set_auto_update_info', { enable: enabled });
    }
    // --- Generic child device command ---
    async sendChildCommand(deviceId, method, params) {
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
    reAuthenticate() {
        this.log.debug('Reauthenticating');
        if (this.is_klap) {
            this.handshake_new()
                .then(() => {
                this.log.info('KLAP Authenticated successfully');
            })
                .catch(() => {
                this.log.error('KLAP Handshake New failed');
                this.is_klap = false;
            });
        }
        else {
            this.handshake().then(() => {
                this.login()
                    .then(() => {
                    this.log.info('Authenticated successfully');
                })
                    .catch(() => {
                    this.log.error('Login failed');
                });
            });
        }
    }
}
exports.default = P100;
//# sourceMappingURL=p100.js.map