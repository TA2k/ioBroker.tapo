export type TAPOCameraGetRequest = {
  method: string;
  params?: Record<string, any>;
};

export type TAPOCameraSetRequest = {
  method: string;
  params?: Record<string, any>;
};

export type TAPOCameraUnencryptedRequest = {
  method: 'multipleRequest';
  params: {
    requests: (TAPOCameraGetRequest | TAPOCameraSetRequest)[];
  };
};

export type TAPOCameraDoRequest = {
  method: string;
  [key: string]: any;
};

export type TAPOCameraEncryptedRequest = {
  method: 'securePassthrough';
  params: {
    request: string;
  };
};

export type TAPOCameraRequest = TAPOCameraUnencryptedRequest | TAPOCameraEncryptedRequest | TAPOCameraDoRequest;

export type TAPOCameraEncryptedResponse = {
  result?: {
    response: string;
  };
};

export type TAPOBasicInfo = {
  device_type: string;
  device_model: string;
  device_name: string;
  device_info: string;
  hw_version: string;
  sw_version: string;
  device_alias: string;
  avatar: string;
  longitude: number;
  latitude: number;
  has_set_location_info: boolean;
  features: string;
  barcode: string;
  mac: string;
  dev_id: string;
  oem_id: string;
  hw_desc: string;
};

export type TAPOCameraResponseDeviceInfo = {
  method: 'getDeviceInfo';
  result: {
    device_info: {
      basic_info: TAPOBasicInfo;
    };
  };
  error_code: number;
};

export type TAPOCameraLoginResponse = {
  error_code?: number;
  result?: {
    data?: {
      encrypt_type?: string;
      nonce?: string;
    };
  };
};

export type TAPOCameraRefreshStokResponse = {
  error_code?: number;
  data?: {
    code?: number;
    sec_left?: number;
  };
  result?: {
    start_seq?: number;
    user_group?: string;
    stok?: string;
    responses?: Array<any>;
    data?: {
      code?: number;
      nonce?: string;
      device_confirm?: string;
      sec_left?: number;
    };
  };
};

export type TAPOCameraResponse = {
  result: {
    error_code: number;
    responses: Array<any>;
  };
  error_code: number;
};
