# ioBroker.tapo

## Project Overview
ioBroker adapter for TP-Link Tapo devices (smart plugs, bulbs, cameras, fans, hubs, thermostats).
Communicates with devices locally via three protocols depending on device/firmware.

## Architecture

### Device Protocols (4 types)
1. **AES SecurePassthrough** (old, legacy) — RSA handshake + AES-CBC encrypted JSON over HTTP port 80
2. **KLAP v1** (md5) — Binary protocol with seed exchange over HTTP port 80
3. **KLAP v2** (sha256) — Same as v1 but sha256-based auth hashes
4. **TPAP/SPAKE2+** (newest, FW 1.4.3+) — SPAKE2+ key exchange + AES-128-CCM encrypted binary over HTTP port 80
   - Used by P100 FW 1.4.3+, potentially other devices with `pake:[2]` in discovery
   - Camera variant uses HTTPS port 443 with cnonce/nonce/digest login (old TPAP/stok)

### TPAP/SPAKE2+ Protocol Details

- **Discovery**: POST / with `{"method":"login","params":{"sub_method":"discover"}}` → returns `pake:[0|1|2|3|5]`, `port:80`, `mac`, `tls:0|1`, `user_hash_type:0|1`
- **Handshake** (2-step SPAKE2+ on NIST P-256 or P-384):
  1. `pake_register`: POST / with `method:pake_register`, username hash, cipher_suites, encryption, passcode_type → server returns `dev_salt`, `dev_share`, `dev_random`, `iterations`, `extra_crypt`, negotiated `cipher_suites`, `encryption`
  2. `pake_share`: POST / with `method:pake_share`, `user_share` (L point), `user_confirm` (MAC) → server returns `dev_confirm`, `sessionId`/`stok`, `start_seq`
- **Username**:
  - `user_hash_type=0` (default): `md5(username)`
  - `user_hash_type=1`: `sha256(username).toUpperCase()`
  - Plugs (pake:[0,2,5]): username = "admin"
  - SmartCam (pake:[1,3]): username = configured email or "admin"
- **passcode_type** (from pake list):
  - `pake:[0]` → `"default_userpw"` (MAC-derived default passcode)
  - `pake:[1]` → `"userpw"` (setup code / raw password)
  - `pake:[2,5]` → `"userpw"` (user password with extra_crypt)
  - `pake:[3]` → `"shared_token"` (md5 of password)
- **Candidate secrets** (tried in order until handshake succeeds):
  - `pake:[0]`: HKDF-SHA256(seed+mac_bytes, salt="tp-kdf-salt-default-passcode", info="tp-kdf-info-default-passcode").hex().toUpperCase()
  - `pake:[1]`: raw password
  - `pake:[2]`: [raw_password, md5(password), sha256(password).toUpperCase()]
  - `pake:[3]`: md5(password)
- **extra_crypt** (from register response, transforms candidate before PBKDF2):
  - `password_shadow` with `passwd_id`:
    - 1: md5_crypt ($1$salt$...)
    - 2: sha1(candidate)
    - 3: sha1(md5(username) + "_" + MAC_WITH_COLONS)
    - 5: sha256_crypt ($5$salt$...)
  - `password_authkey`: XOR(candidate, tmpkey) mapped through dictionary
  - `password_sha_with_salt`: sha256(name + decoded_salt + candidate) where name="admin"|"user"
  - No extra_crypt, generic TPAP: "username/candidate" format
  - No extra_crypt, smartcam: candidate as-is
- **Crypto**:
  - Cipher suites 1-9: SHA-256/SHA-512 hash, HMAC/CMAC-AES confirmation, P-256/P-384 curves
  - Encryptions: aes_128_ccm, aes_256_ccm, chacha20_poly1305
  - SPAKE2+ M/N points: standard P-256/P-384 generator points (RFC 9382)
  - Session keys: HKDF from shared secret with cipher-specific salt/info
  - Nonce: 12-byte base_nonce with last 4 bytes = big-endian sequence number
  - Tag length: 16 bytes for all ciphers
  - `encodeW(w0)`: minimal big-endian encoding, skip 0x00 prefix when byte length is even
- **Requests**: POST /stok=TOKEN/ds with Content-Type: application/octet-stream
  - Payload: 4-byte BE sequence + ciphertext + 16-byte tag
  - Response: 4-byte BE sequence + ciphertext + 16-byte tag

### Protocol Detection

- Old AES handshake returns error_code 1003 → device needs KLAP or TPAP
- KLAP handshake1 returns HTTP 403 → device needs TPAP/SPAKE2+
- Discovery `pake:[2]` → device supports TPAP/SPAKE2+
- Device discovery reports `encrypt_type`: "KLAP" or "TPAP"

### Class Hierarchy
- `P100` (base) → all non-camera devices (P110, L510E, L520E, L530)
  - Supports: AES SecurePassthrough + KLAP v1/v2 + TPAP/SPAKE2+
  - `TpapCipher` class handles SPAKE2+ handshake and AES-CCM encrypt/decrypt
- `TAPOCamera` → camera devices (C210, C310, etc.)
  - Supports: TPAP/stok protocol over HTTPS (old camera variant)
  - Uses `undici` fetch with special TLS ciphers

### Key Files

- `src/lib/utils/p100.ts` — Base class, AES + KLAP + TPAP handshake
- `src/lib/utils/tpapCipher.ts` — TPAP/SPAKE2+ handshake + AES-CCM encryption
- `src/lib/utils/newTpLinkCipher.ts` — KLAP v1/v2 encryption
- `src/lib/utils/camera/tapoCamera.ts` — Camera TPAP/stok protocol (old camera variant)
- `src/main.ts` — Adapter main: device discovery, initialization, polling

### Reference Libraries

- `.references/pytapo-main/` — pytapo Python library (3 transports: kasa, klap, pytapo/TPAP)
- `.references/python-kasa-master/` — python-kasa (KLAP v1/v2, discovery)
- `.references/python-kasa-feature-tpap/` — python-kasa TPAP feature branch (SPAKE2+ reference implementation)

## Important Patterns
- `json2iob.parse()` for creating ioBroker states from JSON — preferred over manual setState
- `sendCommand()` on P100 for generic Tapo local API calls with reconnect logic
- Camera uses `apiRequest()` for multipleRequest-style calls
- `deviceObjects` is a dynamic dispatch map: `deviceObject[command](state.val)`
- Error logging: use `log.error` + return, don't throw in device communication code (adapter must not crash)
- `handleError()` returns boolean, does not throw

## Known Issues

- KLAP handshake returning HTTP 403 = wrong protocol (device needs TPAP), NOT device lock
- Error code 1003 from AES handshake means "use different protocol" (KLAP or TPAP)

## Build & Deploy
- Build: `npx tsc -p tsconfig.build.json`
- Deploy locally: `cp -r build/* /usr/local/iobroker/node_modules/iobroker.tapo/build/`
- Restart: `iobroker restart tapo`
- Logs: `iobroker logs tapo --lines 50`
- ALWAYS build before push and before deploy

## Testing

- TPAP test script: `test_tpap.js` (SPAKE2+ handshake + get_device_info via TpapCipher class)
- Python test script: `test_handshake.py` (KLAP v1/v2 handshake test)
- python-kasa venv at `.references/python-kasa-master/.venv/`
- Test with: `uv run python3 -c "..."` from python-kasa-master directory
