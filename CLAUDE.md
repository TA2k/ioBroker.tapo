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

- **Discovery**: POST / with `{"method":"login","params":{"sub_method":"discover"}}` → returns `pake:[2]`, `port:80`, `mac`, `tls:0`
- **Handshake** (3-step SPAKE2+ on NIST P-256):
  1. `pake_register`: POST / with `method:pake_register`, username=`md5("admin")` → server returns `dev_salt`, `iterations`, `server_identity`
  2. `pake_share`: POST / with `method:pake_share`, client_A point → server returns server_B point, `confirm_server`, `extra_crypt`
  3. `pake_confirm`: POST / with `method:pake_confirm`, client_confirm → server returns `stok` session token, `start_seq`
- **Credentials**:
  - Username: always `md5("admin")` for plugs (NOT md5(email))
  - Password: derived via PBKDF2-SHA256(sha1(raw_password), dev_salt, iterations) → w0/w1
  - `extra_crypt.passwd_id=2`: use `sha1(raw_password)` as credential before PBKDF2
- **Crypto**:
  - SPAKE2+ M/N points: standard P-256 generator points (see RFC 9382)
  - Session keys: HKDF-SHA256 from shared secret → encrypt_key (16B) + decrypt_key (16B)
  - Nonce: 12-byte base_nonce with last 4 bytes = big-endian sequence number
  - Encryption: AES-128-CCM with tag_length=8, auth_tag_length=8
- **Requests**: POST /stok=TOKEN/ds with Content-Type: application/octet-stream
  - Payload: 4-byte BE sequence + AES-CCM(JSON plaintext)
  - Response: 4-byte BE sequence + AES-CCM(JSON response)

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
- Python test script: `test_handshake.py` (KLAP v1/v2 handshake test)
- python-kasa venv at `.references/python-kasa-master/.venv/`
- Test with: `uv run python3 -c "..."` from python-kasa-master directory
