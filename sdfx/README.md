# SDFX — CryptoKit SoftHSM Core

SDFX is the C SDK, daemon, transport, protocol, key-storage, and test layer used by CryptoKit SoftHSM. It exposes a GM/T 0018-2023-style `SDF_*` API and sends operations to the `sdfxd` process. Cryptographic primitives execute through the bundled openHiTLS runtime.

This fork is intended for development, interoperability testing, education, and application integration. It is not a certified commercial cryptographic module or a hardware security boundary.

## Current architecture

```text
Application
    │ SDF_* C API
    ▼
libsdfx / sdfapi_x64.dll
    │ fixed-width protocol v2
    ▼
sdfxd
    ├── device and session manager
    ├── SM2/RSA internal-key managers
    ├── session-key and user-file managers
    ├── token-authenticated private management commands
    └── openHiTLS cryptographic engine
```

The Docker distribution uses TCP `0.0.0.0:18081`. The Web backend connects to `127.0.0.1:18081` from inside the same container and exposes browser management on `0.0.0.0:18080`. `127.0.0.1` is correct for this internal client connection; it must not be changed to `0.0.0.0`.

No separate Unix administration listener or management CLI is shipped. The source transport abstraction can still be built with Unix socket transport for SDF traffic, but the supported CryptoKit container profile explicitly selects TCP.

## Implemented SDF capabilities

| Area | Implemented operations |
| --- | --- |
| Device/session | Open/close device, open/close session, device information |
| Random | openHiTLS random generation |
| Hash | Standard SM3/SHA-256 plus SDFX-extension SHA-1/224/384/512, including SM2 ZA message preprocessing |
| SM4 | ECB, CBC, CFB, OFB, CTR, XTS, GCM, CCM, CBC-MAC, HMAC-SM3; one-shot and streaming |
| SM2 external | Key generation, encrypt/decrypt, sign/verify |
| SM2 internal | Sign/encryption public-key export, private access, internal sign/verify, IPK/EPK/ISK session-key wrapping |
| RSA | 1024–2048-bit key generation, external/internal public/private operations, public-key export, IPK/EPK/ISK session-key wrapping |
| Symmetric wrapping key | `SDF_GenerateKeyWithKEK`, `SDF_ImportKeyWithKEK`, and session-key destruction |
| User files | Create, offset read/write, delete |
| ECC agreement | SM2 sponsor/response flow with static and temporary keys |
| External-key extensions | One-shot/streaming SM4 and external-key HMAC initialization |
| Appendix C | IKE, IPSEC, SSL and their external-SM2-public-key wrapped variants |

All public GM/T 0018 declarations except SM9 have client, protocol, and daemon implementations. SM9 declarations remain ABI-visible and return `SDR_NOTSUPPORT`. The authoritative per-interface status and validation limits are maintained in [`../api-matrix.md`](../api-matrix.md).

Algorithm identifiers follow GM/T 0006-2023: `SGD_SM2_1/2/3` are
`0x00020200/0x00020400/0x00020800`, and `SGD_SM4_XTS` is `0x01000400`.
The teaching-only SHA-1/224/384/512 algorithms use `SDFX_*` identifiers in the
standard's custom hash range (`0x20` through `0xFF`). Deprecated `SGD_SHA*`
spellings remain source aliases only and no longer use non-standard values
`2/3/5/6`. HMAC accepts the standard `SGD_SM3_HMAC` and
`SGD_SHA256_HMAC` identifiers.

## Internal keys and integrity

SM2 and RSA signing/encryption key pairs are independent and may use different indices from 1 through 1024. The Web security administrator can create, enable, disable, delete, export public keys, change access codes, verify integrity, and move a key to another index.

A private-key access code may be empty. An empty code means the application does not need to acquire password-based access; it does not mean the private key is stored in plaintext. Password-protected records derive their encryption secret from the access code and random salt. Passwordless records derive it from the device integrity key. Private material is encrypted with SM4-CTR.

Every persistent SM2/RSA record includes its algorithm, purpose, index, public key, encrypted private key, and metadata in an HMAC-SM3 integrity value. Each persistent SM4 symmetric wrapping-key record likewise protects its record version, algorithm, bit length, index, and key material with HMAC-SM3; legacy raw 16-byte KEK files are migrated when first read. A record that fails verification is rejected before cryptographic use. The HMAC key is the 32-byte device integrity key created by the Web initialization command. It has no management export or change operation and is removed only by a full device reset. Moving a passwordless asymmetric record also re-encrypts it for the new index.

The Web UI separates “非对称密钥” (asymmetric keys) from “对称密钥” (symmetric keys), labels the public-key action “导出公钥”, and provides explicit integrity verification for both record types. The underlying standard API and internal source identifiers retain the term KEK for compatibility.

## Web management roles

The private management protocol is consumed by the Web backend and protected by a 32-byte token generated at each container start. The token is stored only in `/run/sdfx/admin.token` and is not part of the persistent volume.

- Super administrator: first initialization and administrator management; backup/restore and factory reset are also available according to the product matrix.
- System administrator: status, device information, online SDF sessions, and maintenance.
- Security administrator: cryptographic self-tests and SM2/RSA/symmetric-key management.
- Audit administrator: audit settings, viewing, and UTF-8 TXT export.

The Web backend enforces role and CSRF checks for every protected API; hiding a page in the browser is not the authorization boundary.

## Source layout

```text
sdfx/
├── common/       configuration, logging, protocol helpers, openHiTLS init
├── include/      protocol and public/internal shared headers
├── sdk/          SDF client library
├── sdfxd/        daemon, cryptographic engines, key managers, admin commands
├── transport/    TCP/Unix/other transport abstraction
├── tests/        C integration tests
├── examples/     example programs
└── config/       daemon and test configuration files
```

Important current sources:

- `sdk/src/sdf_rsa.c`: implemented RSA SDF entry points;
- `sdk/src/sdf_extended.c`, `sdf_agreement.c`, and `sdf_vpn.c`: GM/T 0018 extended client APIs;
- `sdfxd/src/crypto_extended.c`, `crypto_agreement.c`, and `crypto_vpn.c`: server cryptographic state and derivation;
- `sdfxd/src/rsa_key_manager.c`: persistent protected RSA keys;
- `sdfxd/src/internal_key_manager.c`: protected SM2 keys and device integrity key;
- `sdfxd/src/protocol_handler.c`: standard and private command dispatch;
- `sdfxd/src/admin_protocol.inc`: token-authenticated management dispatch;
- `common/include/log.h`: structured runtime log format.

## Building

### Prerequisites

- CMake 3.16 or newer;
- a C11 compiler;
- Ninja or Make;
- SQLite3 development headers and library (required for the daemon, which
  writes external SDF call records into the web management audit database);
- an installed openHiTLS tree containing headers and libraries.

Configure the same TCP profile used by the container:

```bash
cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DOpenHiTLS_ROOT_DIR=/opt/openhitls \
  -DSDFX_TRANSPORT_TYPE=tcp \
  -DBUILD_DAEMON=ON \
  -DBUILD_SDK=ON \
  -DBUILD_TESTS=ON

cmake --build build
cmake --install build
```

The source-level CMake default remains `unix`; therefore always pass `-DSDFX_TRANSPORT_TYPE=tcp` when reproducing the Docker/Windows SDK deployment.

See [`docs/OPENHITLS_CONFIG.md`](docs/OPENHITLS_CONFIG.md) for dependency discovery options.

## Configuration

Container daemon configuration:

```ini
[transport]
tcp_host = 0.0.0.0
tcp_port = 18081

[daemon]
worker_threads = 8
max_clients = 100
session_timeout = 300
```

A client on another computer uses the server’s real LAN address in its `sdfx.conf` or `sdfapi.ini`. Only the daemon listener uses `0.0.0.0`; a client destination must be a concrete host name or IP address.

The Linux client searches:

1. `./sdfx.conf`;
2. `../config/sdfx.conf`;
3. `/etc/sdfx/sdfx.conf`;
4. built-in defaults when no file exists.

The Windows DLL additionally checks `./sdfapi.ini` and `./config/sdfapi.ini`.

## Running tests

The C integration tests require a running daemon. `test_key_file` expects symmetric wrapping key index 1. `test_internal_key` accepts:

```text
SDFX_TEST_SM2_PASSWORD=<test-only access code>
SDFX_TEST_KEY_INDEX=<index containing both test sign and encryption keys>
```

Run only against an isolated device volume:

```bash
export LD_LIBRARY_PATH=/path/to/sdfx/build/sdk:/opt/openhitls/lib
export SDFX_TEST_SM2_PASSWORD='test-only-password'
export SDFX_TEST_KEY_INDEX=9
ctest --test-dir build --output-on-failure
```

The repository release gate also runs `tests/rbac_integrity_e2e.py`, the Windows `test1.c` SM2 round-trip, `tests/rsa_e2e.c`, and the Windows DLL export checker. Current core verification includes device/session, random, hash/SM2 ZA, SM2, extended SM4/HMAC/AEAD, and all six Appendix C calls. Tests requiring persistent internal keys or KEKs must run against an initialized isolated volume.

## Logging

Runtime records contain:

- local timestamp and level;
- module, process and thread identifiers;
- function, source file, and line;
- for SDF requests: client, command, session, request/response byte counts, result code, and elapsed microseconds.

Passwords, key material, and protocol payloads are deliberately excluded. Web management audit records are stored separately in SQLite and can be filtered and exported as TXT by the audit administrator.

## Security and deployment boundaries

- TCP 18081 and HTTP 18080 do not provide built-in TLS or mutual authentication.
- Bind them only to trusted networks or protect them with firewalling and an HTTPS reverse proxy.
- `/var/lib/sdfx` is the persistent software security boundary. Reusing a named volume reuses administrators, password hashes, device keys, business keys, audit data, and files.
- Backups are validated but are not encrypted as a whole archive.
- A host or Docker administrator with volume access can read software-protected device secrets.
- Never put real credentials, private keys, tokens, or backup archives in source control or an image layer.

## Remaining work

Only SM9 declarations still return `SDR_NOTSUPPORT`. Remaining assurance work includes authoritative SM2 agreement and GM/T 0022/0024 VPN vectors, fuzzing, and wider interoperability testing. TLS for the SDF channel, certificate management, host network/time management, scheduled tasks, upgrade orchestration, and high availability remain outside the current implementation.

## License

SDFX source retains its existing Mulan PSL v2 notices. CryptoKit SoftHSM original additions and modifications are distributed under GNU AGPL v3.0 only (`AGPL-3.0-only`); the corresponding source is <https://github.com/sawanolin/cryptokit-soft-hsm>. The AGPL does not replace upstream licenses. Redistribution must preserve the repository `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md`, `sdfx/LICENSE`, and the bundled openHiTLS license and third-party notice.
