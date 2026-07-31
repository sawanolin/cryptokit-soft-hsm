# Third-Party Notices

This document records the third-party source included in CryptoKit SoftHSM and
the notices that must accompany source and binary redistributions.

## Project additions and modifications

Copyright (C) 2026 sawanolin and CryptoKit SoftHSM contributors.

This copyright statement applies only to original files and modifications made
for CryptoKit SoftHSM. It does not claim ownership of SDFX, openHiTLS, the
GM/T 0018-2023 standard, or other third-party material.

CryptoKit SoftHSM original additions and modifications are licensed under the
[GNU Affero General Public License, Version 3 only](LICENSE)
(`AGPL-3.0-only`). The corresponding source repository is
<https://github.com/sawanolin/cryptokit-soft-hsm>.

The original SDFX and openHiTLS material remains under its existing license.
The AGPL license for the CryptoKit work does not erase or replace upstream
copyright, license, patent, trademark, or disclaimer notices.

## Bundled components

### SDFX

- Project: SDFX - Software Cryptographic Device Framework
- Upstream: <https://gitcode.com/openHiTLS/sdfx>
- License: Mulan PSL v2
- Bundled source: `sdfx/`
- Bundled license: [`sdfx/LICENSE`](sdfx/LICENSE)
- Existing source notices: `Copyright (C) 2025 SDFX Project`

The bundled SDFX snapshot has been modified for CryptoKit SoftHSM. Material
changes include:

- protocol version 2 with fixed-width network fields and opaque remote handles;
- server-side session keys and HMAC-SM3-protected persistent SM4/SM2/RSA key records;
- expanded GM/T 0018-style RSA, SM2, SM3, SM4, MAC, session-key, and user-file operations;
- private token-authenticated commands used by the four-role Web management plane;
- device-rooted HMAC-SM3 integrity over protected key records and indices;
- passwordless or password-protected private-key access, reindexing, and verification;
- Web-only management instead of a separately shipped Unix administration UI;
- backup, validated restore, device reset, structured audit/TXT export, detailed runtime logging, and online RSA/SM2/SM3/SM4/random self-tests;
- Windows x64 TCP transport, DLL build, import library, SM2/RSA examples, and export verification;
- Docker packaging, health checks and end-to-end tests.

The source snapshot did not retain Git metadata in this workspace, so its exact
upstream commit cannot be proven from local files alone. Before the first public
release, the maintainer should compare the snapshot with the upstream repository
and record the matching commit or source archive digest in this document.

### openHiTLS

- Project: openHiTLS
- Upstream: <https://gitcode.com/openhitls/openhitls>
- Website: <https://openhitls.net>
- License: Mulan PSL v2
- Bundled source: `openhitls/`
- Bundled license: [`openhitls/LICENSE`](openhitls/LICENSE)
- Bundled third-party notice:
  [`openhitls/Third_Party_Open_Source_Software_Notice`](openhitls/Third_Party_Open_Source_Software_Notice)

The bundled header `openhitls/include/bsl/bsl_version.h` identifies the runtime
source as `openHiTLS 0.4.0 31 Mar. 2026`. The bundled release document still
mentions 0.3.0, and the workspace does not contain upstream Git metadata.
Accordingly, the exact upstream commit should be recorded when it can be
identified.

CryptoKit SoftHSM builds openHiTLS from the bundled source and copies its
runtime libraries into the Linux container. The Windows SDF client DLL does not
link openHiTLS; cryptographic operations execute in the Linux service.

openHiTLS includes test certificates and private-key fixtures in its upstream
test data. They are public test material, not CryptoKit SoftHSM production
credentials. Their original notices and directory structure must be preserved.

## License and source-availability obligations

CryptoKit SoftHSM original work is distributed under `AGPL-3.0-only`. Source and object-code
redistribution must follow the AGPL, and modified versions used to provide a
service over a network must prominently offer their users the Corresponding
Source as required by section 13. The official project source is:

<https://github.com/sawanolin/cryptokit-soft-hsm>

The Mulan PSL v2 notices for bundled SDFX and openHiTLS material must also be
retained, and recipients must receive the applicable upstream license copies.

This repository satisfies that structure by keeping:

- `LICENSE`;
- `NOTICE`;
- this `THIRD_PARTY_NOTICES.md`;
- `sdfx/LICENSE` and existing SDFX source headers;
- `openhitls/LICENSE`;
- `openhitls/Third_Party_Open_Source_Software_Notice`;
- other copyright and attribution notices already present in bundled source.

Do not remove these files when creating source archives, GitHub Releases,
Docker images, SDK packages, or downstream redistributions.

## Binary distributions

The Linux Docker image must install the notices under:

```text
/usr/share/licenses/cryptokit-soft-hsm/
```

The Windows x64 SDK package must include them under:

```text
licenses/
```

Downstream distributors should reproduce the same files in accompanying
documentation or another location that recipients can readily access.

## Standards material

References to GM/T 0018-2023 identify the interface specification implemented
by this project. They do not imply certification, endorsement, or ownership of
the standard.

The local file below is excluded from the initial Git publication unless the
maintainer separately confirms public redistribution rights:

```text
GMT 0018-2023 密码设备应用接口规范.json
```

Excluding that file does not affect the independently written implementation
matrix or source code.

## Trademarks and endorsement

No project or upstream license grants a trademark license. Names such as
openHiTLS, SDFX, GitHub, Docker, Windows, and CryptoKit are used only to identify projects, platforms,
or compatibility targets. No upstream contributor sponsors or endorses this
modified distribution unless separately stated in writing.

## Warranty

The software and contributions are provided without warranties. Consult the
AGPL v3 text, the applicable Mulan PSL v2 texts, and each bundled notice for
the controlling disclaimers and limitations of liability.
