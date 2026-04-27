# lpac

lpac is a cross-platform local profile agent program, compatible with [SGP.22 version 2.2.2](https://www.gsma.com/solutions-and-impact/technologies/esim/wp-content/uploads/2020/06/SGP.22-v2.2.2.pdf).

## Zero-Knowledge (ZK) eSIM Profile Support

lpac includes specialized support for Zero-Knowledge eSIM provisioning workflows. ZK profiles can be provisioned through a series of cryptographic phases that maintain privacy and security:

### ZK Profile Phases

- **Order Phase** (`profile zk-order`): Initial profile ordering request to the MNO server, obtaining profile identifiers and metadata
- **Registration Phase** (`profile zk-register`): ZK-based authentication and registration with MNO, using cryptographic commitments and partial signatures
- **Certificate Initialization Phase** (`profile zk-certinit`): Secure certificate chain establishment and validation with the eUICC
- **Download Phase** (`profile zk-download`): Final profile package download and installation on the eUICC

These phases leverage ES10b (eUICC-side ZK operations) and ES12p (server-side ZK challenge/response) protocols for privacy-preserving profile provisioning.

## Features:

- Support Activation Code and Confirmation Code
- Support Custom IMEI sent to server
- Support Profile Discovery (SM-DS)
- Profile management: list, enable, disable, delete and nickname
- Notification management: list, send and delete
- Lookup eUICC chip info
- etc

## Usage

You can download lpac from [GitHub Release][latest], and read [USAGE](docs/USAGE.md) to use it.
If you can't run it you need to compile by yourself, see also [DEVELOPERS](docs/DEVELOPERS.md).
If you want to known which Linux distributions include lpac, see also [LINUX-DIST](docs/LINUX-DIST.md).
If you have any issue, please read [FAQ](docs/FAQ.md) first.

[latest]: https://github.com/estkme-group/lpac/releases/latest

## Software Ecosystem

- [EasyLPAC] (Windows, Linux and macOS)
- [{Open,Easy}EUICC][openeuicc] ([Mirror][openeuicc-mirror], Android)
- [eSIM Manager (lpa-gtk)](https://codeberg.org/lucaweiss/lpa-gtk) (Linux Mobile)
- [rlpa-server](https://github.com/estkme-group/rlpa-server) for eSTK.me Cloud Enhance function

[easylpac]: https://github.com/creamlike1024/EasyLPAC/releases/latest
[openeuicc]: https://gitea.angry.im/PeterCxy/OpenEUICC
[openeuicc-mirror]: https://github.com/estkme-group/openeuicc

## Thanks

[![Contributors][contrib]][contributors]

[contrib]: https://contrib.rocks/image?repo=estkme-group/lpac
[contributors]: https://github.com/estkme-group/lpac/graphs/contributors

---

## License

See [REUSE.toml](REUSE.toml) and comment header of files for details.

Copyright &copy; 2023-2025 ESTKME TECHNOLOGY LIMITED, Hong Kong
