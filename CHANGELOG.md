# Changelog

## [0.14.0](https://github.com/chinmina/chinmina-bridge/compare/v0.13.0...v0.14.0) (2026-08-22)


### Features

* gate startup on the first profile generation ([#371](https://github.com/chinmina/chinmina-bridge/issues/371)) ([1c20946](https://github.com/chinmina/chinmina-bridge/commit/1c20946d0279034af46f8ebe3c3270de3ba5de7f))
* record why a profile is unavailable on the audit entry ([#369](https://github.com/chinmina/chinmina-bridge/issues/369)) ([91c18f9](https://github.com/chinmina/chinmina-bridge/commit/91c18f9d036f3a486e49f1d670215125029bc54a))
* support _FILE variants for static JWKS and GitHub app private key ([#375](https://github.com/chinmina/chinmina-bridge/issues/375)) ([9a45a67](https://github.com/chinmina/chinmina-bridge/commit/9a45a67f5f2ef2352e770c46ea9ce4a5b64a28cf))


### Bug Fixes

* run shutdown hooks on every exit path ([#370](https://github.com/chinmina/chinmina-bridge/issues/370)) ([ad60bf0](https://github.com/chinmina/chinmina-bridge/commit/ad60bf0034e760909ccd864a839de164802b3687))

## [0.13.0](https://github.com/chinmina/chinmina-bridge/compare/v0.12.1...v0.13.0) (2026-08-14)


### Features

* add release-notes skill for augmented GitHub releases ([#340](https://github.com/chinmina/chinmina-bridge/issues/340)) ([18ac817](https://github.com/chinmina/chinmina-bridge/commit/18ac817069ac2bb7ee10f0596bea3cfd92d7ad83))


### Bug Fixes

* **deps:** update aws-sdk-go-v2 ([#352](https://github.com/chinmina/chinmina-bridge/issues/352)) ([2ecda6f](https://github.com/chinmina/chinmina-bridge/commit/2ecda6f318dd6d89ba6038d4916c73653d47700f))
* **deps:** update dependency cosign to v3.1.3 ([#348](https://github.com/chinmina/chinmina-bridge/issues/348)) ([ef99794](https://github.com/chinmina/chinmina-bridge/commit/ef997947436578e2258da919fadda9ba24aa03aa))
* **deps:** update dependency go to v1.26.6 ([#361](https://github.com/chinmina/chinmina-bridge/issues/361)) ([1b471a3](https://github.com/chinmina/chinmina-bridge/commit/1b471a362cad1dfa83df83001ba7c259dfb53f94))
* **deps:** update dependency goreleaser to v2.17.1 ([#349](https://github.com/chinmina/chinmina-bridge/issues/349)) ([6824860](https://github.com/chinmina/chinmina-bridge/commit/68248609f32aa5954a980762fe3e9b4289a31f94))
* **deps:** update dependency just to v1.58.0 ([#353](https://github.com/chinmina/chinmina-bridge/issues/353)) ([8aed62d](https://github.com/chinmina/chinmina-bridge/commit/8aed62dfc6eab9a05dbd738454e29501eb4f03de))
* **deps:** update github-actions ([#347](https://github.com/chinmina/chinmina-bridge/issues/347)) ([3d30c23](https://github.com/chinmina/chinmina-bridge/commit/3d30c2363920540821d4ad3fc170ddc1b1286f68))
* **deps:** update jwx-and-auth0-jwt-middleware ([#354](https://github.com/chinmina/chinmina-bridge/issues/354)) ([1b3c441](https://github.com/chinmina/chinmina-bridge/commit/1b3c441f0a89ba7e7fdf86210f59249c8ecf2cfc))
* **deps:** update module github.com/buildkite/go-buildkite/v5 to v5.11.0 ([#355](https://github.com/chinmina/chinmina-bridge/issues/355)) ([fb6ce65](https://github.com/chinmina/chinmina-bridge/commit/fb6ce65a83f796f9ecd8f7962e5dd7a81bbaa03a))
* **deps:** update module github.com/go-logr/logr to v1.4.4 ([#350](https://github.com/chinmina/chinmina-bridge/issues/350)) ([5598ae0](https://github.com/chinmina/chinmina-bridge/commit/5598ae015b459af2110f8e39de6706b767a157e3))
* **deps:** update module github.com/google/go-github/v89 to v90 ([#357](https://github.com/chinmina/chinmina-bridge/issues/357)) ([371e4bc](https://github.com/chinmina/chinmina-bridge/commit/371e4bc83df5e7fac20b4ec59639e6f26c1d4b3d))
* **deps:** update module github.com/grafana/pyroscope-go to v1.4.2 ([#362](https://github.com/chinmina/chinmina-bridge/issues/362)) ([41804d6](https://github.com/chinmina/chinmina-bridge/commit/41804d68ca8b58e105b72da9fd62acd4341b3ff2))
* **deps:** update module github.com/phuslu/log to v1.0.128 ([#351](https://github.com/chinmina/chinmina-bridge/issues/351)) ([479ee21](https://github.com/chinmina/chinmina-bridge/commit/479ee21c29178ff1ad3c47c7ab0b20fa44f1d11c))
* **deps:** update module github.com/sethvargo/go-envconfig to v1.4.3 ([#363](https://github.com/chinmina/chinmina-bridge/issues/363)) ([f0a3a8e](https://github.com/chinmina/chinmina-bridge/commit/f0a3a8e8c74f03c4c6ff3a08dca1179c78b05bd9))
* **deps:** update module github.com/testcontainers/testcontainers-go to v0.44.0 ([#364](https://github.com/chinmina/chinmina-bridge/issues/364)) ([6581c43](https://github.com/chinmina/chinmina-bridge/commit/6581c436c52d850529286e6db8c9b58db493bdb9))
* **deps:** update module github.com/tink-crypto/tink-go/v2 to v2.8.0 ([#365](https://github.com/chinmina/chinmina-bridge/issues/365)) ([71a34da](https://github.com/chinmina/chinmina-bridge/commit/71a34dadcb82c87ee38eec9a562e1b1d38e20dbc))
* **deps:** update opentelemetry ([#356](https://github.com/chinmina/chinmina-bridge/issues/356)) ([79d722f](https://github.com/chinmina/chinmina-bridge/commit/79d722fc98834b11a1cc25b33649e2264a18365d))
* remove potential race when configuration reloads ([#360](https://github.com/chinmina/chinmina-bridge/issues/360)) ([3102538](https://github.com/chinmina/chinmina-bridge/commit/310253895f6ff350e252eca481e6a0d5fc85ca5d))

## [0.12.1](https://github.com/chinmina/chinmina-bridge/compare/v0.12.0...v0.12.1) (2026-08-12)


### Bug Fixes

* **deps:** pin GitHub Actions dependencies ([#346](https://github.com/chinmina/chinmina-bridge/issues/346)) ([4160495](https://github.com/chinmina/chinmina-bridge/commit/4160495f4be1d7f2dc309835eaf0f1c7062dd7d6))
* **vendor:** evaluate profile match rules outside the token cache ([#358](https://github.com/chinmina/chinmina-bridge/issues/358)) ([a2c4bcb](https://github.com/chinmina/chinmina-bridge/commit/a2c4bcbfa2fe6cd16756375157e490fe1d8386c8))

## [0.12.0](https://github.com/chinmina/chinmina-bridge/compare/v0.11.0...v0.12.0) (2026-07-20)

### Features

* adopt shared release pipeline toolchain and version config ([#324](https://github.com/chinmina/chinmina-bridge/issues/324)) ([1322dbc](https://github.com/chinmina/chinmina-bridge/commit/1322dbc63fd8054c5360ccdbe49552d3c9b2dada))

### Bug Fixes

* **deps:** bump golang.org/x/crypto to v0.52.0 ([#343](https://github.com/chinmina/chinmina-bridge/issues/343)) ([0cbb08a](https://github.com/chinmina/chinmina-bridge/commit/0cbb08a568f63b710850e905a3b30f694c285540))
* **deps:** update aws-sdk-go-v2 ([#328](https://github.com/chinmina/chinmina-bridge/issues/328)) ([550eaf3](https://github.com/chinmina/chinmina-bridge/commit/550eaf340ba1782ca4c488d3beae24fb692c279e))
* **deps:** update dependency cosign to v3 ([#334](https://github.com/chinmina/chinmina-bridge/issues/334)) ([8cc7c04](https://github.com/chinmina/chinmina-bridge/commit/8cc7c04479ba992effbfc387ae1f280910ebf273))
* **deps:** update dependency golangci-lint to v2.12.2 ([#331](https://github.com/chinmina/chinmina-bridge/issues/331)) ([9c3a77f](https://github.com/chinmina/chinmina-bridge/commit/9c3a77fa4c84eb3439e17c51fe3ab72bbce544c3))
* **deps:** update github-actions (major) ([#339](https://github.com/chinmina/chinmina-bridge/issues/339)) ([011ad4e](https://github.com/chinmina/chinmina-bridge/commit/011ad4e4f034a578b42ad688a57f1eb4d7a123b4))
* **deps:** update module github.com/auth0/go-jwt-middleware/v3 to v3.2.0 ([#337](https://github.com/chinmina/chinmina-bridge/issues/337)) ([daebc05](https://github.com/chinmina/chinmina-bridge/commit/daebc0557e6fb1c346a24555ce40774d595378e2))
* **deps:** update module github.com/buildkite/go-buildkite/v5 to v5.7.0 ([#332](https://github.com/chinmina/chinmina-bridge/issues/332)) ([0582d16](https://github.com/chinmina/chinmina-bridge/commit/0582d1695b17b0413010023c54fb029f0a3f03ca))
* **deps:** update module github.com/gkampitakis/go-snaps to v0.5.23 ([#329](https://github.com/chinmina/chinmina-bridge/issues/329)) ([2a564b6](https://github.com/chinmina/chinmina-bridge/commit/2a564b6157923af0c7406d3b9fe58589ed99702d))
* **deps:** update module github.com/google/go-github/v84 to v89 ([#336](https://github.com/chinmina/chinmina-bridge/issues/336)) ([a472471](https://github.com/chinmina/chinmina-bridge/commit/a4724713380b87d7a5d63e65cd9b83f2448af43d))
* **deps:** update module github.com/grafana/pyroscope-go to v1.4.1 ([#330](https://github.com/chinmina/chinmina-bridge/issues/330)) ([e9731e2](https://github.com/chinmina/chinmina-bridge/commit/e9731e207d9d17cf27a9b87c8f624aeebdf36f8e))
* **deps:** update module github.com/testcontainers/testcontainers-go to v0.43.0 ([#316](https://github.com/chinmina/chinmina-bridge/issues/316)) ([7122411](https://github.com/chinmina/chinmina-bridge/commit/71224114a70530af1a00e79d1f91eaf1a93cb166))
* **deps:** update opentelemetry ([#318](https://github.com/chinmina/chinmina-bridge/issues/318)) ([a260b6c](https://github.com/chinmina/chinmina-bridge/commit/a260b6c495be7c1e591db9073dce0f3059b2a124))


### Miscellaneous Chores

* release 0.12.0 ([#342](https://github.com/chinmina/chinmina-bridge/issues/342)) ([4fb57b9](https://github.com/chinmina/chinmina-bridge/commit/4fb57b9035df7c7125b3e74829f66cf4dba91096))
