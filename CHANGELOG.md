# Changelog

## [0.12.0](https://github.com/chinmina/chinmina-bridge/compare/v0.15.1...v0.12.0) (2026-08-28)


### ⚠ BREAKING CHANGES

* **deps:** `CreateDeployment` and `CreateDeploymentStatus` now take `DeploymentRequest` and `DeploymentStatusRequest` by value; `DeploymentRequest.Ref` and `DeploymentStatusRequest.State` are now `string`, and `DeploymentRequest.RequiredContexts` is now `[]string`.
    - refactor!: Pass `HookConfig` by value and rename
    `EditHookConfiguration` to `UpdateHookConfiguration`
    ([#&#8203;4360](https://redirect.github.com/google/go-github/issues/4360))
    `EditHookConfiguration` is renamed to
    `UpdateHookConfiguration` on `RepositoriesService` and
    `OrganizationsService`; these methods and `AppsService.UpdateHookConfig`
    now take `HookConfig` by value.
    - refactor!: Pass `OIDCSubjectClaimCustomTemplate` by value in the OIDC
    subject-claim Set methods
    ([#&#8203;4340](https://redirect.github.com/google/go-github/issues/4340))
    `SetOrgOIDCSubjectClaimCustomTemplate` and
    `SetRepoOIDCSubjectClaimCustomTemplate` now take their `body` params by
    value.
    - feat!: Refactor actions variables to pass request by value
    ([#&#8203;4346](https://redirect.github.com/google/go-github/issues/4346))
    `ActionsService` methods involving variables have new
    params and return values.
    - feat!: Replace actions env secret endpoints
    ([#&#8203;4335](https://redirect.github.com/google/go-github/issues/4335))
    `ActionsService` methods involving secrets have new
    params and return values.
    - refactor!: Pass `CreateJITConfigRequest` by value and rename
    `Generate*JITConfig` to `Create*JITConfig`
    ([#&#8203;4337](https://redirect.github.com/google/go-github/issues/4337))
    the JIT config methods are renamed from
    `Generate*JITConfig` to `Create*JITConfig`, and they now take
    `CreateJITConfigRequest` (renamed from `GenerateJITConfigRequest`) by
    value instead of by pointer.
    - refactor!: Pass release-notes and asset params by value and rename
    `EditReleaseAsset` to `UpdateReleaseAsset`
    ([#&#8203;4336](https://redirect.github.com/google/go-github/issues/4336))
    `GenerateReleaseNotes` now takes `GenerateNotesRequest`
    by value (renamed from `GenerateNotesOptions`); `EditReleaseAsset` is
    renamed to `UpdateReleaseAsset` and takes `UpdateReleaseAssetRequest` by
    value.
    - refactor!: Pass release params by value and rename `EditRelease` to
    `UpdateRelease`
    ([#&#8203;4329](https://redirect.github.com/google/go-github/issues/4329))
    `CreateRelease` & `UpdateRelease` now take
    `RepositoryRelease` by value; `EditRelease` is renamed to
    `UpdateRelease`.
    - refactor!: Pass `GistsService` required params by value
    ([#&#8203;4320](https://redirect.github.com/google/go-github/issues/4320))
    `GistsService` methods now pass required params
    by-value instead of by-ref.
    - fix!: Send request body in SCIM update methods
    ([#&#8203;4315](https://redirect.github.com/google/go-github/issues/4315))
    `UpdateProvisionedOrgMembership` and
    `UpdateAttributeForSCIMUser` params and return values changed.
    - fix!: Fix `LicenseStatus` response and `Supportkey` type
    ([#&#8203;4297](https://redirect.github.com/google/go-github/issues/4297))
    `LicenseStatus.SupportKey` type changed from `*string`
    to `*bool` and `License` return type is no longer a slice.
    - fix!: Enterprise App installation repos options structs
    ([#&#8203;4298](https://redirect.github.com/google/go-github/issues/4298))
    `SelectedRepositoryIDs []int64` is now `Repositories
    []string` in `*AppInstallationRepositoriesOptions`.

### Features

* add cache backend selection in main ([fb81098](https://github.com/chinmina/chinmina-bridge/commit/fb810980497566aa94d665bce763c8c3ae714e83))
* add cache configuration structs ([10b0f90](https://github.com/chinmina/chinmina-bridge/commit/10b0f90c204b874844d18e11f833831183bf4c4d))
* add cache observability with OTEL metrics ([5391dee](https://github.com/chinmina/chinmina-bridge/commit/5391dee3990931fb26ec3b24fccea19cf25d495e))
* add claim validation via interface changes and ValidatingLookup wrapper ([2fa01be](https://github.com/chinmina/chinmina-bridge/commit/2fa01be549d27ff6e9e2bc2f4a98dd621ba518c8))
* add ClaimValueLookup interface and new claim fields ([6b168ac](https://github.com/chinmina/chinmina-bridge/commit/6b168ac3999fa1d7ba06347e9e8b36252cc70a4b))
* add conventional PR title workflow ([#299](https://github.com/chinmina/chinmina-bridge/issues/299)) ([019191f](https://github.com/chinmina/chinmina-bridge/commit/019191f06c8a16a7464e8e2b1a5e96bbde63f438))
* add conventional PR title workflow ([#302](https://github.com/chinmina/chinmina-bridge/issues/302)) ([47deb49](https://github.com/chinmina/chinmina-bridge/commit/47deb4901a4ad3b59d6cb6808cdfa9a867004188))
* add digest tracking to ProfileConfig for change detection ([3b37efb](https://github.com/chinmina/chinmina-bridge/commit/3b37efb5868626ccdf4715429f5071ed762e7fd9))
* add Digest() method to ProfileStore ([0510467](https://github.com/chinmina/chinmina-bridge/commit/0510467b9e35f0247217c098623b448600b5e631))
* add encryption infrastructure with Tink AEAD and AWS KMS integration ([9198981](https://github.com/chinmina/chinmina-bridge/commit/91989814ff9898cbd8e966005ce7e56f89f09452))
* add encryption package with Tink AEAD primitives and tests ([59b1867](https://github.com/chinmina/chinmina-bridge/commit/59b1867354b93e60b38752c15a3a78ecb8e5a2b5))
* add encryption support to distributed Valkey cache ([b37c02a](https://github.com/chinmina/chinmina-bridge/commit/b37c02af7036772f6af9272c09b346dbdbd95416))
* add encryption/decryption to distributed cache Set and Get ([27f7a4d](https://github.com/chinmina/chinmina-bridge/commit/27f7a4d5475152c87b62254db38f54e9b61cb2b5))
* add HTTP 400 Bad Request for invalid JWT claims ([12861b8](https://github.com/chinmina/chinmina-bridge/commit/12861b810f950a54a412e103122b3cbc88eb4bd2))
* add IAM authentication for Valkey ([44f2b7c](https://github.com/chinmina/chinmina-bridge/commit/44f2b7cb5cee354dbb559057438ca3a26e64f000))
* add IAM authentication for Valkey via iamcacheauth ([c5f4472](https://github.com/chinmina/chinmina-bridge/commit/c5f4472286aa9e7d53ceed6ee1d5ba2d444cf924))
* add JSON error response format and helper ([556f594](https://github.com/chinmina/chinmina-bridge/commit/556f59483348373c3e0aaf4d43a383c5979d0443))
* add KMS and Secrets Manager integration for encryption ([434186e](https://github.com/chinmina/chinmina-bridge/commit/434186ecfb67e2cff3ef402bad8bc4a3adec4314))
* add MatchRule struct for claim-based profile matching ([57ea7ad](https://github.com/chinmina/chinmina-bridge/commit/57ea7adc88f9970a151dc876375b9cbf64f2b88b))
* add metadata:read permission to all tokens automatically ([f1113d4](https://github.com/chinmina/chinmina-bridge/commit/f1113d4cba2344c25b534c47b0495171e07ffbea))
* add metadata:read permission to all tokens automatically ([48455b7](https://github.com/chinmina/chinmina-bridge/commit/48455b74cdbae71ec5491ea9804c96d1bd19cc90)), closes [#182](https://github.com/chinmina/chinmina-bridge/issues/182)
* add observability for cache encryption operations ([a15c911](https://github.com/chinmina/chinmina-bridge/commit/a15c911072da501f710c00fc55c00ccf235f2aae))
* add observability for cache encryption operations ([08ae842](https://github.com/chinmina/chinmina-bridge/commit/08ae8428d1e600bd6b4c7562f0769db5901ec720))
* add optional AEAD parameter to distributed cache constructor ([41dd2c1](https://github.com/chinmina/chinmina-bridge/commit/41dd2c1e328bcd43049f46f551b8663af112d6ee))
* add optional profile parameter to base routes ([eb4faaa](https://github.com/chinmina/chinmina-bridge/commit/eb4faaa22d80c6c29b7d142e090d23e0f78f4442))
* add phuslu/log dependency for improved logging performance ([1ee64a3](https://github.com/chinmina/chinmina-bridge/commit/1ee64a33ed19ed1cd04f41717d054386a7a80151))
* add pipeline profile support into vendor ([02ed4bc](https://github.com/chinmina/chinmina-bridge/commit/02ed4bcb9f70cbd0b7ca2bab163b22f77b6a5a7b))
* add pipeline profiles runtime types ([e2a8ead](https://github.com/chinmina/chinmina-bridge/commit/e2a8eada93d3dc2da6cb151eb3d4b673cd9ce09f))
* add pipeline profiles YAML configuration structure ([9d0389f](https://github.com/chinmina/chinmina-bridge/commit/9d0389f8ccf42def026cc55552f0fbb619e09131))
* add profile name uniqueness validation ([3193226](https://github.com/chinmina/chinmina-bridge/commit/319322633216d6448c7a309f5cd28fb3c2661d67))
* add ProfileMatchFailedError type ([409deca](https://github.com/chinmina/chinmina-bridge/commit/409decac49b369c6e0f63a5ee72e5c9f59536a86))
* add ProfileRef type for canonical profile identity ([61f2127](https://github.com/chinmina/chinmina-bridge/commit/61f2127507bcb5d1c019b9a18dbf7a90a41c144b))
* add Pyroscope continuous profiling ([453a1da](https://github.com/chinmina/chinmina-bridge/commit/453a1da4a3283e22d66882f049d25b562cede0e0))
* add Pyroscope continuous profiling ([7c2b9b0](https://github.com/chinmina/chinmina-bridge/commit/7c2b9b0e793df7e84af1fef79382b2c75697a63e))
* add RefreshableAEAD for automatic keyset rotation ([5d9954e](https://github.com/chinmina/chinmina-bridge/commit/5d9954e3be6f9233b98eed76406c6a2c43c76c1b))
* add RefreshableAEAD with periodic keyset refresh ([e5d2184](https://github.com/chinmina/chinmina-bridge/commit/e5d21840f0e0f3d3977ce303efb4ba5f767b338a))
* add release-notes skill for augmented GitHub releases ([#340](https://github.com/chinmina/chinmina-bridge/issues/340)) ([18ac817](https://github.com/chinmina/chinmina-bridge/commit/18ac817069ac2bb7ee10f0596bea3cfd92d7ad83))
* add slog helper utilities for zerolog-to-slog migration (phase 1) ([e649e5f](https://github.com/chinmina/chinmina-bridge/commit/e649e5f1d90954034dcc0782b7c5faed8c5e761c))
* add span attributes for cache encryption operations ([2a57eb9](https://github.com/chinmina/chinmina-bridge/commit/2a57eb96b02b494f9e3e786e3b9595d1a6d1ef0a))
* add span attributes for cache operations ([a8d5366](https://github.com/chinmina/chinmina-bridge/commit/a8d5366457dc5d4a9d29a9577e30b8c6c3f50f10))
* add storage key prefixing for encrypted cache entries ([2d95ae0](https://github.com/chinmina/chinmina-bridge/commit/2d95ae0b0e7eef449085a570e127a360e19bd191))
* add TokenCache and Digester interfaces ([1e97daf](https://github.com/chinmina/chinmina-bridge/commit/1e97daf87688c6b1c16c0537fb1763ef3a7c43d8))
* add validation for non-empty repositories and permissions lists ([262925e](https://github.com/chinmina/chinmina-bridge/commit/262925e4772522748fb0573d4c2c9a71611ec284))
* add Valkey dependencies ([399631d](https://github.com/chinmina/chinmina-bridge/commit/399631d0dcc8f74d9f1cf3a51acf68b4b05a88d4))
* add Valkey distributed cache for horizontal scaling ([f73418c](https://github.com/chinmina/chinmina-bridge/commit/f73418c3bf1e5149be469794716be399de0ca08e))
* add Valkey service to docker-compose ([70994f4](https://github.com/chinmina/chinmina-bridge/commit/70994f485204e4239c4096355a3f3bf43f943e39))
* adopt shared release pipeline toolchain and version config ([#324](https://github.com/chinmina/chinmina-bridge/issues/324)) ([1322dbc](https://github.com/chinmina/chinmina-bridge/commit/1322dbc63fd8054c5360ccdbe49552d3c9b2dada))
* **audit:** migrate audit subsystem from zerolog to slog ([3119c04](https://github.com/chinmina/chinmina-bridge/commit/3119c04be8a6b2ca1187c3f885c27a1af0b5442a))
* **audit:** SHA-256 token hashing for GitHub audit log correlation ([7e2c2cd](https://github.com/chinmina/chinmina-bridge/commit/7e2c2cdaeed2d61edaa2c86340020aba397f6d4d))
* **audit:** surface HashedToken in audit log for GitHub audit correlation ([01a4477](https://github.com/chinmina/chinmina-bridge/commit/01a4477eb9a0221a5d3084f308b7d7cd3cdbc281))
* capture match results in ProfileToken for audit logging ([7ab928d](https://github.com/chinmina/chinmina-bridge/commit/7ab928d82848a1d4d04f026bf6f52e3f4d8a23d6))
* compilation support for pipeline profiles ([efb2965](https://github.com/chinmina/chinmina-bridge/commit/efb2965f5f2422668cea80e0b61814da794d1444))
* complete switch to runtime profiles structures ([79d6121](https://github.com/chinmina/chinmina-bridge/commit/79d61213c27ec2add1af33ccb5dea7f593bc44cb))
* complete zerolog removal — migrate remaining files and purge dependency ([4d3dc1b](https://github.com/chinmina/chinmina-bridge/commit/4d3dc1b309a9f1d003e7841de9fde995794ebf81))
* configurable default permissions for repository tokens ([589d79e](https://github.com/chinmina/chinmina-bridge/commit/589d79ea17021f2e56d23f9d3ecb9c4e531838d6))
* create tokens through multiple GitHub Apps ([#374](https://github.com/chinmina/chinmina-bridge/issues/374)) ([a51c4a8](https://github.com/chinmina/chinmina-bridge/commit/a51c4a8b6da75ad4ac1c25b4a033c78b9c7b3268))
* define core matcher types for claim matching ([c59f5b3](https://github.com/chinmina/chinmina-bridge/commit/c59f5b3b952e92436af3e0080c19171c6fe90010))
* dynamic repository scoping for organization profiles ([#297](https://github.com/chinmina/chinmina-bridge/issues/297)) ([264c2df](https://github.com/chinmina/chinmina-bridge/commit/264c2df9c34279fbe1f33c02a4ac3ece3bd5ede2))
* enable GOEXPERIMENT=jsonv2 across all builds ([98cf465](https://github.com/chinmina/chinmina-bridge/commit/98cf465e233ab3deb7cb3fc5d5b615ba94ab1d5f))
* enable GOEXPERIMENT=jsonv2 across all builds ([498400a](https://github.com/chinmina/chinmina-bridge/commit/498400acdcfb925e255f92b8fe00189a157ae0bc))
* enrich otel spans and audit logs with Buildkite request identity ([3b9ba97](https://github.com/chinmina/chinmina-bridge/commit/3b9ba9756a21ded56071dbb129be0badb82088dc))
* enrich OTel spans and audit logs with Buildkite request identity ([277cad2](https://github.com/chinmina/chinmina-bridge/commit/277cad29974acbf172a1e2a85ec4963953028156))
* extend audit Entry for claim match results ([236a63b](https://github.com/chinmina/chinmina-bridge/commit/236a63bfb5def56c6a91baea8d05cb0877009139))
* gate startup on the first profile generation ([#371](https://github.com/chinmina/chinmina-bridge/issues/371)) ([1c20946](https://github.com/chinmina/chinmina-bridge/commit/1c20946d0279034af46f8ebe3c3270de3ba5de7f))
* implement cache.Distributed with Valkey ([2c82ca9](https://github.com/chinmina/chinmina-bridge/commit/2c82ca98b1b91410c8b9c9f7493399abd557eb65))
* implement cache.Memory with otter backend ([a78c0d8](https://github.com/chinmina/chinmina-bridge/commit/a78c0d8a9a67722077605713c3b82d6ad2e7b0a3))
* implement CompositeMatcher with AND logic ([c50f1b7](https://github.com/chinmina/chinmina-bridge/commit/c50f1b7e04bf9182258eac235974d2e601316d5e))
* implement custom JSON unmarshaling for agent tags ([46410b4](https://github.com/chinmina/chinmina-bridge/commit/46410b43d10557c597ebb61183512ce16b33cb79))
* implement ExactMatcher for claim matching ([b07f0f1](https://github.com/chinmina/chinmina-bridge/commit/b07f0f16ebd31f98c185493728ba1e5f9578c2e3))
* implement Lookup method on BuildkiteClaims ([636ae2f](https://github.com/chinmina/chinmina-bridge/commit/636ae2fdee460fe7ba26160635a524710ef1390c))
* implement match rule validation ([d927c33](https://github.com/chinmina/chinmina-bridge/commit/d927c3310257bb6e4d0e556a48f944c7a9f2f11e))
* implement pipeline profiles for repository-scoped permissions ([b1278ec](https://github.com/chinmina/chinmina-bridge/commit/b1278ec1230bab1ac36a1efc05376e3f2801a92d))
* implement profile-level validation with graceful degradation ([15b1ccf](https://github.com/chinmina/chinmina-bridge/commit/15b1ccf61e0eb4a3da6d0f061b37679ae835ee11))
* implement RegexMatcher with automatic anchoring ([e404e93](https://github.com/chinmina/chinmina-bridge/commit/e404e9322c2d4e929dfe7322f2175c71cab2ad3f))
* integrate match evaluation into OrgVendor ([dbcacc2](https://github.com/chinmina/chinmina-bridge/commit/dbcacc2333a8dc5afa07be712022582623f6b216))
* map vendor errors to appropriate HTTP status codes ([fcd658b](https://github.com/chinmina/chinmina-bridge/commit/fcd658be19b9194b07984b636a28c11e3f18b4c4))
* migrate application files from zerolog to slog ([72660b0](https://github.com/chinmina/chinmina-bridge/commit/72660b0d5d8b7b5fa6e1f2075f5bf5d7d1038aa9))
* migrate cache subsystem from zerolog to slog (phase 2c) ([a3c8f18](https://github.com/chinmina/chinmina-bridge/commit/a3c8f1884a697183ac5b147f7a33a87e6a892f1f))
* migrate main initialization from zerolog to slog (phase 2a) ([3a7e2ee](https://github.com/chinmina/chinmina-bridge/commit/3a7e2ee1f8cb887c9a9fc0ae2099f34768627801))
* migrate observe subsystem from zerologr to logr.FromSlogHandler ([06aabf6](https://github.com/chinmina/chinmina-bridge/commit/06aabf61048e5194d9e4608ff550295c1239d72c))
* migrate profile subsystem from zerolog to slog ([38d6866](https://github.com/chinmina/chinmina-bridge/commit/38d68666b2cc21e641d680222828376c727d8fe1))
* migrate server.go and cache/factory.go from zerolog to slog (phase 2b) ([6f5e1d6](https://github.com/chinmina/chinmina-bridge/commit/6f5e1d6f6d429a8efd81888b18858892583b0e6d))
* **observe:** add HTTP/protobuf OTLP exporter ([0ba0226](https://github.com/chinmina/chinmina-bridge/commit/0ba02263fb294c03c33ac306f05ba3006e12e276))
* **observe:** add HTTP/protobuf OTLP exporter ([cff0b05](https://github.com/chinmina/chinmina-bridge/commit/cff0b05fdf6019526d5fee9ff9e556708e8ea416))
* populate audit log with claim match results ([55c61e5](https://github.com/chinmina/chinmina-bridge/commit/55c61e571deb522bf5e66d2325c09cf9cbde1770))
* prime profile store with default profile on startup ([0cbfdbb](https://github.com/chinmina/chinmina-bridge/commit/0cbfdbb78e48fd526cc323791771ef8563445083))
* profile refresh gets its own OTEL trace ([e8a97ec](https://github.com/chinmina/chinmina-bridge/commit/e8a97ecc12f108bf96196362c188869229beb14e))
* **profile:** add generic profile types ([8208f22](https://github.com/chinmina/chinmina-bridge/commit/8208f2204cb8d96e8bed1507fc3958c6701053fe))
* **profile:** add types for runtime profile model ([50cf32f](https://github.com/chinmina/chinmina-bridge/commit/50cf32ff9e73003a164403dedf97c60f3b782c9d))
* **profile:** switch vendor to use AuthorizedProfile abstraction ([ec56bd5](https://github.com/chinmina/chinmina-bridge/commit/ec56bd59abcf020cf759530a58124dd1f7ca53b2))
* **profile:** switch vendor to use AuthorizedProfile abstraction ([ba28d0e](https://github.com/chinmina/chinmina-bridge/commit/ba28d0e4db9b1d7afeadb8f6eb877f86781a2ce5))
* record why a profile is unavailable on the audit entry ([#369](https://github.com/chinmina/chinmina-bridge/issues/369)) ([91c18f9](https://github.com/chinmina/chinmina-bridge/commit/91c18f9d036f3a486e49f1d670215125029bc54a))
* **routes:** add optional profile parameter to base routes ([310cedc](https://github.com/chinmina/chinmina-bridge/commit/310cedcd554810d4479a6e0b36f55a2140e51ca4))
* support _FILE variants for static JWKS and GitHub app private key ([#375](https://github.com/chinmina/chinmina-bridge/issues/375)) ([9a45a67](https://github.com/chinmina/chinmina-bridge/commit/9a45a67f5f2ef2352e770c46ea9ce4a5b64a28cf))
* support cleartext Tink keysets for local development ([7a48c9e](https://github.com/chinmina/chinmina-bridge/commit/7a48c9e5704b34deceb91a32bc20fccf4a080990))
* support cleartext Tink keysets for local development ([df11740](https://github.com/chinmina/chinmina-bridge/commit/df11740c8fce7c86fb2d81dcd0cae9528e760ebe))
* support configurable base path for sub-path deployments ([#287](https://github.com/chinmina/chinmina-bridge/issues/287)) ([4d1a1a3](https://github.com/chinmina/chinmina-bridge/commit/4d1a1a39e0f86e0ff9b73e518e86e2f1f2b03642))
* update handlers to construct ProfileRef from request ([83435ec](https://github.com/chinmina/chinmina-bridge/commit/83435ec9c525de06ec282057cfdb6bdca331380c))
* update profile URN format to include pipeline slug ([0a7ea9e](https://github.com/chinmina/chinmina-bridge/commit/0a7ea9e4565994b432d215ddfe91bf0723ad3ee6))
* **vendor:** add SHA-256 token hashing and ProfileToken.HashedToken field ([9e08142](https://github.com/chinmina/chinmina-bridge/commit/9e081426b641ff1cad085cafcc6c4bd1ac68b51e))
* **vendor:** populate HashedToken on ProfileToken in repo and org vendors ([e6331e5](https://github.com/chinmina/chinmina-bridge/commit/e6331e58aa6a056888f58f37bd0695540a539750))
* wire separate vendor chains for pipeline and org routes ([4f37fc8](https://github.com/chinmina/chinmina-bridge/commit/4f37fc8365ad0e91501a3dfa13b79f4c39552559))


### Bug Fixes

* adapt cache package to two-layer encryption API ([27fbab1](https://github.com/chinmina/chinmina-bridge/commit/27fbab110f0cdd6f30c0df821e353eaf2247fe51))
* adapt JWT middleware code for go-jwt-middleware v3 API changes ([92fd2d6](https://github.com/chinmina/chinmina-bridge/commit/92fd2d64dfe610ca8c0799abe8cf89068a326504))
* add error handling for shutdown operations ([fed478a](https://github.com/chinmina/chinmina-bridge/commit/fed478aef32ebf27d60c788f386ec46bb176f4af))
* add OTEL metrics for token cache outcomes ([81f77b2](https://github.com/chinmina/chinmina-bridge/commit/81f77b2bec35c041850b468bea13dc9c9773507a))
* add resolved profile and app details to traces ([#392](https://github.com/chinmina/chinmina-bridge/issues/392)) ([9b58b7d](https://github.com/chinmina/chinmina-bridge/commit/9b58b7d1b5753cb1f3e1b3233767daba8396063d))
* add the updated digest as trace information ([79a3166](https://github.com/chinmina/chinmina-bridge/commit/79a3166cde3fb512e0edf78711fe8cc96885c89e))
* align error responses to security best practices ([4776d91](https://github.com/chinmina/chinmina-bridge/commit/4776d913a325ab007dd6c31ca3b8d9de9f79d148))
* allow authenticated use of pyroscope for remote/Grafana Cloud targets ([10ee6b6](https://github.com/chinmina/chinmina-bridge/commit/10ee6b6db3a4116c7336400cfaad97d0c7bba34c))
* allow for authenticated use of pyroscope ([bca7675](https://github.com/chinmina/chinmina-bridge/commit/bca7675f5c1e7fd1d3d93603bba5608562dc3821))
* allow ingress container config to be overridden ([795d726](https://github.com/chinmina/chinmina-bridge/commit/795d7264c17baec5720e7de777fd4fa998ba005f))
* allow ingress container config to be overridden ([33e99af](https://github.com/chinmina/chinmina-bridge/commit/33e99af692b551003997b0ccc0ca4fdc87a65339))
* avoid possible null issues with ProfileStore.Update ([a0d9c2d](https://github.com/chinmina/chinmina-bridge/commit/a0d9c2d2a16aa81427e51ea77c53870d7ee7b166))
* block go-githubauth v2 in renovate config ([46ed959](https://github.com/chinmina/chinmina-bridge/commit/46ed9595ffe86fe847b8c657047daedd521320fc))
* caching hit rate degradation due to incorrect comparison in caching layer ([1bb4ea9](https://github.com/chinmina/chinmina-bridge/commit/1bb4ea95bda0bc3264aecdef0ce21dd72473de65))
* cancel in-flight refresh on Close to avoid shutdown delays ([2aa9caf](https://github.com/chinmina/chinmina-bridge/commit/2aa9caf6b1260575d18caa4990a3c9884763a64b))
* check for a valid profile first ([066d3e4](https://github.com/chinmina/chinmina-bridge/commit/066d3e4d42e8dc43b3c576a0906fa593b4bbea4f))
* claim name and value validation fixes ([e3f304a](https://github.com/chinmina/chinmina-bridge/commit/e3f304a2712ed847a605a6df5d695bf5fb017603))
* clarify references to profiles in messages ([589e31f](https://github.com/chinmina/chinmina-bridge/commit/589e31f855de8cfb3e84671fc1f57eb42790705a))
* clarifying logging and output from vendors ([d6354a5](https://github.com/chinmina/chinmina-bridge/commit/d6354a5ad4cbc4cd2b5529d74450ba2a37d47e4f))
* comment YAML read to communicate security implications ([4daffa5](https://github.com/chinmina/chinmina-bridge/commit/4daffa540236f1a1ee5599e0ecf735bb3e9987d7))
* compact logging for profile updates ([df56982](https://github.com/chinmina/chinmina-bridge/commit/df56982992c43357d9ae85a36dfcbefb7dd2b232))
* consolidate the use of JWX helpers ([26a8371](https://github.com/chinmina/chinmina-bridge/commit/26a8371fa76793546feebdfdbe6b9a354983068a))
* correct double-counting in cache outcome metrics ([0e5282b](https://github.com/chinmina/chinmina-bridge/commit/0e5282b85d7932d4118fb0d9a1f32849b8909030))
* correct spelling of 'response' in comments ([f769a67](https://github.com/chinmina/chinmina-bridge/commit/f769a67c4118e0b0f5e57c82dc3b92dea3266b29))
* custom zerolog marshalling must not write a message ([968394f](https://github.com/chinmina/chinmina-bridge/commit/968394ff842d45b9909db7adbbbb435b967e2b95))
* **deps:** bump golang.org/x/crypto to v0.52.0 ([#343](https://github.com/chinmina/chinmina-bridge/issues/343)) ([0cbb08a](https://github.com/chinmina/chinmina-bridge/commit/0cbb08a568f63b710850e905a3b30f694c285540))
* **deps:** pin GitHub Actions dependencies ([#346](https://github.com/chinmina/chinmina-bridge/issues/346)) ([4160495](https://github.com/chinmina/chinmina-bridge/commit/4160495f4be1d7f2dc309835eaf0f1c7062dd7d6))
* **deps:** update aws-sdk-go-v2 ([#328](https://github.com/chinmina/chinmina-bridge/issues/328)) ([550eaf3](https://github.com/chinmina/chinmina-bridge/commit/550eaf340ba1782ca4c488d3beae24fb692c279e))
* **deps:** update aws-sdk-go-v2 ([#352](https://github.com/chinmina/chinmina-bridge/issues/352)) ([2ecda6f](https://github.com/chinmina/chinmina-bridge/commit/2ecda6f318dd6d89ba6038d4916c73653d47700f))
* **deps:** update aws-sdk-go-v2 ([#379](https://github.com/chinmina/chinmina-bridge/issues/379)) ([644f016](https://github.com/chinmina/chinmina-bridge/commit/644f0160484d626a7c2ea54a7623af19997f3283))
* **deps:** update dependency cosign to v3 ([#334](https://github.com/chinmina/chinmina-bridge/issues/334)) ([8cc7c04](https://github.com/chinmina/chinmina-bridge/commit/8cc7c04479ba992effbfc387ae1f280910ebf273))
* **deps:** update dependency cosign to v3.1.3 ([#348](https://github.com/chinmina/chinmina-bridge/issues/348)) ([ef99794](https://github.com/chinmina/chinmina-bridge/commit/ef997947436578e2258da919fadda9ba24aa03aa))
* **deps:** update dependency go to v1.26.6 ([#361](https://github.com/chinmina/chinmina-bridge/issues/361)) ([1b471a3](https://github.com/chinmina/chinmina-bridge/commit/1b471a362cad1dfa83df83001ba7c259dfb53f94))
* **deps:** update dependency golangci-lint to v2.12.2 ([#331](https://github.com/chinmina/chinmina-bridge/issues/331)) ([9c3a77f](https://github.com/chinmina/chinmina-bridge/commit/9c3a77fa4c84eb3439e17c51fe3ab72bbce544c3))
* **deps:** update dependency golangci-lint to v2.13.1 ([#382](https://github.com/chinmina/chinmina-bridge/issues/382)) ([55381f5](https://github.com/chinmina/chinmina-bridge/commit/55381f5809d8a7ecfd508d26f6b2bcf4380a9189))
* **deps:** update dependency goreleaser to v2.17.1 ([#349](https://github.com/chinmina/chinmina-bridge/issues/349)) ([6824860](https://github.com/chinmina/chinmina-bridge/commit/68248609f32aa5954a980762fe3e9b4289a31f94))
* **deps:** update dependency goreleaser to v2.18.0 ([#383](https://github.com/chinmina/chinmina-bridge/issues/383)) ([527fdb6](https://github.com/chinmina/chinmina-bridge/commit/527fdb628ce61b9acb024fb46bfb63d12542b371))
* **deps:** update dependency just to v1.58.0 ([#353](https://github.com/chinmina/chinmina-bridge/issues/353)) ([8aed62d](https://github.com/chinmina/chinmina-bridge/commit/8aed62dfc6eab9a05dbd738454e29501eb4f03de))
* **deps:** update github-actions ([#347](https://github.com/chinmina/chinmina-bridge/issues/347)) ([3d30c23](https://github.com/chinmina/chinmina-bridge/commit/3d30c2363920540821d4ad3fc170ddc1b1286f68))
* **deps:** update github-actions (major) ([#339](https://github.com/chinmina/chinmina-bridge/issues/339)) ([011ad4e](https://github.com/chinmina/chinmina-bridge/commit/011ad4e4f034a578b42ad688a57f1eb4d7a123b4))
* **deps:** update github/codeql-action digest to db488dd ([#378](https://github.com/chinmina/chinmina-bridge/issues/378)) ([494943a](https://github.com/chinmina/chinmina-bridge/commit/494943a807a3253473493b9a7c7eff1df5ef67c2))
* **deps:** update jwx-and-auth0-jwt-middleware ([#354](https://github.com/chinmina/chinmina-bridge/issues/354)) ([1b3c441](https://github.com/chinmina/chinmina-bridge/commit/1b3c441f0a89ba7e7fdf86210f59249c8ecf2cfc))
* **deps:** update module github.com/auth0/go-jwt-middleware/v3 to v3.2.0 ([#337](https://github.com/chinmina/chinmina-bridge/issues/337)) ([daebc05](https://github.com/chinmina/chinmina-bridge/commit/daebc0557e6fb1c346a24555ce40774d595378e2))
* **deps:** update module github.com/buildkite/go-buildkite/v5 to v5.11.0 ([#355](https://github.com/chinmina/chinmina-bridge/issues/355)) ([fb6ce65](https://github.com/chinmina/chinmina-bridge/commit/fb6ce65a83f796f9ecd8f7962e5dd7a81bbaa03a))
* **deps:** update module github.com/buildkite/go-buildkite/v5 to v5.14.0 ([#384](https://github.com/chinmina/chinmina-bridge/issues/384)) ([2488d9a](https://github.com/chinmina/chinmina-bridge/commit/2488d9a8bd5aa2620eb3cc0e0bdc0033ad3406f6))
* **deps:** update module github.com/buildkite/go-buildkite/v5 to v5.7.0 ([#332](https://github.com/chinmina/chinmina-bridge/issues/332)) ([0582d16](https://github.com/chinmina/chinmina-bridge/commit/0582d1695b17b0413010023c54fb029f0a3f03ca))
* **deps:** update module github.com/gkampitakis/go-snaps to v0.5.23 ([#329](https://github.com/chinmina/chinmina-bridge/issues/329)) ([2a564b6](https://github.com/chinmina/chinmina-bridge/commit/2a564b6157923af0c7406d3b9fe58589ed99702d))
* **deps:** update module github.com/go-logr/logr to v1.4.4 ([#350](https://github.com/chinmina/chinmina-bridge/issues/350)) ([5598ae0](https://github.com/chinmina/chinmina-bridge/commit/5598ae015b459af2110f8e39de6706b767a157e3))
* **deps:** update module github.com/google/go-github/v84 to v89 ([#336](https://github.com/chinmina/chinmina-bridge/issues/336)) ([a472471](https://github.com/chinmina/chinmina-bridge/commit/a4724713380b87d7a5d63e65cd9b83f2448af43d))
* **deps:** update module github.com/google/go-github/v89 to v90 ([#357](https://github.com/chinmina/chinmina-bridge/issues/357)) ([371e4bc](https://github.com/chinmina/chinmina-bridge/commit/371e4bc83df5e7fac20b4ec59639e6f26c1d4b3d))
* **deps:** update module github.com/grafana/pyroscope-go to v1.4.1 ([#330](https://github.com/chinmina/chinmina-bridge/issues/330)) ([e9731e2](https://github.com/chinmina/chinmina-bridge/commit/e9731e207d9d17cf27a9b87c8f624aeebdf36f8e))
* **deps:** update module github.com/grafana/pyroscope-go to v1.4.2 ([#362](https://github.com/chinmina/chinmina-bridge/issues/362)) ([41804d6](https://github.com/chinmina/chinmina-bridge/commit/41804d68ca8b58e105b72da9fd62acd4341b3ff2))
* **deps:** update module github.com/moby/go-archive to v0.3.3 ([#387](https://github.com/chinmina/chinmina-bridge/issues/387)) ([896914d](https://github.com/chinmina/chinmina-bridge/commit/896914d280f34994c745e83e5d2d43fb414ce7e5))
* **deps:** update module github.com/phuslu/log to v1.0.128 ([#351](https://github.com/chinmina/chinmina-bridge/issues/351)) ([479ee21](https://github.com/chinmina/chinmina-bridge/commit/479ee21c29178ff1ad3c47c7ab0b20fa44f1d11c))
* **deps:** update module github.com/sethvargo/go-envconfig to v1.4.3 ([#363](https://github.com/chinmina/chinmina-bridge/issues/363)) ([f0a3a8e](https://github.com/chinmina/chinmina-bridge/commit/f0a3a8e8c74f03c4c6ff3a08dca1179c78b05bd9))
* **deps:** update module github.com/stretchr/testify to v1.12.1 ([#385](https://github.com/chinmina/chinmina-bridge/issues/385)) ([112ecbf](https://github.com/chinmina/chinmina-bridge/commit/112ecbfc89f7cc197640060fc16deb075df0e1b4))
* **deps:** update module github.com/testcontainers/testcontainers-go to v0.43.0 ([#316](https://github.com/chinmina/chinmina-bridge/issues/316)) ([7122411](https://github.com/chinmina/chinmina-bridge/commit/71224114a70530af1a00e79d1f91eaf1a93cb166))
* **deps:** update module github.com/testcontainers/testcontainers-go to v0.44.0 ([#364](https://github.com/chinmina/chinmina-bridge/issues/364)) ([6581c43](https://github.com/chinmina/chinmina-bridge/commit/6581c436c52d850529286e6db8c9b58db493bdb9))
* **deps:** update module github.com/tink-crypto/tink-go/v2 to v2.8.0 ([#365](https://github.com/chinmina/chinmina-bridge/issues/365)) ([71a34da](https://github.com/chinmina/chinmina-bridge/commit/71a34dadcb82c87ee38eec9a562e1b1d38e20dbc))
* **deps:** update module github.com/valkey-io/valkey-go to v1.0.77 ([#380](https://github.com/chinmina/chinmina-bridge/issues/380)) ([79da920](https://github.com/chinmina/chinmina-bridge/commit/79da920defddf9d7561c0ca090594ced3eea5da0))
* **deps:** update opentelemetry ([#318](https://github.com/chinmina/chinmina-bridge/issues/318)) ([a260b6c](https://github.com/chinmina/chinmina-bridge/commit/a260b6c495be7c1e591db9073dce0f3059b2a124))
* **deps:** update opentelemetry ([#356](https://github.com/chinmina/chinmina-bridge/issues/356)) ([79d722f](https://github.com/chinmina/chinmina-bridge/commit/79d722fc98834b11a1cc25b33649e2264a18365d))
* disable CGO just for the build ([f8a5120](https://github.com/chinmina/chinmina-bridge/commit/f8a5120f7a86480df28df55dc66dc89d1d2b2b81))
* enable PIE build mode for ASLR hardening ([d7a4160](https://github.com/chinmina/chinmina-bridge/commit/d7a41600712c149a7c2bfe53237b1b28670addb1))
* enforce profile type for different endpoints, retire prefixes ([de6d73b](https://github.com/chinmina/chinmina-bridge/commit/de6d73b8b03c7c1c6a50299a85da819ae859b0e4))
* ensure necessary dev context is copied to worktrees ([#323](https://github.com/chinmina/chinmina-bridge/issues/323)) ([b0cc750](https://github.com/chinmina/chinmina-bridge/commit/b0cc7507cf811a7d06300314777e0df72da97fa3))
* ensure OTEL metrics have the correct service name ([b0b9ab0](https://github.com/chinmina/chinmina-bridge/commit/b0b9ab05a34dc5364bfbe89713c8befa37711198))
* ensure periodic refresh shuts down gracefully ([8cc3e08](https://github.com/chinmina/chinmina-bridge/commit/8cc3e082bf205dd304c38921608c3f5bd6e9d993))
* extract repo name from URL before comparing in checkTokenRepository ([9dff2d5](https://github.com/chinmina/chinmina-bridge/commit/9dff2d53e59a3eb4a0fddfd23a19c174e63a83be))
* gate IAM validation on valkey cache type and log IAM status ([522e25e](https://github.com/chinmina/chinmina-bridge/commit/522e25ed85dc605c2a786e2277006f4a4fca24a9))
* handle edge case in content download ([118d175](https://github.com/chinmina/chinmina-bridge/commit/118d175b0dba7f14009b605161ef9161bd9043be))
* improve error handling and Close safety in RefreshableAEAD ([9e30a02](https://github.com/chinmina/chinmina-bridge/commit/9e30a0205d08c8aec9c366f2b53b7a7026b83bd6))
* improve error handling for invalid config paths ([c60930f](https://github.com/chinmina/chinmina-bridge/commit/c60930fcaa53517240cf08ac4bc05ac22f23eca0))
* improve error messages on profile retrieval ([c2d8f66](https://github.com/chinmina/chinmina-bridge/commit/c2d8f661eef5b89d61fb2684060c74d36257fa02))
* improve logging when requestedRepoURL is empty in RepoVendor ([5c42e13](https://github.com/chinmina/chinmina-bridge/commit/5c42e135e411f88cf408b9131ce4e4fe84396c9c))
* improve permissions validation and token vending performance ([f958383](https://github.com/chinmina/chinmina-bridge/commit/f95838354c0de9b6f83104c2fbc055284336ad30))
* improve shutdown handling ([128e746](https://github.com/chinmina/chinmina-bridge/commit/128e7467fb106be3f1187d396d6ad90e9e959b8e))
* improve status messages when profiles change ([47f3d47](https://github.com/chinmina/chinmina-bridge/commit/47f3d47814a8f61e6e80f5f04d10858a6425839b))
* improve test instructions to agents ([5dc5a15](https://github.com/chinmina/chinmina-bridge/commit/5dc5a15afffe8c9bb9ac91eeae729a245b9dba66))
* integration environment switch installations to bootstrap script ([70fe2b1](https://github.com/chinmina/chinmina-bridge/commit/70fe2b1ed8986b39d1e9998652d5bd1626c7d09e))
* introduce cache OTEL metrics ([5311223](https://github.com/chinmina/chinmina-bridge/commit/53112230f02716eb4ea050963a8e9438641b156f))
* migrate away from direct use of go-jose completely ([eff31e9](https://github.com/chinmina/chinmina-bridge/commit/eff31e91eec8011642da04a6b443f728dacb1376))
* migrate GitHub auth from ghinstallation to go-githubauth/v2 ([a1cd042](https://github.com/chinmina/chinmina-bridge/commit/a1cd04297ab8f8337beaf277580cbd80e02fdaf3))
* migrate GitHub auth from ghinstallation to go-githubauth/v2 ([87b7e31](https://github.com/chinmina/chinmina-bridge/commit/87b7e3166d9fdb5ed46fd433a68a2c9ffa2adca5))
* migrate go-githubauth from v2.0.0 to v1.5.0 ([be946db](https://github.com/chinmina/chinmina-bridge/commit/be946dbcad2fa708fdb7a3f9f268057b5562e6a1))
* migrate go-githubauth from v2.0.0 to v1.5.0 ([de66779](https://github.com/chinmina/chinmina-bridge/commit/de66779850d2cd73241dca3cce1deec8bc0e5578))
* minor updates ([0edc047](https://github.com/chinmina/chinmina-bridge/commit/0edc047ea28c51b99c545ed410a2e836f2823da0))
* move panic recovery to per-iteration in refresh loop ([022a932](https://github.com/chinmina/chinmina-bridge/commit/022a932b1bbe019133ecc608ad4df67d677066c6))
* move profilestoremock alongside profile store ([5c64746](https://github.com/chinmina/chinmina-bridge/commit/5c64746a7af5f4c9a117086891db79a2e698d9b8))
* move repository check to runtime structure ([69e23a7](https://github.com/chinmina/chinmina-bridge/commit/69e23a75b07b9a36d2031b66039d9a2a32a6a88a))
* nest Valkey and Encryption config under CacheConfig ([4917a9d](https://github.com/chinmina/chinmina-bridge/commit/4917a9d31ee67d8c3acaea839ddc45b6760380dd))
* normalize close on cache interface ([d8b59f2](https://github.com/chinmina/chinmina-bridge/commit/d8b59f29ea137e9944e73094980d2fd6c66cf8a6))
* org vendor needs to support wildcard repository matching ([de2aaa6](https://github.com/chinmina/chinmina-bridge/commit/de2aaa65d8c26a6fce0f96d8e6cc476155dc2831))
* organization profile mismatches wipe out cached token ([b3113d5](https://github.com/chinmina/chinmina-bridge/commit/b3113d525b4007e02aaaed32c54e65451de4e3fa))
* organization profiles marked for any repository aren't working ([f6bd4a1](https://github.com/chinmina/chinmina-bridge/commit/f6bd4a197b0d7fbec35cbc495e9888ff8b1965c7))
* pipeline defaults is guaranteed to return ([dbb53e1](https://github.com/chinmina/chinmina-bridge/commit/dbb53e1a11312b17c5a48972d508310acaf6eb3a))
* plumb valkey credentials into client ([28c86b3](https://github.com/chinmina/chinmina-bridge/commit/28c86b3bdc57c8a1480781aea95670501381f1a3))
* preserve org profile cache on repository mismatch ([39969b0](https://github.com/chinmina/chinmina-bridge/commit/39969b071a28ba42d9a9a2371f20526743c485ca))
* propagate write errors in WriteProperties ([ff290c6](https://github.com/chinmina/chinmina-bridge/commit/ff290c60debbd17256466ccb19913331dae06875))
* race detected in test mock ([3751755](https://github.com/chinmina/chinmina-bridge/commit/3751755515136b07c07fd3dc33e954bd14aa7824))
* refine audit support ([aebf209](https://github.com/chinmina/chinmina-bridge/commit/aebf2095fafa96d7dbfedae487d6730601cac3d4))
* refine logging for profile location ([0bc0d9c](https://github.com/chinmina/chinmina-bridge/commit/0bc0d9cea912c6b23dacc44a8c17f2ada6877cdd))
* refine vendor cache telemetry and fix outcome metric double-counting ([03d34b8](https://github.com/chinmina/chinmina-bridge/commit/03d34b8ebe3ca8b98cf70349723e58d8146be365))
* remove dead code ([cf21506](https://github.com/chinmina/chinmina-bridge/commit/cf215067aa05854dacc44fee52cecb4c1f7511c7))
* remove obsolete LookupProfile method ([4dd273c](https://github.com/chinmina/chinmina-bridge/commit/4dd273c1b510bbda4bd9d2aff9819a25debaf6a1))
* remove potential race when configuration reloads ([#360](https://github.com/chinmina/chinmina-bridge/issues/360)) ([3102538](https://github.com/chinmina/chinmina-bridge/commit/310253895f6ff350e252eca481e6a0d5fc85ca5d))
* remove unnecessary log ([788e25b](https://github.com/chinmina/chinmina-bridge/commit/788e25bcd8cd72114c173103ac49d8096f032caa))
* RepoVendor now vends tokens for pipeline repository only ([8da76e1](https://github.com/chinmina/chinmina-bridge/commit/8da76e1f774b274e642680744baaab897d8b9350))
* restructure cache configuration for encryption support ([f6fa188](https://github.com/chinmina/chinmina-bridge/commit/f6fa188c620a27ef0207db90533fe236d99a2ed5))
* restructure profile package ([b44fb90](https://github.com/chinmina/chinmina-bridge/commit/b44fb90e672284d17d5d5f617c7c278ab7dfefa3))
* restructure profile package for clean separation of concerns ([a7e3a2d](https://github.com/chinmina/chinmina-bridge/commit/a7e3a2dc3a5a6be7fe7dcf649764bbe3d6b244f5))
* return 413 for oversize body ([1c56ab6](https://github.com/chinmina/chinmina-bridge/commit/1c56ab6358126576c04ca16c646685e1c8f9f4f6))
* revert usage of PIE mode ([cf1fd0b](https://github.com/chinmina/chinmina-bridge/commit/cf1fd0b34bcbb69df31c7fa836edc39428199d75))
* run shutdown hooks on every exit path ([#370](https://github.com/chinmina/chinmina-bridge/issues/370)) ([ad60bf0](https://github.com/chinmina/chinmina-bridge/commit/ad60bf0034e760909ccd864a839de164802b3687))
* separate handler chains for repository and organisation based tokens ([3e3421c](https://github.com/chinmina/chinmina-bridge/commit/3e3421cf330c2bd18207e801aeb1ebf81279a9bf))
* simplify token cache checks ([9e0b830](https://github.com/chinmina/chinmina-bridge/commit/9e0b8304a81e5abea662ed6af4ea276c17d7d8b6))
* simplify token caching logic ([f0840b3](https://github.com/chinmina/chinmina-bridge/commit/f0840b3438a3be6f85c29afc8f2799f256578745))
* speed local test startup with apk cache ([c80c6ac](https://github.com/chinmina/chinmina-bridge/commit/c80c6ac4ad660826badc8a009243f2253229e5b5))
* speed local test startup with apk cache ([829a3dd](https://github.com/chinmina/chinmina-bridge/commit/829a3dd947537c18d7593c015489596c5c3a36d1))
* structure audit log for readability and searchability ([ef6a055](https://github.com/chinmina/chinmina-bridge/commit/ef6a0556aa4157c1bc5281e2da23e12cfc3ff86e))
* structure audit log to improve reading and searching ([c9ee132](https://github.com/chinmina/chinmina-bridge/commit/c9ee1323593721d1f5c641827332d1fbf75c7d29))
* support optional claims that are explicitly null ([458d4b8](https://github.com/chinmina/chinmina-bridge/commit/458d4b83f96823da1b99582b85b51f9721974669))
* test reassigned package variable ([e679ccf](https://github.com/chinmina/chinmina-bridge/commit/e679ccf49f4d1dbf8e9cf000ba5459db15f2bc3a))
* **tooling:** pin goreleaser to 2.17.1 ([#389](https://github.com/chinmina/chinmina-bridge/issues/389)) ([d0de6bc](https://github.com/chinmina/chinmina-bridge/commit/d0de6bc7af7bd1e1acbfed654618c46771092c49))
* trim method off OTEL resource path ([340bc2b](https://github.com/chinmina/chinmina-bridge/commit/340bc2b8aecf7ce51a466141bed172eb43868b0a))
* update claim marshalling to reduce boilerplate ([d5307a4](https://github.com/chinmina/chinmina-bridge/commit/d5307a48d235b6a6a15e3223c70958283dc43996))
* update doco links in README ([#290](https://github.com/chinmina/chinmina-bridge/issues/290)) ([30afe4c](https://github.com/chinmina/chinmina-bridge/commit/30afe4c6ff07377efd31eca1683ce95bf9fb62c8))
* update plugins and tools for local integration testing ([a8ce7ac](https://github.com/chinmina/chinmina-bridge/commit/a8ce7ac244e17b5659f1ddd18571b57bc0ccbf57))
* update semconv import to v1.39.0 for otel sdk v1.40.0 compat ([a6fa780](https://github.com/chinmina/chinmina-bridge/commit/a6fa780c500ebd389e60af0c8516cdb761debce8))
* use a Must method to show intentional use of panic ([0594817](https://github.com/chinmina/chinmina-bridge/commit/0594817b1c932b7fe8c9472b72470cfbe7514fda))
* use correct camelCase format for audit log field name ([39907b0](https://github.com/chinmina/chinmina-bridge/commit/39907b072b6f92e0b6d7a6a93748f295bfaa368b))
* use pipeline slug instead of ID in Buildkite API calls ([244d803](https://github.com/chinmina/chinmina-bridge/commit/244d803ed1f806f91867450ae82101e397924967))
* use reliable loaded check for profiles ([165a926](https://github.com/chinmina/chinmina-bridge/commit/165a9266105b35a85be846dc7c6cbf770e1934af))
* use RWMutex for better concurrency under high read loads ([761ead9](https://github.com/chinmina/chinmina-bridge/commit/761ead9ad76612c2bf2a10911abec82b2f3120fb))
* use wrapped error ([cded5b7](https://github.com/chinmina/chinmina-bridge/commit/cded5b74e7fff991ef99e6bc61b68c0cc9807630))
* validate permissions in profile compilation ([3a889cc](https://github.com/chinmina/chinmina-bridge/commit/3a889cc038c7ae0f3cb80aaee996f2666359888e))
* **vendor:** evaluate profile match rules outside the token cache ([#358](https://github.com/chinmina/chinmina-bridge/issues/358)) ([a2c4bcb](https://github.com/chinmina/chinmina-bridge/commit/a2c4bcbfa2fe6cd16756375157e490fe1d8386c8))
* wildcard org profile always misses token cache on git-credentials ([d3b5459](https://github.com/chinmina/chinmina-bridge/commit/d3b54595baaecf94908a297884352e7e94b1240a))
* wildcard org profile cache miss + RepositoryScope type ([a819172](https://github.com/chinmina/chinmina-bridge/commit/a819172073f52c8f14d1dd65e439a83da5c8a20e))
* write handler errors to audit log ([b0a1fe1](https://github.com/chinmina/chinmina-bridge/commit/b0a1fe193e6a57c85359f4aa4c24201414909c75))


### Performance Improvements

* extend JWKS cache TTL from 5 minutes to 1 hour ([36662d9](https://github.com/chinmina/chinmina-bridge/commit/36662d92ab1d980b261bdb0969ab7d037bc4517a))
* extend JWKS cache TTL to 1 hour ([449eb9e](https://github.com/chinmina/chinmina-bridge/commit/449eb9ebc7eb802a32a3e1d9570f5aa6db0de25c))
* improve logging throughput with phuslu/log handler ([cc572b5](https://github.com/chinmina/chinmina-bridge/commit/cc572b56910a44f8a27660ce23dccff65c5112d7))
* **jwt:** replace map-based UnmarshalJSON with json/v2 token streaming ([#255](https://github.com/chinmina/chinmina-bridge/issues/255)) ([f2952a6](https://github.com/chinmina/chinmina-bridge/commit/f2952a68186b7e595e34af27b4c117aea9cff34d))


### Miscellaneous Chores

* release 0.12.0 ([#342](https://github.com/chinmina/chinmina-bridge/issues/342)) ([4fb57b9](https://github.com/chinmina/chinmina-bridge/commit/4fb57b9035df7c7125b3e74829f66cf4dba91096))

## [0.15.1](https://github.com/chinmina/chinmina-bridge/compare/v0.15.0...v0.15.1) (2026-08-28)


### Bug Fixes

* add resolved profile and app details to traces ([#392](https://github.com/chinmina/chinmina-bridge/issues/392)) ([9b58b7d](https://github.com/chinmina/chinmina-bridge/commit/9b58b7d1b5753cb1f3e1b3233767daba8396063d))

## [0.15.0](https://github.com/chinmina/chinmina-bridge/compare/v0.14.1...v0.15.0) (2026-08-28)


### Features

* create tokens through multiple GitHub Apps ([#374](https://github.com/chinmina/chinmina-bridge/issues/374)) ([a51c4a8](https://github.com/chinmina/chinmina-bridge/commit/a51c4a8b6da75ad4ac1c25b4a033c78b9c7b3268))

## [0.14.1](https://github.com/chinmina/chinmina-bridge/compare/v0.14.0...v0.14.1) (2026-08-25)


### Bug Fixes

* **tooling:** pin goreleaser to 2.17.1 ([#389](https://github.com/chinmina/chinmina-bridge/issues/389)) ([d0de6bc](https://github.com/chinmina/chinmina-bridge/commit/d0de6bc7af7bd1e1acbfed654618c46771092c49))

## [0.14.0](https://github.com/chinmina/chinmina-bridge/compare/v0.13.0...v0.14.0) (2026-08-25)


### Features

* gate startup on the first profile generation ([#371](https://github.com/chinmina/chinmina-bridge/issues/371)) ([1c20946](https://github.com/chinmina/chinmina-bridge/commit/1c20946d0279034af46f8ebe3c3270de3ba5de7f))
* record why a profile is unavailable on the audit entry ([#369](https://github.com/chinmina/chinmina-bridge/issues/369)) ([91c18f9](https://github.com/chinmina/chinmina-bridge/commit/91c18f9d036f3a486e49f1d670215125029bc54a))
* support _FILE variants for static JWKS and GitHub app private key ([#375](https://github.com/chinmina/chinmina-bridge/issues/375)) ([9a45a67](https://github.com/chinmina/chinmina-bridge/commit/9a45a67f5f2ef2352e770c46ea9ce4a5b64a28cf))


### Bug Fixes

* **deps:** update aws-sdk-go-v2 ([#379](https://github.com/chinmina/chinmina-bridge/issues/379)) ([644f016](https://github.com/chinmina/chinmina-bridge/commit/644f0160484d626a7c2ea54a7623af19997f3283))
* **deps:** update dependency golangci-lint to v2.13.1 ([#382](https://github.com/chinmina/chinmina-bridge/issues/382)) ([55381f5](https://github.com/chinmina/chinmina-bridge/commit/55381f5809d8a7ecfd508d26f6b2bcf4380a9189))
* **deps:** update dependency goreleaser to v2.18.0 ([#383](https://github.com/chinmina/chinmina-bridge/issues/383)) ([527fdb6](https://github.com/chinmina/chinmina-bridge/commit/527fdb628ce61b9acb024fb46bfb63d12542b371))
* **deps:** update github/codeql-action digest to db488dd ([#378](https://github.com/chinmina/chinmina-bridge/issues/378)) ([494943a](https://github.com/chinmina/chinmina-bridge/commit/494943a807a3253473493b9a7c7eff1df5ef67c2))
* **deps:** update module github.com/buildkite/go-buildkite/v5 to v5.14.0 ([#384](https://github.com/chinmina/chinmina-bridge/issues/384)) ([2488d9a](https://github.com/chinmina/chinmina-bridge/commit/2488d9a8bd5aa2620eb3cc0e0bdc0033ad3406f6))
* **deps:** update module github.com/moby/go-archive to v0.3.3 ([#387](https://github.com/chinmina/chinmina-bridge/issues/387)) ([896914d](https://github.com/chinmina/chinmina-bridge/commit/896914d280f34994c745e83e5d2d43fb414ce7e5))
* **deps:** update module github.com/stretchr/testify to v1.12.1 ([#385](https://github.com/chinmina/chinmina-bridge/issues/385)) ([112ecbf](https://github.com/chinmina/chinmina-bridge/commit/112ecbfc89f7cc197640060fc16deb075df0e1b4))
* **deps:** update module github.com/valkey-io/valkey-go to v1.0.77 ([#380](https://github.com/chinmina/chinmina-bridge/issues/380)) ([79da920](https://github.com/chinmina/chinmina-bridge/commit/79da920defddf9d7561c0ca090594ced3eea5da0))
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
