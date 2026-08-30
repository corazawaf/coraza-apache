# Changelog

## [0.21.0](https://github.com/corazawaf/coraza-apache/compare/v0.20.1...v0.21.0) (2026-08-30)


### release

* prepare 0.21.0 ([#32](https://github.com/corazawaf/coraza-apache/issues/32)) ([eba1e7d](https://github.com/corazawaf/coraza-apache/commit/eba1e7d5c81d052e1be223513519c79059af34a1))

## [0.20.1](https://github.com/corazawaf/coraza-apache/compare/v0.20.0...v0.20.1) (2026-08-28)


### Bug Fixes

* read the loaded libcoraza version for the ABI check ([3ca5c20](https://github.com/corazawaf/coraza-apache/commit/3ca5c209219888b1b1e0b85ab5c1b326914286b5))
* return the rule status for phase-2/4 interruptions ([b4babc8](https://github.com/corazawaf/coraza-apache/commit/b4babc8dadd48b6def4309ed229f281f9c021f8f))
* return the rule status for phase-2/4 interruptions ([b61a8f7](https://github.com/corazawaf/coraza-apache/commit/b61a8f787ba658fffb6a1138cbaba5be221ec5f4)), closes [#26](https://github.com/corazawaf/coraza-apache/issues/26)

## [0.20.0](https://github.com/corazawaf/coraza-apache/compare/v0.3.0...v0.20.0) (2026-08-26)


### release

* prepare 0.20.0 ([97da1cf](https://github.com/corazawaf/coraza-apache/commit/97da1cf6bc4a07aa4beb5d7bec2fae0675259b9c))


### Bug Fixes

* cap delayed response-body buffering to bound worker memory ([c2d5af7](https://github.com/corazawaf/coraza-apache/commit/c2d5af78c79e7683e292228c7041f780c8cbff91))
* cap delayed response-body buffering to bound worker memory ([9685f71](https://github.com/corazawaf/coraza-apache/commit/9685f71463d20520b36f5171d9d77500e2363541))
* fail closed when body submission or processing fails in Coraza ([8031a75](https://github.com/corazawaf/coraza-apache/commit/8031a7500160be9b311b52758a8372c205a8abdb))
* fail closed when body submission or processing fails in Coraza ([70afb20](https://github.com/corazawaf/coraza-apache/commit/70afb20170cebd53af9b8e31533211b4429d78f5))
* fail closed when transaction creation fails in create_ctx ([adab744](https://github.com/corazawaf/coraza-apache/commit/adab7448506c35f5574908cc8a8db621cc1a34a7))
* fail closed when transaction creation fails in create_ctx ([8485aa6](https://github.com/corazawaf/coraza-apache/commit/8485aa6754f5b36e6d8c089ed7df050a2613a78a))
* guard size_t to int narrowing at the Coraza cgo boundary ([4425e23](https://github.com/corazawaf/coraza-apache/commit/4425e23e5319ba9d3fa314f48a0d3afe44624f44))
* guard size_t to int narrowing at the Coraza cgo boundary ([5ef6cd9](https://github.com/corazawaf/coraza-apache/commit/5ef6cd9e3e150a5aae50672be30ebb80aa9c3095))
* report REQUEST_PROTOCOL in slash-delimited form ([a83c85b](https://github.com/corazawaf/coraza-apache/commit/a83c85bd7fbad49497ec43e3f68c34c95c2f3495))
* report REQUEST_PROTOCOL in slash-delimited form ([4dbfc0f](https://github.com/corazawaf/coraza-apache/commit/4dbfc0fea259f4bca7890a95e696ea73551a07f6))
* stream SSE responses instead of buffering them ([9edb2ab](https://github.com/corazawaf/coraza-apache/commit/9edb2abc502ccd80102112918044baa9dbc838d2))
* stream SSE responses instead of buffering them ([706f502](https://github.com/corazawaf/coraza-apache/commit/706f5027edacf6139d5a55c8df7a9bbdfb6f6b7f))

## [0.3.0](https://github.com/corazawaf/coraza-apache/compare/v0.2.0...v0.3.0) (2026-04-16)


### Features

* add go-ftw e2e tests ([2e9d11e](https://github.com/corazawaf/coraza-apache/commit/2e9d11e7be787c4a2f41896f3192236c80672296))
* add go-ftw e2e tests ([15dfe02](https://github.com/corazawaf/coraza-apache/commit/15dfe02384e303754e899df11f02e1d0f4bfa9d6))


### Bug Fixes

* pin go-ftw version with renovatebot hint ([4bfee26](https://github.com/corazawaf/coraza-apache/commit/4bfee2650d748196a3d48b1a8462714e34e843ba))
* use v2 module path for go-ftw install ([748c09d](https://github.com/corazawaf/coraza-apache/commit/748c09dc81bbd1cac5bb7c5c2163ccbde9601867))

## [0.2.0](https://github.com/corazawaf/coraza-apache/compare/v0.1.0...v0.2.0) (2026-04-13)


### Features

* skip response body FFI when body inspection is disabled ([d838a8c](https://github.com/corazawaf/coraza-apache/commit/d838a8c92d6f0dc5a2bb1b0cb2cede7aa12135d0))
* skip response body FFI when body inspection is disabled ([5b21198](https://github.com/corazawaf/coraza-apache/commit/5b2119841ad205a37a31c66f473c41663c71de2d))


### Bug Fixes

* bump default LIBCORAZA_VERSION to v1.4.0 in Dockerfile ([bf58668](https://github.com/corazawaf/coraza-apache/commit/bf5866807aaff66a4558446beba70d203cc84289))
* update audit log tests for coraza engine v3.6.0+ semantics ([f9ffc4e](https://github.com/corazawaf/coraza-apache/commit/f9ffc4e72ac57e4a594f7daafc9c1f03452e1995)), closes [#9](https://github.com/corazawaf/coraza-apache/issues/9)

## [0.1.0](https://github.com/corazawaf/coraza-apache/compare/v0.0.1...v0.1.0) (2026-03-19)


### Features

* add Debian packaging ([bb0659a](https://github.com/corazawaf/coraza-apache/commit/bb0659a4a34093d84039c2ce376c0d87e70a7ada))
* add Debian packaging ([72e4c9e](https://github.com/corazawaf/coraza-apache/commit/72e4c9ef02d56f6ace36fd97aecd833729ea4d00))

## 0.0.1 (2026-03-16)


### Features

* Initial release
