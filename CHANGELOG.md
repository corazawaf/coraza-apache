# Changelog

## [0.21.1](https://github.com/corazawaf/coraza-apache/compare/v0.21.0...v0.21.1) (2026-09-26)


### Bug Fixes

* compare rule content on a WAF cache hit, not just hash and count ([5a73cc8](https://github.com/corazawaf/coraza-apache/commit/5a73cc84802af948f288eda86394e5e5324c46ec))
* compare rule content on a WAF cache hit, not just hash and count ([47cbf92](https://github.com/corazawaf/coraza-apache/commit/47cbf920f0cd5165c4661936af990256d074220b))
* do not delay response headers when the body will not be inspected ([64d3eb0](https://github.com/corazawaf/coraza-apache/commit/64d3eb084ecaa95beff7a1ee24aacc9bdf435215)), closes [#60](https://github.com/corazawaf/coraza-apache/issues/60)
* fail closed on every engine result, not only the body phases ([#64](https://github.com/corazawaf/coraza-apache/issues/64)) ([d050f24](https://github.com/corazawaf/coraza-apache/commit/d050f241b81d47e0a4513b7170779247389255b2))
* finalize phase 4 for an uninspected SSE response before streaming it ([6e0acef](https://github.com/corazawaf/coraza-apache/commit/6e0acef51c26c9056c032897bfdb8110a58ed611))
* hand the request body on to the application ([b5fbea8](https://github.com/corazawaf/coraza-apache/commit/b5fbea8c9ae3303b37fb3b7021c1f29c06d5c5bb))
* hand the request body on to the application ([01c37f8](https://github.com/corazawaf/coraza-apache/commit/01c37f8ef6a7e17b31506311665f7f1fedf453bf)), closes [#34](https://github.com/corazawaf/coraza-apache/issues/34)
* partition speculative replay reads and honour AP_MODE_EXHAUSTIVE ([ddc49b3](https://github.com/corazawaf/coraza-apache/commit/ddc49b395b2eb11e711cc465391ab27707756290))
* reject "Coraza On" when no rule is configured anywhere ([#58](https://github.com/corazawaf/coraza-apache/issues/58)) ([1441171](https://github.com/corazawaf/coraza-apache/commit/1441171ac91bd689dddc8ccaa03c16683e5bbaf4)), closes [#39](https://github.com/corazawaf/coraza-apache/issues/39)
* reject SecRemoteRules at httpd -t instead of in every child ([#63](https://github.com/corazawaf/coraza-apache/issues/63)) ([04759b7](https://github.com/corazawaf/coraza-apache/commit/04759b7c03e9d9e616b7d8afd4f705c899fcb215))
* release the coraza_new_waf error string with coraza_free_string ([#57](https://github.com/corazawaf/coraza-apache/issues/57)) ([21d7e68](https://github.com/corazawaf/coraza-apache/commit/21d7e682d4516ffe825cdf4e1fea4abfb6954894))
* report the protocol version as it arrived ([49e828a](https://github.com/corazawaf/coraza-apache/commit/49e828af7a99fa88d503d1623a27021cfb55f16f))
* report the protocol version as it arrived ([bba4139](https://github.com/corazawaf/coraza-apache/commit/bba413973d05f6d9a75214e27686e4f0f30a7cc3)), closes [#36](https://github.com/corazawaf/coraza-apache/issues/36)
* require libcoraza 1.8 and drop the 1.7 compatibility path ([aadf6e3](https://github.com/corazawaf/coraza-apache/commit/aadf6e3986252bac322d2eb85314e0f457b514ce)), closes [#60](https://github.com/corazawaf/coraza-apache/issues/60)
* reset r-&gt;read_length so ap_get_client_block callers get the replay ([3c73c7a](https://github.com/corazawaf/coraza-apache/commit/3c73c7a4951df5f20dc3cb92d64bdedc29f59c3a)), closes [#34](https://github.com/corazawaf/coraza-apache/issues/34)
* reuse the transaction across internal redirects instead of re-inspecting ([#59](https://github.com/corazawaf/coraza-apache/issues/59)) ([865678d](https://github.com/corazawaf/coraza-apache/commit/865678df1994971b349ccf7dd32f818a743313f7))
* spool the saved request body to disk above an in-memory limit ([a64cf9a](https://github.com/corazawaf/coraza-apache/commit/a64cf9a17d16464340c0b2d853b858335abe509f))


### Performance Improvements

* do not submit the request body to the engine when body access is off ([#66](https://github.com/corazawaf/coraza-apache/issues/66)) ([75ccb33](https://github.com/corazawaf/coraza-apache/commit/75ccb333e9bd4c767e2a5f91b84986e7ed7c314d))
* read the request body in 64 KiB chunks from the request pool ([c2cad5e](https://github.com/corazawaf/coraza-apache/commit/c2cad5e975c0220ac2a626866e285e02f55fca3b))
* read the request body in 64 KiB chunks from the request pool ([758f4ee](https://github.com/corazawaf/coraza-apache/commit/758f4ee0680d816c9c83fd50aad13a2ea664689b))
* submit request and response headers to the engine in bulk ([#68](https://github.com/corazawaf/coraza-apache/issues/68)) ([cbc13ac](https://github.com/corazawaf/coraza-apache/commit/cbc13ac53926d0114f94969e27421ce9dd00ca53))

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
