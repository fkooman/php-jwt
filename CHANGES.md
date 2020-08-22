# ChangeLog

## 1.1.0 (2020-08-22)
- make static code analyzers happy
- move header check until after the signature has been verified
- remove public `Jwt::setDateTime()`, was only used for testing and nobody was
  supposed to use it anyway, if they do/did that is a security issue, and their
  code MUST break
- actual algorithm classes have now a `getAlgorithm()` method exposing the
  JWT algorithm instead of a `const`

## 1.0.1 (2019-08-20)
- switch to `paragonie/sodium_compat` for Composer installations
- add benchmarks for signature validation

## 1.0.0 (2019-03-06)
- remove redundant type checks
- update README

## 0.3.0 (2019-02-08)
- add ability to set key ID
- remove "automatic" key ID from Key classes

## 0.2.2 (2018-10-23)
- add missing polyfill

## 0.2.1 (2018-10-23)
- implement libsodium < 2 support

## 0.2.0 (2018-10-23)
- move Keys to their own namespace
- implement `EdDSA` (RFC 8037, curve Ed25519)

## 0.1.0 (2018-09-28)
- initial release
