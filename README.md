# Introduction

This is small and secure JSON Web Token implementation. It only supports 
the following signatures types:

- `HS256` (`HMAC` using `SHA-256`)
- `RS256` (`RSASSA-PKCS1-v1_5` using `SHA-256`)

These seem to be the most widely deployed JWT signature algorithms. The library 
does _NOT_ support encryption/decryption. Needless to say, this library is 
_NOT_ fully compliant with the JWT specification.

# Why?

Quite a number of JWT implementations exist for PHP, varying in quality. 
However, JWT can be [insecure](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid), 
so it is very important to get things right from a security perspective. This
means implementing the absolute minimum to support JWT, in a secure way. 
Simplicity and security is more important than fully supporting the 
specification(s).

# How?

A secure JWT library for generating and verifying JSON Web Tokens:

* Only supports `RS256` and `HS256` through separate classes, the header is 
  _NOT_ used to determine the algorithm;
* All keys are validated before use and wrapped in "Key" objects, to make sure 
  they are of the correct format. Helper methods are provided to 
  load/save/generate keys;
* Does NOT support the [crit](https://tools.ietf.org/html/rfc7515#section-4.1.11) 
  header key. If a token is presented with the `crit` header key it will be 
  rejected;
* Does NOT support encryption, encryption with the algorithms specified is a 
  lost cause;
* Verifies the `exp` and `nbf` payload field if present to make sure the token 
  is valid.

# Keys

## RS256 (RSA)

```bash
    $ openssl genrsa --out rsa.key 2048
    $ openssl rsa -in rsa.key -pubout -out rsa.pub
```

The RSA key MUST have [at least](https://tools.ietf.org/html/rfc7518#section-4.2)
2048 bits. This will generate a private key in `rsa.key` and the public key in 
`rsa.pub`. Those files can be used with `PublicKey` and `PrivateKey`.

To inspect a public key:

```bash
    $ openssl rsa -pubin -in rsa.pub -noout -text
```

## HS256 (HMAC)

Some helper methods are introduced to help you with generating, loading and 
saving keys. Do NOT use any other means to generate keys!

```php
    <?php

    // generating and saving a key
    $secretKey = SecretKey::generate();
    $encodedString = $secretKey->encode();

    // loading a key
    $secretKey = SecretKey::fromEncodedString($encodedString);
```

# API

## RS256

```php
    <?php

    $r = new RS256(
        PublicKey::load('rsa.pub'),
        PrivateKey::load('rsa.key')
    );
    $jwtStr = $r->encode(['foo' => 'bar']);
    var_dump($r->decode($jwtStr));
```

The `PrivateKey` parameter is optional. Do not specify it if you only want to
verify JWTs. Of course, you need to specify it when you want to sign a JWT.

## HS256

```php
    <?php

    $h = new HS256(SecretKey::fromEncodedString('5SBq2gMQFsy6ToGH0SS8CLFPCGxxFl8uohZUooCq5ps'));
    $jwtStr = $h->encode(['foo' => 'bar']);
    var_dump($h->decode($jwtStr));
```
