# vaulted

[![Build status](https://github.com/sumup-oss/vaulted/workflows/Go/badge.svg?branch=master&event=push)](https://github.com/sumup-oss/vaulted/actions?query=workflow%3AGo)
[![Go Report Card](https://goreportcard.com/badge/github.com/sumup-oss/vaulted)](https://goreportcard.com/report/github.com/sumup-oss/vaulted)

Multi purpose cryptography tool for encryption/decryption using AES256 GCM.

A "swiss-army" encryption/decryption knife with focus on developer experience, ease-of-use and
 integration capabilities in infrastructure-as-code software such as https://github.com/hashicorp/terraform.

Combined with https://github.com/sumup-oss/terraform-provider-vaulted, it's shown 
 at https://medium.com/@syndbg/provisioning-vault-encrypted-secrets-using-terraform-using-sumup-oss-vaulted-and-4aa9721d082c?source=friends_link&sk=9eabe1bbe6ba089fe176d94cf413862d

## Why

* Ease-of-use.
* First-class terraform support. Also check https://github.com/sumup-oss/terraform-provider-vaulted/.
* Asymmetric encryption.
* **Large files are supported due to AES256 GCM encryption/decryption used.**
* GPG/PGP keychain-less which means you don't need external GPG/PGP keychain and neither do your users. (Support for this may be added in the future)
* Completely testable and high test coverage consisting of unit, integration and e2e tests.
* Encryption,
* Decryption,
* Secret rotation,
* Secret re-keying.

## [How it works](./HOW_IT_WORKS.md)

## Used in:
 
* https://github.com/sumup-oss/terraform-provider-vaulted to provide encryption/decryption capabilities.
* SumUp inner-source large-scale provision orchestration software projects.
* SumUp inner-source projects that deploy using Ansible. Used to encrypt/decrypt the initial Ansible-Vault passphrase.
* SumUp infrastructure provisioning via Terraform to provide Vault secrets and enable developers to 
 encrypt and submit secrets as PRs without anyone other than system administrators, devops, 
 site-reliability engineers be able to decrypt them.
* SumUp inner-source CI systems that need to encrypt/decrypt secrets in sandboxes.

## Prerequisites

1. RSA public and private key pair for asymmetric encryption (using `openssl`, `cfssl` or whichever works for you).

## Setup

### Generating a private key pair for asymmetric encryption

```shell
# Generate PKCS#1 private key
> openssl genrsa -f4 -out private.pem 4096
# Generate from private key, a public key
> openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```

### I already have keys

**Make sure that your private and public keys are PEM-formatted**.

Example valid public key

```
-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----
```

**Your private key must be `PKCS#1`-formatted**.

Example `PKCS#1`-formatted private key

```
-----BEGIN RSA PRIVATE KEY-----
...
<content>
...
-----END RSA PRIVATE KEY-----
```

Example **unusable** with `vaulted` `PKCS#8`-formatted private key

```
-----BEGIN PRIVATE KEY-----
...
<content>
...
-----END PRIVATE KEY-----
```

**What is the difference in base64-encoded content?** 

Obvious different is in the PEM block names.

However, in terms of content, `PKCS#8` PEM contains the `version` and `algorithm` identifiers and 
 `private key` content.

The `PKCS#1` PEM contains just the `private key` content. 

## Usage

Check out [COMMANDS](./COMMANDS.md)

## Data format structure

When you use `vaulted`, you're going to see that it generates unique "strings" in a certain format.
The format is:

* Reserved `$VED` signature
* Data format version, e.g `1.0`
* Separator `::`
* Randomly generated and base64-encoded AES256 cipher passphrase encrypted via user-provided RSA public key
* Separator `::`
* User-provided base64-encoded secret payload encrypted via the previously randomly generated AES256 cipher passphrase

E.g payload

```
$VED;1.0::lobnjrnSDJZBzWeaETjbxc0Gqs3cm6BlIkgCebGBtTYJSchZRMoJlXjH79ladMuBxkjvRbk/Hul5ZjC+gKGjLW1wm+1n+KmZQGjeq418zq1uZ5S6GGLGC/x9tc1CYV2n6dljTV77kSDaL94/My6sHp+HKeHP6LM/uGg0ixRMqv8gW/uC27wnjuONzad9I/EfUmyoDxd7sIi3nr/UnLelsgDJ4cCMlABAmEdXf+TyrpLfSQ7t7DACTpzB3WIomlNM4jSmcvhbVHfvmsOZgzIxK38LyvNAsLNAHZx/e0NcEE8jxBei3r8MHZZ9JSms1KlHzRbR7Yh8+giYx4ArpmS/vw==::m8mqNQMIfNpdWjj3zjCe/aoNCwfpCUbJ/3Dt4ulcLyRFOZR8dA==
```

## Contributing

Check out [CONTRIBUTING](./CONTRIBUTING.md)

## About SumUp

[SumUp](https://sumup.com) is a mobile-point of sale provider.

It is our mission to make easy and fast card payments a reality across the *entire* world. 

You can pay with SumUp in more than 30 countries, already. 

Our engineers work in Berlin, Cologne, Sofia and Sāo Paulo. 

They write code in JavaScript, Swift, Ruby, Go, Java, Erlang, Elixir and more. 

Want to come work with us? [Head to our careers page](https://sumup.com/careers) to find out more.
