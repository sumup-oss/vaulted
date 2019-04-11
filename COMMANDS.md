# Commands

All subcommands are:

* [`vaulted version`](#vaulted-version)
* [`vaulted help`](#vaulted-help)
* [`vaulted legacy`](#vaulted-legacy)
* [`vaulted legacy ini`](#vaulted-legacy-ini)
* [`vaulted legacy encrypt`](#vaulted-legacy-encrypt)
* [`vaulted legacy decrypt`](#vaulted-legacy-decrypt)
* [`vaulted encrypt`](#vaulted-encrypt)
* [`vaulted decrypt`](#vaulted-decrypt)
* [`vaulted rotate`](#vaulted-rotate)
* [`vaulted rekey`](#vaulted-rekey)
* [`vaulted terraform ini`](#vaulted-terraform-ini)
* [`vaulted terraform migrate`](#vaulted-terraform-migrate)
* [`vaulted terraform new-resource`](#vaulted-terraform-new-resource)
* [`vaulted terraform rekey`](#vaulted-terraform-rekey)
* [`vaulted terraform rotate`](#vaulted-terraform-rotate)

## `vaulted version`

Shows the version of `vaulted`

```shell
> vaulted version
0.6.0
```

## `vaulted help`

Shows usage help

```shell
> vaulted help
Vault encrypt/decrypt using asymmetric RSA keys and AES

Usage:
  vaulted [flags]
  vaulted [command]

Available Commands:
  decrypt     Decrypt a file/value
  encrypt     Encrypt a file/value
  help        Help about any command
  legacy      Legacy Proof-of-concept-phase commands
  rekey       Rekey (decrypt and encrypt using different keypair) a file/value
  rotate      Rotate (decrypt and encrypt) a file/value
  terraform   Terraform resources related commands
  version     Print the version of vaulted

Flags:
  -h, --help   help for vaulted

Use "vaulted [command] --help" for more information about a command.
```

## `vaulted legacy`

Points you to using `--help` to see available subcommands for `legacy`.

```shell
> vaulted legacy
Use `--help` to see available commands
```

## `vaulted legacy ini`

Converts an INI file to terraform file. It uses "legacy" `vault_encrypted_secret` terraform resources.

```shell
> vaulted legacy ini \
--public-key-path pubkey.pem \
--in ./my_secrets.ini \
--out ./my_secrets.tf
```

## `vaulted legacy encrypt`

Encrypts an `in` file source or from stdin and 
writes to `out` file source or to stdout.

It uses legacy encryption strategy.

```shell
> vaulted legacy encrypt \
--public-key-path pubkey.pem \
--in ./my_secrets.raw \
--out ./my_secrets.enc
```

## `vaulted legacy decrypt`

Decrypts an `in` file source or from stdin and 
writes to `out` file source or to stdout.

It uses legacy decryption strategy.

```shell
> vaulted legacy decrypt \
--private-key-path privkey.pem \
--in ./my_secrets.enc \
--out ./my_secrets.raw
```

## `vaulted encrypt`

Encrypts an `in` file source or from stdin and 
writes to `out` file source or to stdout.

It uses encrypt flow specified in [How it works](./HOW_IT_WORKS.md#encrypt-secret-flow).

```shell
> vaulted encrypt \
--public-key-path pubkey.pem \
--in ./my_secrets.raw \
--out ./my_secrets.enc
```

## `vaulted decrypt`

Decrypts an `in` file source or from stdin and 
writes to `out` file source or to stdout.

It uses decrypt flow specified in [How it works](./HOW_IT_WORKS.md#decrypt-secret-flow).

```shell
> vaulted decrypt \
--private-key-path privkey.pem \
--in ./my_secrets.enc \
--out ./my_secrets.raw
```

## `vaulted rotate`

Rotates an `in` file source or from stdin and 
writes to `out` file source or to stdout.

It uses rotate flow specified in [How it works](./HOW_IT_WORKS.md#rotate-secret-flow).

```shell
> vaulted rotate \
--private-key-path privkey.pem \
--public-key-path pubkey.pem \
--in ./my_secrets.enc \
--out ./rotated_my_secrets.enc
```

## `vaulted rekey`

Rekeys an `in` file source or from stdin and 
writes to `out` file source or to stdout.

Rekeying is the process of decrypting an encrypted payload 
with old private key and encrypting with new public key (from new keypair).

It uses rekeys flow specified in [How it works](./HOW_IT_WORKS.md#re-key-secret-flow).

```shell
> vaulted rekey \
--old-private-key-path privkey.pem \
--new_public-key-path pubkey.pem \
--in ./my_secrets.enc \
--out ./rekeyed_my_secrets.enc
```

## `vaulted terraform ini`

Converts an INI file to terraform file. It uses "future-proof" 
 `vaulted_vault_secret` terraform resources.

```shell
> vaulted terraform ini \
--public-key-path pubkey.pem \
--in ./my_secrets.ini \
--out ./my_secrets.tf
```

## `vaulted terraform migrate`

Migrates a terraform `in` file  with `vault_encrypted_secret` resources generated from `legacy ini`,
 to terraform `vaulted_vault_secret` resources as you would generate them from `terraform ini`.
 
**If specified `out` already exists, it does not overwrite, it appends.**

**Terraform resources different than `vault_encrypted_secret` are not modified. They're simply moved to `out`**

```shell
> vaulted terraform migrate \
--public-key-path ./my-pubkey.pem \
--private-key-path ./my-privkey.pem \
--in ./mysecret.tf \
--out ./migrated.tf
```

## `vaulted terraform new-resource`

Create new terraform `vaulted_vault_secret` resource with specified `path` and `resource-name` (as suffix).

`in` will be encrypted and serialized. Result is terraform file at `out`.
 
**If specified `out` already exists, it does not overwrite, it appends.**

```shell
> vaulted terraform new-resource \
--public-key-path ./my-pubkey.pem \
--in ./mysecret.txt \
--out ./mysecret.tf \
--path secret/example-app/example-key \
--resource-name example_app_example_key
```

## `vaulted terraform rekey`

Rekeys an `in` terraform file and writes to `out` terraform file with rekeyed resources.

Rekeying is the process of decrypting an encrypted payload 
with old private key and encrypting with new public key (from new keypair).

It uses rekeys flow specified in [How it works](./HOW_IT_WORKS.md#re-key-secret-flow).
 
**If specified `out` already exists, it does not overwrite, it appends.**

**Terraform resources different than `vaulted_vault_secret` are not modified. They're simply moved to `out`**

```shell
> vaulted terraform rekey \
--new-public-key-path ./my-pubkey.pem \
--old-private-key-path ./my-privkey.pem \
--in new.tf \
--out test.tf
```

## `vaulted terraform rotate`

Rotates an `in` terraform file and writes to `out` terraform file with rekeyed resources.

It uses rotate flow specified in [How it works](./HOW_IT_WORKS.md#rotate-secret-flow).
 
**If specified `out` already exists, it does not overwrite, it appends.**

**Terraform resources different than `vaulted_vault_secret` are not modified. They're simply moved to `out`**

```shell
> vaulted terraform rotate \
--public-key-path ./my-pubkey.pem \
--private-key-path ./my-privatekey.pem \
--in ./in.tf \
--out ./out.tf
```


