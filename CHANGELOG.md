# Version History

## Intro

The version history is motivated by https://semver.org/ and https://keepachangelog.com/en/1.0.0/ .

NOTE: This project went from non-standard versioning to semver at some point. 

## Structure

Types of changes that can be seen in the changelog

```
Added: for new features/functionality.
Changed: for changes in existing features/functionality.
Deprecated: for soon-to-be removed features. Removed in the 
Removed: for now removed features.
Fixed: for any bug fixes.
Security: in case of vulnerabilities.
```

## How deprecation of functionality is handled?

tl;dr 1 minor release stating that the functionality is going to be deprecated. Then in the next major - removed.

```
Deprecating existing functionality is a normal part of software development and 
is often required to make forward progress. 

When you deprecate part of your public API, you should do two things: 

(1) update your documentation to let users know about the change, 
(2) issue a new minor release with the deprecation in place. 
Before you completely remove the functionality in a new major 
release there should be at least one minor release 
that contains the deprecation so that users can smoothly transition to the new API
```

As per https://semver.org/ .

As per rule-of-thumb, moving the project forward is very important, 
  but providing stability is the most important thing to anyone using `vaulted`.

Introducing breaking changes under a feature flag can be ok in some cases where new functionality needs user feedback before being introduced in next major release.

## Changelog

Change line format:

```
* <Change title/PR title/content> ; Ref: <pr link>
```

## Unreleased (master)

### Changed

* Fix AWS interface extensibility ; Ref: https://github.com/sumup-oss/vaulted/pull/34

## v0.3.0

### Added

* AWS KMS asymmetric keypair encryption & decryption support ; Ref: https://github.com/sumup-oss/vaulted/pull/33

### Changed

* Commands from `terraform` sub-command are now part of `terraform vault`. This is to accommodate for future `terraform X` command where X might be another provider ; Ref: https://github.com/sumup-oss/vaulted/pull/5
* Replaced HCLv1 parser with HCLv2 one ; Ref: https://github.com/sumup-oss/vaulted/pull/16
* Untangled the API implemented by other users of vaulted like terraform providers. Result is now it's easier to implement different strategies, like in the future - GCP KMS support. ; Ref: https://github.com/sumup-oss/vaulted/pull/33
 
### Removed

* Commands from `legacy` sub-command are now removed. We're not using them internally. The migration from legacy to v1 secret format command(s) are there to help you transition ; Ref: https://github.com/sumup-oss/vaulted/pull/15
* HCLv1 parsing and support for Terraform earlier than 0.12 ; Ref: https://github.com/sumup-oss/vaulted/pull/16
* `ini` commands. Ref: https://github.com/sumup-oss/vaulted/pull/33

## v0.2.1

### Changed

* Commands that have sub-commands print help information by default ; Ref: https://github.com/sumup-oss/vaulted/pull/3

## v0.2.0

### Added

* Support to read public and private keys from []byte ; Ref: https://github.com/sumup-oss/vaulted/pull/2

### Fixed

* Fixed test execution on windows ; Ref: https://github.com/sumup-oss/vaulted/pull/2

## v0.1.0

### Added

* Project
* CI setup
* Documentation
