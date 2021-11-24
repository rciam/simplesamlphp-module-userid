# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Save CUID after generating the User ID

### Changed

- Refactor `copyUserId()` function

### Fixed

- Save `$state` in `copyUserId()`

## [v3.2.0] - 2021-11-23

### Added

- Add `cuid_candidates` option containing a list of candidate attributes to
  consider for the persistent user identifier. The first non-empty value from
  the candidates list will be copied (pass-through) to the target
  `id_attribute`.

## [v3.1.0] - 2021-05-10

### Added

- Support for retaining authority identifier when IdP entityId changes

## [v3.0.4] - 2021-03-08

### Fixed

- Fix translation bug in error template

## [v3.0.3] - 2021-03-04

### Fixed

- Fix bug in parseUserId()
- Fix getters for SP NameID element

## [v3.0.2] - 2020-11-18

### Changed

- Improve `OpaqueSmartID` logging
- Improve `OpaqueSmartID` error messages

## [v3.0.1] - 2020-07-10

### Changed

- Improve handling of idpTagBlacklist/idpTagWhitelist

## [v3.0.0] - 2019-01-20

This version is compatible with [SimpleSAMLphp v1.17](https://simplesamlphp.org/docs/1.17/simplesamlphp-changelog)

### Changed

- Switch classes to use namespaces
- Add use declarations to classes
- Change coding style based on PSR-2
  - Opening braces for classes and functions go on the next line
  - Remove left over whitespaces
- Apply modern array syntax to all files

## [v2.2.0] - 2019-11-25

### Added

- OpaqueSmartID class
  - Add `idp_tag_blacklist` option

### Changed

- OpaqueSmartID class
  - Replace `skip_tag_list` with `idp_tag_whitelist` option

## [v2.1.0] - 2019-09-18

### Added

- OpaqueSmartID class
  - Include email address of the IdP technical/support contact in the error message

## [v2.0.0] - 2019-09-13

This version is compatible with [SimpleSAMLphp v1.15](https://simplesamlphp.org/docs/1.15/simplesamlphp-changelog)

### Added

- OpaqueSmartID class
  - Add support for excluding IdPs from the authority part of the user id
    source based on their tags
- Add instructions for `PersistentNameID2Attribute` class
- Add `RequiredAttributes` class

### Changed

- Required changes to support SimpleSAMLphp v1.15

## [v1.0.0] - 2019-09-10

This version is compatible with [SimpleSAMLphp v1.14](https://simplesamlphp.org/docs/1.14/simplesamlphp-changelog)

### Added

- OpaqueSmartID class
  - Provides consistent user identifiers
  - Support for SAML 2.0 Persistent NameIDs/ePTIDs
  - List of IdP entityIDs that should be excluded from the authority part of
    the user id source.
- PersistentNameID2Attribute class
  - Generates an attribute from the persistent NameID
- Use template for error page
  - Include IdP DisplayName in error page
  - Restart authentication process on error
- Skip filter when attribute is already set

### Changed

- Use last authority value in case of IdP proxies
- Include IdP DisplayName in error page
- Use PSR-2 coding rules
