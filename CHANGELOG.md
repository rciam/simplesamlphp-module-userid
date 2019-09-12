# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- OpaqueSmartID class
  - List of tags that should be excluded from the authority part of the user id source.
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
  - List of IdP entityIDs that should be excluded from the authority part of the user id source.
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
