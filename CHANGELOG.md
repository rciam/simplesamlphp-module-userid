# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v1.4.0]
This version is compatible with [SimpleSAMLphp v1.17](https://simplesamlphp.org/docs/1.17/simplesamlphp-changelog)

### Changed
- Code reformatted to PSR-2
- Declare module's class under SimpleSAML\Module namespace

## [v1.3.0]
This version is compatible with [SimpleSAMLphp v1.14](https://simplesamlphp.org/docs/1.14/simplesamlphp-changelog)

### Added
- PersistentNameID2Attribute class
  - Generates an attribute from the persistent NameID
- Skip filter when attribute is already set

### Changed
- Include IdP DisplayName in error page
- Use PSR-2 coding rules

## [v1.2.0]
This version is compatible with [SimpleSAMLphp v1.14](https://simplesamlphp.org/docs/1.14/simplesamlphp-changelog)

### Added
- Use last authority value in case of IdP proxies

## [v1.1.0]
This version is compatible with [SimpleSAMLphp v1.14](https://simplesamlphp.org/docs/1.14/simplesamlphp-changelog)

### Added
- Use template for error page
- Support for SAML 2.0 Persistent NameIDs/ePTIDs

## [v1.0.0]
This version is compatible with [SimpleSAMLphp v1.14](https://simplesamlphp.org/docs/1.14/simplesamlphp-changelog)

### Added
- OpaqueSmartID class
  - Provides consistent user identifiers
