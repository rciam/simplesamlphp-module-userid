# simplesamlphp-module-userid
A SimpleSAMLphp authentication processing filter for generating long-lived, 
non-reassignable, non-targeted, opaque and globally unique user identifiers
based on the attributes received from the Identity Provider (IdP). The
identifier is generated using the first non-empty attribute from a given
list of attributes. At least one non-empty attribute is required, otherwise
authentication fails with an exception.

This filter is based on the `smartattributes:SmartID` authentication
processing filter included in the SimpleSAMLphp distribution. As such,
it can be used to provide consistent user identifiers when there are 
multiple SAML IdPs releasing different identifier attributes.
The functionality of the original filter has been extended to support the
following identifier properties:
 * **Global uniqueness**: This can be ensured by specifying a scope for the 
   generated user identifier.
 * **Opaqueness**: The generated user identifier (excluding the "@scope" portion)
   is based on the SHA-256 hash of the attributes received by the IdP, resulting 
   in an opaque 64-character long string that by itself provides no information about
   the identified user.
   
## Configuration
The following configuration options are available:
 * `candidates`: An array of attributes names to consider as the user 
   identifier attribute. Defaults to:
    * `eduPersonUniqueId`
    * `eduPersonPrincipalName`
    * `eduPersonTargetedID`
    * `openid`
    * `linkedin_targetedID`
    * `facebook_targetedID`
    * `windowslive_targetedID`
    * `twitter_targetedID`
 * `id_attribute`. A string to use as the name of the newly added attribute. 
   Defaults to `smart_id`.
 * `add_authority`: A boolean to indicate whether or not to append the SAML
   AuthenticatingAuthority to the resulting identifier. This can be useful to
   indicate what SAML IdP was used, in case the original identifier is not 
   scoped. Defaults to `true`.
 * `add_candidate`: A boolean to indicate whether or not to prepend the 
   candidate attribute name to the resulting identifier. This can be useful
   to indicate the attribute from which the identifier comes from. Defaults
   to `true`.
 * `scope`: A string to use as the scope portion of the generated user
   identifier. There is no default scope value; however, you should consider
   scoping the generated attribute for creating globally unique identifiers
   that can be used across infrastructures.
 * `set_userid_attribute`: A boolean to indicate whether or not to assign the
    generated user identifier to the `UserID` state parameter. Defaults to 
    `true`. If this is set to `false`, SSP will attempt to use the value of the
    `eduPersonPrincipalName` attribute, leading to errors when the latter is
    not available.
 
The generated identifiers have the following form:
```
SHA-256(AttributeName:AttributeValue!AuthenticatingAuthority!SecretSalt)
``` 
or, if a scope has been specified:
``` 
SHA-256(AttributeName:AttributeValue!AuthenticatingAuthority!SecretSalt)@scope
```

### Example configuration:
 
```
authproc = [
    ...
    '60' => [
        'class' => 'uid:OpaqueSmartID',
        'candidates' => [
            'eduPersonUniqueId',
            'eduPersonPrincipalName',
            'eduPersonTargetedID',
        ],
        'id_attribute' => 'eduPersonUniqueId',
        'add_candidate' => false,
        'add_authority' => true,   
        'scope' => 'example.org',
    ],
```

## License

Licensed under the Apache 2.0 license, for details see `LICENSE`.
