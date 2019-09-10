<?php

/**
 * A SimpleSAMLphp authentication processing filter for generating long-lived, 
 * non-reassignable, non-targeted, opaque and globally unique user identifiers
 * based on the attributes received from the Identity Provider (IdP). The
 * identifier is generated using the first non-empty attribute from a given
 * list of attributes. At least one non-empty attribute is required, otherwise
 * authentication fails with an exception.
 *
 * This filter is based on the `smartattributes:SmartID` authentication
 * processing filter included in the SimpleSAMLphp distribution. As such,
 * it can be used to provide consistent user identifiers when there are 
 * multiple SAML IdPs releasing different identifier attributes.
 * The functionality of the original filter has been extended to support the
 * following identifier properties:
 * - Global uniqueness: This can be ensured by specifying a scope for the 
 *   generated user identifiers.
 * - Opaqueness: The generated user identifier (excluding the "@scope" portion)
 *   is based on the SHA-256 hash of the attributes received by the IdP, 
 *   resulting in an opaque 64-character long string that by itself provides no
 *   information about the identified user.
 * 
 * The following configuration options are available:
 * - `candidates`: An array of attributes names to consider as the user 
 *   identifier attribute. Defaults to:
 *     - `eduPersonUniqueId`
 *     - `eduPersonPrincipalName`
 *     - `eduPersonTargetedID`
 *     - `openid`
 *     - `linkedin_targetedID`
 *     - `facebook_targetedID`
 *     - `windowslive_targetedID`
 *     - `twitter_targetedID`
 * - `id_attribute`: A string to use as the name of the newly added attribute. 
 *    Defaults to `smart_id`.
 * - `add_authority`: A boolean to indicate whether or not to append the SAML
 *   AuthenticatingAuthority to the resulting identifier. This can be useful to
 *   indicate what SAML IdP was used, in case the original identifier is not 
 *   scoped. Defaults to `true`.
 * - `add_candidate`: A boolean to indicate whether or not to prepend the 
 *   candidate attribute name to the resulting identifier. This can be useful
 *   to indicate the attribute from which the identifier comes from. Defaults
 *   to `true`.
 * - `scope`: A string to use as the scope portion of the generated user
 *   identifier. There is no default scope value; however, you should consider
 *   scoping the generated attribute for creating globally unique identifiers
 *   that can be used across infrastructures.
 * - `set_userid_attribute`: A boolean to indicate whether or not to assign the
 *   generated user identifier to the `UserID` state parameter. Defaults to 
 *   `true`. If this is set to `false`, SSP will attempt to use the value of the
 *   `eduPersonPrincipalName` attribute, leading to errors when the latter is
 *   not available.
 *
 * The generated identifiers have the following form:
 *
 *     SHA-256(AttributeName:AttributeValue!AuthenticatingAuthority!SecretSalt)
 *
 * or, if a scope has been specified:
 *
 *     SHA-256(AttributeName:AttributeValue!AuthenticatingAuthority!SecretSalt)@scope
 * 
 * Example configuration:
 *
 *    authproc = array(
 *       ...
 *       '60' => array(
 *           'class' => 'uid:OpaqueSmartID',
 *           'candidates' => array(
 *               'eduPersonUniqueId',
 *               'eduPersonPrincipalName',
 *               'eduPersonTargetedID',
 *           ),
 *           'id_attribute' => 'eduPersonUniqueId',
 *           'add_candidate' => false,
 *           'add_authority' => true,
 *           'scope' => 'example.org',
 *           'skip_authority_list' => array(
 *               'https://www.example1.org',
 *               'https://www.example2.org',
 *           ),
 *       ),
 *
 * @author Nicolas Liampotis <nliam@grnet.gr>
 */
class sspmod_userid_Auth_Process_OpaqueSmartID extends SimpleSAML_Auth_ProcessingFilter {

    // List of IdP entityIDs that should be excluded from the authority
    // part of the user id source.
    private $skipAuthorityList = array();

    /**
     * The list of candidate attribute(s) to be used for the new ID attribute.
     */
    private $candidates = array(
        'eduPersonUniqueId',
        'eduPersonPrincipalName',
        'eduPersonTargetedID',
        'openid',
        'linkedin_targetedID',
        'facebook_targetedID',
        'windowslive_targetedID',
        'twitter_targetedID',
    );

    /**
     * The name of the generated ID attribute.
     */
    private $idAttribute = 'smart_id';

    /**
     * Whether to append the AuthenticatingAuthority, separated by '!'
     * This only works when SSP is used as a gateway.
     */
    private $addAuthority = true;

    /**
     * Whether to prepend the CandidateID, separated by ':'
     */
    private $addCandidate = true;

    /**
     * The scope of the generated ID attribute (optional).
     */
    private $scope;

    /**
     * Whether to assign the generated user identifier to the `UserID` 
         * state parameter
     */
    private $setUserIdAttribute = true;


    public function __construct($config, $reserved) {
        parent::__construct($config, $reserved);

        assert('is_array($config)');

        if (array_key_exists('skip_authority_list', $config)) {
            $this->skipAuthorityList = $config['skip_authority_list'];
            if (!is_array($this->skipAuthorityList)) {
                throw new Exception('OpaqueSmartID authproc configuration error: \'skip_authority_list\' should be an array.');
            }
        }

        if (array_key_exists('candidates', $config)) {
            $this->candidates = $config['candidates'];
            if (!is_array($this->candidates)) {
                throw new Exception('OpaqueSmartID authproc configuration error: \'candidates\' should be an array.');
            }
        }

        if (array_key_exists('id_attribute', $config)) {
            $this->idAttribute = $config['id_attribute'];
            if (!is_string($this->idAttribute)) {
                throw new Exception('OpaqueSmartID authproc configuration error: \'id_attribute\' should be a string.');
            }
        }

        if (array_key_exists('add_authority', $config)) {
            $this->addAuthority = $config['add_authority'];
            if (!is_bool($this->addAuthority)) {
                throw new Exception('OpaqueSmartID authproc configuration error: \'add_authority\' should be a boolean.');
            }
        }

        if (array_key_exists('add_candidate', $config)) {
            $this->addCandidate = $config['add_candidate'];
            if (!is_bool($this->addCandidate)) {
                throw new Exception('OpaqueSmartID authproc configuration error: \'add_candidate\' should be a boolean.');
            }
        }

        if (array_key_exists('scope', $config)) {
            $this->scope = $config['scope'];
            if (!is_string($this->scope)) {
                throw new Exception('OpaqueSmartID authproc configuration error: \'scope\' should be a string.');
            }
        }

        if (array_key_exists('set_userid_attribute', $config)) {
            $this->setUserIdAttribute = $config['set_userid_attribute'];
            if (!is_bool($this->setUserIdAttribute)) {
                throw new Exception('OpaqueSmartID authproc configuration error: \'set_userid_attribute\' should be a boolean.');
            }
        }
    }

    /**
     * Process request.
     *
     * @param array &$request  The request to process
     */
    public function process(&$request) {
        assert('is_array($request)');
        assert('array_key_exists("Attributes", $request)');

        $userId = $this->generateUserId($request['Attributes'], $request);

        if (isset($userId)) {
            $request['Attributes'][$this->idAttribute] = array($userId);
            // TODO: Remove this in SSP 2.0
            if ($this->setUserIdAttribute) {
                $request['UserID'] = $userId;
            }
            return;
        }
        $baseUrl = SimpleSAML_Configuration::getInstance()->getString('baseurlpath'
);
        $this->showError('NOATTRIBUTE', array(
            '%ATTRIBUTES%' => $this->candidates,
            '%IDP%' => $this->getIdPDisplayName($request),
            '%BASEDIR%' => $baseUrl,
            '%RESTARTURL%' => $request[SimpleSAML_Auth_State::RESTART]));
    }

    private function generateUserId($attributes, $request) {
        foreach ($this->candidates as $idCandidate) {
            if (empty($attributes[$idCandidate][0])) {
                continue;
            }
            try {
                $idValue = $this->parseUserId($attributes[$idCandidate][0]);
            } catch(Exception $e) {
                SimpleSAML_Logger::warning("Failed to generate user ID based on candidate "
                    . $idCandidate . " attribute: " . $e->getMessage());
                continue;
            }
            SimpleSAML_Logger::debug("[OpaqueSmartID] Generating opaque user ID based on "
                . $idCandidate . ': ' . $idValue);
            $authority = null;
            if ($this->addAuthority) {
                $authority = $this->getAuthority($request);
            }
            if (!empty($authority) && !in_array($authority, $this->skipAuthorityList, true)) {
                SimpleSAML_Logger::debug("[OpaqueSmartID] authority=" . var_export($authority, true));
                $smartID = ($this->addCandidate ? $idCandidate.':' : '') . $idValue . '!' . $authority;
            } else {
                $smartID = ($this->addCandidate ? $idCandidate.':' : '') . $idValue;
            }
            $salt = SimpleSAML\Utils\Config::getSecretSalt();
            $hashedUID = hash("sha256", $smartID.'!'.$salt);
            if (isset($this->scope)) {
                return $hashedUID.'@'.$this->scope;
            }
            return $hashedUID;
        }
    }

    private function getAuthority($request)
    {
        if (!empty($request['saml:AuthenticatingAuthority'])) {
            return array_values(array_slice($request['saml:AuthenticatingAuthority'], -1))[0];
        }
        return null;
    }

    private function parseUserId($attribute)
    {
        if (is_string($attribute) || is_int($attribute)) {
            $idValue = $attribute;
        } elseif (is_a($attribute, 'DOMNodeList') && $attribute->length === 1) {
            $nameId = new SAML2_XML_saml_NameID($attribute->item(0));
            if (isset($nameId->Format) && $nameId->Format === SAML2_Const::NAMEID_PERSISTENT && !empty($nameId->value)) {
                $idValue = $nameId->value;
            } else {
                throw new Exception('Unsupported NameID format');
            }
        } else     {
            throw new Exception('Unsupported attribute value type: '
                . get_class($attribute));
        }
        return $idValue;
    }

    private function getIdPDisplayName($request) 
    {
        assert('array_key_exists("entityid", $request["Source"])');

        // If the module is active on a bridge,
        // $request['saml:sp:IdP'] will contain an entry id for the remote IdP.
        if (!empty($request['saml:sp:IdP'])) {
            $idpEntityId = $request['saml:sp:IdP'];
            $idpMetadata = SimpleSAML_Metadata_MetaDataStorageHandler::getMetadataHandler()->getMetaData($idpEntityId, 'saml20-idp-remote');
        } else {
            $idpEntityId = $request['Source']['entityid'];
            $idpMetadata = $request['Source'];
        }

        if (!empty($idpMetadata['UIInfo']['DisplayName'])) {
            $displayName = $idpMetadata['UIInfo']['DisplayName'];
            // Should always be an array of language code -> translation
            assert('is_array($displayName)');
            // TODO: Use \SimpleSAML\Locale\Translate::getPreferredTranslation()
            // in SSP 2.0
            if (!empty($displayName['en'])) {
                return $displayName['en'];
            }
        }

        if (!empty($idpMetadata['name'])) {
            // TODO: Use \SimpleSAML\Locale\Translate::getPreferredTranslation()
            // in SSP 2.0
            if (!empty($idpMetadata['name']['en'])) {
                return $idpMetadata['name']['en'];
            } else {
                return $idpMetadata['name'];
            }
        }

        return $idpEntityId;
    }

    private function showError($errorCode, $parameters)
    {
        $globalConfig = SimpleSAML_Configuration::getInstance();
        $t = new SimpleSAML_XHTML_Template($globalConfig, 'userid:error.tpl.php');
        $t->data['errorCode'] = $errorCode;
        $t->data['parameters'] = $parameters;
        $t->show();
        exit();
    }

}
