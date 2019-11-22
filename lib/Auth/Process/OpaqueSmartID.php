<?php

namespace SimpleSAML\Module\userid\Auth\Process;

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
 *    authproc = [
 *       ...
 *       '60' => [
 *           'class' => 'uid:OpaqueSmartID',
 *           'candidates' => [
 *               'eduPersonUniqueId',
 *               'eduPersonPrincipalName',
 *               'eduPersonTargetedID',
 *           ],
 *           'id_attribute' => 'eduPersonUniqueId',
 *           'add_candidate' => false,
 *           'add_authority' => true,
 *           'scope' => 'example.org',
 *           'skip_authority_list' => [
 *               'https://www.example1.org',
 *               'https://www.example2.org',
 *           ],
 *           'idp_tag_whitelist' => [
 *               'example1',
 *               'example2',
 *           ],
 *       ],
 *
 * @author Nicolas Liampotis <nliam@grnet.gr>
 */

use SimpleSAML\Auth\State;
use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\XHTML\Template;
use SimpleSAML\Utils\Config;

class OpaqueSmartID extends \SimpleSAML\Auth\ProcessingFilter
{

    /**
     * List of tags that the auth process should be executed
     */
    private $idpTagWhitelist = [];

    /**
     * List of tags that the auth process should not be executed
     */
    private $idpTagBlacklist = [];

    // List of IdP entityIDs that should be excluded from the authority
    // part of the user id source.
    private $skipAuthorityList = [];

    /**
     * The list of candidate attribute(s) to be used for the new ID attribute.
     */
    private $candidates = [
        'eduPersonUniqueId',
        'eduPersonPrincipalName',
        'eduPersonTargetedID',
        'openid',
        'linkedin_targetedID',
        'facebook_targetedID',
        'windowslive_targetedID',
        'twitter_targetedID',
    ];

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


    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);

        assert('is_array($config)');

        if (array_key_exists('idp_tag_whitelist', $config)) {
            $this->idpTagWhitelist = $config['idp_tag_whitelist'];
            if (!is_array($this->idpTagWhitelist)) {
                throw new \Exception('OpaqueSmartID authproc configuration error: \'idp_tag_whitelist\' should be an array.');
            }
        }

        if (array_key_exists('idp_tag_blacklist', $config)) {
            $this->idpTagBlacklist = $config['idp_tag_blacklist'];
            if (!is_array($this->idpTagBlacklist)) {
                throw new \Exception('OpaqueSmartID authproc configuration error: \'idp_tag_blacklist\' should be an array.');
            }
        }

        if (array_key_exists('skip_authority_list', $config)) {
            $this->skipAuthorityList = $config['skip_authority_list'];
            if (!is_array($this->skipAuthorityList)) {
                throw new \Exception('OpaqueSmartID authproc configuration error: \'skip_authority_list\' should be an array.');
            }
        }

        if (array_key_exists('candidates', $config)) {
            $this->candidates = $config['candidates'];
            if (!is_array($this->candidates)) {
                throw new \Exception('OpaqueSmartID authproc configuration error: \'candidates\' should be an array.');
            }
        }

        if (array_key_exists('id_attribute', $config)) {
            $this->idAttribute = $config['id_attribute'];
            if (!is_string($this->idAttribute)) {
                throw new \Exception('OpaqueSmartID authproc configuration error: \'id_attribute\' should be a string.');
            }
        }

        if (array_key_exists('add_authority', $config)) {
            $this->addAuthority = $config['add_authority'];
            if (!is_bool($this->addAuthority)) {
                throw new \Exception('OpaqueSmartID authproc configuration error: \'add_authority\' should be a boolean.');
            }
        }

        if (array_key_exists('add_candidate', $config)) {
            $this->addCandidate = $config['add_candidate'];
            if (!is_bool($this->addCandidate)) {
                throw new \Exception('OpaqueSmartID authproc configuration error: \'add_candidate\' should be a boolean.');
            }
        }

        if (array_key_exists('scope', $config)) {
            $this->scope = $config['scope'];
            if (!is_string($this->scope)) {
                throw new \Exception('OpaqueSmartID authproc configuration error: \'scope\' should be a string.');
            }
        }

        if (array_key_exists('set_userid_attribute', $config)) {
            $this->setUserIdAttribute = $config['set_userid_attribute'];
            if (!is_bool($this->setUserIdAttribute)) {
                throw new \Exception('OpaqueSmartID authproc configuration error: \'set_userid_attribute\' should be a boolean.');
            }
        }
    }

    /**
     * Process request.
     *
     * @param array &$request  The request to process
     */
    public function process(&$request)
    {
        assert('is_array($request)');
        assert('array_key_exists("Attributes", $request)');

        $idpMetadata = $this->getIdPMetadata($request);
        $idpTags = $this->getIdPTags($idpMetadata);
        if (!empty(array_intersect($this->idpTagBlacklist, $idpTags))) {
            if ($this->setUserIdAttribute && !empty($request['Attributes'][$this->idAttribute])) {
                $request['UserID'] = $request['Attributes'][$this->idAttribute][0];
            }
            Logger::debug("[OpaqueSmartID] Skipping IdP with tags " . var_export($idpTags, true));
            return;
        } else {
            if (!empty($this->idpTagWhitelist)) {
                if (empty(array_intersect($this->idpTagWhitelist, $idpTags))) {
                    if ($this->setUserIdAttribute && !empty($request['Attributes'][$this->idAttribute])) {
                        $request['UserID'] = $request['Attributes'][$this->idAttribute][0];
                    }
                    Logger::debug("[OpaqueSmartID] Skipping IdP with tags " . var_export($idpTags, true));
                    return;
                }
            }
        }

        $userId = $this->generateUserId($request['Attributes'], $request);

        if (isset($userId)) {
            $request['Attributes'][$this->idAttribute] = [$userId];
            // TODO: Remove this in SSP 2.0
            if ($this->setUserIdAttribute) {
                $request['UserID'] = $userId;
            }
            return;
        }
        $idpEmailAddress = $this->getIdPEmailAddress($idpMetadata);
        $baseUrl = Configuration::getInstance()->getString('baseurlpath');
        $this->showError('NOATTRIBUTE', [
            '%ATTRIBUTES%' => $this->candidates,
            '%IDP%' => $this->getIdPDisplayName($request),
            '%IDPEMAILADDRESS%' => $idpEmailAddress,
            '%BASEDIR%' => $baseUrl,
            '%RESTARTURL%' => $request[State::RESTART]
        ]);
    }

    private function generateUserId($attributes, $request)
    {
        foreach ($this->candidates as $idCandidate) {
            if (empty($attributes[$idCandidate][0])) {
                continue;
            }
            try {
                $idValue = $this->parseUserId($attributes[$idCandidate][0]);
            } catch (\Exception $e) {
                Logger::error("Failed to generate user ID based on candidate "
                    . $idCandidate . " attribute: " . $e->getMessage());
                continue;
            }
            Logger::debug("[OpaqueSmartID] Generating opaque user ID based on "
                . $idCandidate . ': ' . $idValue);
            $authority = null;
            if ($this->addAuthority) {
                $authority = $this->getAuthority($request);
            }
            if (!empty($authority) && !in_array($authority, $this->skipAuthorityList, true)) {
                Logger::debug("[OpaqueSmartID] authority=" . var_export($authority, true));
                $smartID = ($this->addCandidate ? $idCandidate . ':' : '') . $idValue . '!' . $authority;
            } else {
                $smartID = ($this->addCandidate ? $idCandidate . ':' : '') . $idValue;
            }
            $salt = Config::getSecretSalt();
            $hashedUID = hash("sha256", $smartID . '!' . $salt);
            Logger::notice("[OpaqueSmartID] externalId=" . var_export($smartID, true) . ", internalId=" . var_export($hashedUID, true));
            if (isset($this->scope)) {
                return $hashedUID . '@' . $this->scope;
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
                throw new \Exception('Unsupported NameID format');
            }
        } else {
            throw new \Exception('Unsupported attribute value type: '
                . get_class($attribute));
        }
        return $idValue;
    }

    private function getIdPEmailAddress($idpMetadata)
    {
        $idpEmailAddress = null;
        if (!empty($idpMetadata['contacts']) && is_array($idpMetadata['contacts'])) {
            foreach ($idpMetadata['contacts'] as $contact) {
                if (!empty($contact['contactType']) && !empty($contact['emailAddress'])) {
                    if ($contact['contactType'] === 'technical') {
                        $idpEmailAddress = $contact['emailAddress'];
                        continue;
                    } elseif ($contact['contactType'] === 'support') {
                        $idpEmailAddress = $contact['emailAddress'];
                        break;
                    }
                }
            }
        }

        if (!empty($idpEmailAddress)) {
            foreach ($idpEmailAddress as &$idpEmailAddressEntry) {
                if (substr($idpEmailAddressEntry, 0, 7) === "mailto:") {
                    $idpEmailAddressEntry = substr($idpEmailAddressEntry, 7);
                }
            }
            $idpEmailAddress = implode(";", $idpEmailAddress);
        }
        return $idpEmailAddress;
    }

    private function getIdPTags($idpMetadata)
    {
        if (!empty($idpMetadata['tags'])) {
            return $idpMetadata['tags'];
        }

        return [];
    }

    private function getIdPDisplayName($request)
    {
        assert('array_key_exists("entityid", $request["Source"])');

        // If the module is active on a bridge,
        // $request['saml:sp:IdP'] will contain an entry id for the remote IdP.
        if (!empty($request['saml:sp:IdP'])) {
            $idpEntityId = $request['saml:sp:IdP'];
            $idpMetadata = MetaDataStorageHandler::getMetadataHandler()->getMetaData($idpEntityId, 'saml20-idp-remote');
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

    private function getIdPMetadata($request)
    {
        // If the module is active on a bridge,
        // $request['saml:sp:IdP'] will contain an entry id for the remote IdP.
        if (!empty($request['saml:sp:IdP'])) {
            $idpEntityId = $request['saml:sp:IdP'];
            return MetaDataStorageHandler::getMetadataHandler()->getMetaData($idpEntityId, 'saml20-idp-remote');
        } else {
            return $request['Source'];
        }
    }

    private function showError($errorCode, $parameters)
    {
        $globalConfig = Configuration::getInstance();
        $t = new Template($globalConfig, 'userid:error.tpl.php');
        $t->data['errorCode'] = $errorCode;
        $t->data['parameters'] = $parameters;
        $t->show();
        exit();
    }
}
