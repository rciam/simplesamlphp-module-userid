<?php

namespace SimpleSAML\Module\userid\Auth\Process;

use SimpleSAML\Auth\ProcessingFilter;
use SimpleSAML\Auth\State;
use SimpleSAML\Configuration;
use SimpleSAML\Error\Exception;
use SimpleSAML\Logger;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Utils\Config;
use SimpleSAML\XHTML\Template;

/**
 * This filter is based on the `smartattributes:SmartID` authentication
 * processing filter included in the SimpleSAMLphp distribution. As such,
 * it can be used to provide consistent user identifiers when there are
 * multiple SAML IdPs releasing different identifier attributes.
 *
 */
class OpaqueSmartID extends ProcessingFilter
{

    /**
     * If this option is specified, the filter will be executed only if the
     * authenticating IdP tags match any of the tags in the whitelist.
     */
    private $idpTagWhitelist = [];

    /**
     * If this option is specified, the filter will not be executed if the
     * authenticating IdP tags match any of the tags in the blacklist.
     */
    private $idpTagBlacklist = [];

    // List of IdP entityIDs that should be excluded from the authority
    // part of the user id source.
    private $skipAuthorityList = [];

    // List of IdP that have modified their entityID.
    // The array keys contain the new entityIDs and the values the old ones
    private $authorityMap = [];

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
     * The list of candidate attribute(s) to be used to copy the user ID for
     * whitelisted/blacklisted IdP tags.
     */
    private $cuidCandidates = [
        'voPersonID',
        'subject-id',
        'eduPersonUniqueId',
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
                throw new Exception(
                    '[OpaqueSmartID] authproc configuration error: \'idp_tag_whitelist\' should be an array.'
                );
            }
        }

        if (array_key_exists('idp_tag_blacklist', $config)) {
            $this->idpTagBlacklist = $config['idp_tag_blacklist'];
            if (!is_array($this->idpTagBlacklist)) {
                throw new Exception(
                    '[OpaqueSmartID] authproc configuration error: \'idp_tag_blacklist\' should be an array.'
                );
            }
        }

        if (array_key_exists('skip_authority_list', $config)) {
            $this->skipAuthorityList = $config['skip_authority_list'];
            if (!is_array($this->skipAuthorityList)) {
                throw new Exception(
                    '[OpaqueSmartID] authproc configuration error: \'skip_authority_list\' should be an array.'
                );
            }
        }

        if (array_key_exists('authority_map', $config)) {
            $this->authorityMap = $config['authority_map'];
            if (!is_array($this->authorityMap)) {
                throw new Exception(
                    '[OpaqueSmartID] authproc configuration error: \'authority_map\' should be an array.'
                );
            }
        }

        if (array_key_exists('candidates', $config)) {
            $this->candidates = $config['candidates'];
            if (!is_array($this->candidates)) {
                throw new Exception('[OpaqueSmartID] authproc configuration error: \'candidates\' should be an array.');
            }
        }

        if (array_key_exists('cuid_candidates', $config)) {
            $this->cuidCandidates = $config['cuid_candidates'];
            if (!is_array($this->cuidCandidates)) {
                throw new Exception(
                    '[OpaqueSmartID] authproc configuration error: \'cuid_candidates\' should be an array.'
                );
            }
        }

        if (array_key_exists('id_attribute', $config)) {
            $this->idAttribute = $config['id_attribute'];
            if (!is_string($this->idAttribute)) {
                throw new Exception(
                    '[OpaqueSmartID] authproc configuration error: \'id_attribute\' should be a string.'
                );
            }
        }

        if (array_key_exists('add_authority', $config)) {
            $this->addAuthority = $config['add_authority'];
            if (!is_bool($this->addAuthority)) {
                throw new Exception(
                    '[OpaqueSmartID] authproc configuration error: \'add_authority\' should be a boolean.'
                );
            }
        }

        if (array_key_exists('add_candidate', $config)) {
            $this->addCandidate = $config['add_candidate'];
            if (!is_bool($this->addCandidate)) {
                throw new Exception(
                    '[OpaqueSmartID] authproc configuration error: \'add_candidate\' should be a boolean.'
                );
            }
        }

        if (array_key_exists('scope', $config)) {
            $this->scope = $config['scope'];
            if (!is_string($this->scope)) {
                throw new Exception('[OpaqueSmartID] authproc configuration error: \'scope\' should be a string.');
            }
        }

        if (array_key_exists('set_userid_attribute', $config)) {
            $this->setUserIdAttribute = $config['set_userid_attribute'];
            if (!is_bool($this->setUserIdAttribute)) {
                throw new Exception(
                    '[OpaqueSmartID] authproc configuration error: \'set_userid_attribute\' should be a boolean.'
                );
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

        // If IdP tag blacklist is defined then skip OpaqueUserID generation
        // if IdP tag is blacklisted
        if (
            !empty($this->idpTagBlacklist)
            && !empty(array_intersect($this->idpTagBlacklist, $idpTags))
        ) {
            Logger::debug(
                "[OpaqueSmartID] process: Skipping IdP with tags " . var_export($idpTags, true) . " - blacklisted"
            );
            $this->copyUserId($request, $idpMetadata);
            return;
        }

        // If IdP tag whitelist is defined then skip OpaqueUserID generation
        // if IdP tag is *not* whitelisted
        if (
            !empty($this->idpTagWhitelist)
            && empty(array_intersect($this->idpTagWhitelist, $idpTags))
        ) {
            Logger::debug(
                "[OpaqueSmartID] process: Skipping IdP with tags " . var_export($idpTags, true)
                . " - not it whitelist"
            );
            $this->copyUserId($request, $idpMetadata);
            return;
        }

        $userId = $this->generateUserId($request);

        if (isset($userId)) {
            $request['Attributes'][$this->idAttribute] = [$userId];
            $request['rciamAttributes']['cuid'] = [$userId];
            // TODO: Remove this in SSP 2.0
            if ($this->setUserIdAttribute) {
                $request['UserID'] = $userId;
            }
            return;
        }
        $idpEmailAddress = $this->getIdPEmailAddress($idpMetadata);
        $baseUrl = Configuration::getInstance()->getString('baseurlpath');
        $this->showError(
            'NOIDENTIFIER',
            [
                '%ATTRIBUTES%' => $this->candidates,
                '%IDPNAME%' => $this->getIdPDisplayName($request),
                '%IDPEMAILADDRESS%' => $idpEmailAddress,
                '%BASEDIR%' => $baseUrl,
                '%RESTARTURL%' => $request[State::RESTART]
            ]
        );
    }

    private function generateUserId($request)
    {
        foreach ($this->candidates as $idCandidate) {
            if (empty($request['Attributes'][$idCandidate][0])) {
                continue;
            }
            try {
                $idValue = $this->parseUserId($request['Attributes'][$idCandidate][0]);
            } catch (Exception $e) {
                Logger::debug(
                    "[OpaqueSmartID] generateUserId: Failed to generate user ID based on candidate "
                    . $idCandidate . " attribute: " . $e->getMessage()
                );
                continue;
            }
            Logger::debug(
                "[OpaqueSmartID] generateUserId: Generating opaque user ID based on " . $idCandidate . ': ' . $idValue
            );
            $authority = null;
            if ($this->addAuthority) {
                $authority = $this->getAuthority($request);
            }
            if (!empty($authority) && array_key_exists($authority, $this->authorityMap)) {
                Logger::notice(
                    "[OpaqueSmartID] generateUserId: authorityMap: " . var_export($authority, true)
                    . " = " . var_export($this->authorityMap[$authority], true)
                );
                $authority = $this->authorityMap[$authority];
            }
            if (!empty($authority) && !in_array($authority, $this->skipAuthorityList, true)) {
                Logger::debug("[OpaqueSmartID] generateUserId: authority=" . var_export($authority, true));
                $smartId = ($this->addCandidate ? $idCandidate . ':' : '') . $idValue . '!' . $authority;
            } else {
                $smartId = ($this->addCandidate ? $idCandidate . ':' : '') . $idValue;
            }
            $salt = Config::getSecretSalt();
            $hashedUid = hash("sha256", $smartId . '!' . $salt);
            if (isset($this->scope)) {
                $hashedUid .= '@' . $this->scope;
            }
            Logger::notice(
                "[OpaqueSmartID] generateUserId: externalId=" . var_export($smartId, true)
                . ", internalId=" . var_export($hashedUid, true)
            );
            return $hashedUid;
        }
    }

    private function copyUserId(&$request, $idpMetadata)
    {
        foreach ($this->cuidCandidates as $idCandidate) {
            if (empty($request['Attributes'][$idCandidate][0])) {
                continue;
            }
            $idValue = $request['Attributes'][$idCandidate][0];
            Logger::debug(
                "[OpaqueSmartID] copyUserId: Copying user ID based on " . $idCandidate . ': ' . $idValue
            );
            $request['UserID'] = $idValue;
            $request['Attributes'][$this->idAttribute] = [$idValue];
            $request['rciamAttributes']['cuid'] = [$idValue];
            return;
        }
        $this->showError(
            'NOIDENTIFIER',
            [
                '%ATTRIBUTES%' => $this->cuidCandidates,
                '%IDPNAME%' => $this->getIdPDisplayName($request),
                '%IDPEMAILADDRESS%' => $this->getIdPEmailAddress($idpMetadata),
                '%BASEDIR%' => Configuration::getInstance()->getString('baseurlpath'),
                '%RESTARTURL%' => $request[State::RESTART]
            ]
        );
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
        } elseif (is_a($attribute, '\SAML2\XML\saml\NameID')) {
            if (
                !empty($attribute->getFormat())
                && $attribute->getFormat() === \SAML2\Constants::NAMEID_PERSISTENT
                && !empty($attribute->getValue())
            ) {
                $idValue = $attribute->getValue();
            } else {
                throw new Exception('[OpaqueSmartID] parseUserId: Unsupported NameID format');
            }
        } else {
            throw new Exception(
                '[OpaqueSmartID] parseUserId: Unsupported attribute value type: ' . get_class($attribute)
            );
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
