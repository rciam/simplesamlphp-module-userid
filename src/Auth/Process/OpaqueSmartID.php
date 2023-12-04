<?php
declare(strict_types=1);

namespace SimpleSAML\Module\userid\Auth\Process;

use SimpleSAML\{Configuration, Logger, Module};
use SimpleSAML\Assert\Assert;
use SimpleSAML\Auth\{ProcessingFilter, State};
use SimpleSAML\Error\Exception;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Utils;

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
     * @var \SimpleSAML\Utils\Config
     */
    protected Utils\Config $configUtils;

    /**
     * @var \SimpleSAML\Logger|string
     * @psalm-var \SimpleSAML\Logger|class-string
     */
    protected $logger = Logger::class;

    /**
     * If this option is specified, the filter will be executed only if the
     * authenticating IdP tags match any of the tags in the whitelist.
     */
    private array $idpTagWhitelist = [];

    /**
     * If this option is specified, the filter will not be executed if the
     * authenticating IdP tags match any of the tags in the blacklist.
     */
    private array $idpTagBlacklist = [];

    // List of IdP entityIDs that should be excluded from the authority
    // part of the user id source.
    /**
     * @var array|mixed
     */
    private array $skipAuthorityList = [];

    // List of IdP that have modified their entityID.
    // The array keys contain the new entityIDs and the values the old ones
    /**
     * @var array|mixed
     */
    private array $authorityMap = [];

    /**
     * The list of candidate attribute(s) to be used for the new ID attribute.
     */
    private array $candidates = [
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
     * Map of IdP-specific lists of candidate attribute(s) to be used for
     * the new ID attribute.
     */
    private array $authorityCandidateMap = [];

    /**
     * The list of candidate attribute(s) to be used to copy the user ID for
     * whitelisted/blacklisted IdP tags.
     */
    private array $cuidCandidates = [
        'voPersonID',
        'subject-id',
        'eduPersonUniqueId',
    ];

    /**
     * The name of the generated ID attribute.
     */
    private string $idAttribute = 'smart_id';

    /**
     * Whether to append the AuthenticatingAuthority, separated by '!'
     * This only works when SSP is used as a gateway.
     */
    private bool $addAuthority = true;

    /**
     * Whether to prepend the CandidateID, separated by ':'
     */
    private bool $addCandidate = true;

    /**
     * The scope of the generated ID attribute (optional).
     */
    private string $scope;

    /**
     * Whether to assign the generated user identifier to the `UserID`
     * state parameter
     */
    private bool $setUserIdAttribute = true;


    public function __construct(array $config, $reserved)
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

        if (array_key_exists('authority_candidate_map', $config)) {
            $this->authorityCandidateMap = $config['authority_candidate_map'];
            if (!is_array($this->authorityCandidateMap)) {
                throw new Exception(
                    '[OpaqueSmartID] authproc configuration error: \'authority_candidate_map\' should be an array.'
                );
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

        $this->configUtils = new Utils\Config();
    }

    /**
     * Process request.
     *
     * @param array &$request  The request to process
     */
    public function process(array &$request): void
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
            $this->logger::debug(
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
            $this->logger::debug(
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
                'attributes' => $this->candidates,
                'idpname' => $this->getIdPDisplayName($request),
                'idpemailaddress' => $idpEmailAddress,
                'basedir' => $baseUrl,
                'returnurl' => $request[State::RESTART]
            ]
        );
    }

    /**
     * @param   array  $request
     *
     * @return string|null
     * @throws Exception
     */
    private function generateUserId(array $request): ?string
    {
        $authority = null;
        if ($this->addAuthority) {
            $authority = $this->getAuthority($request);

            if (empty($authority)) {
                // This should never happen
                throw new Exception(
                   'Could not generate user identifier: Unknown authenticating authority'
                );
            }
        }

        if (isset($authority)
            && !empty($this->authorityCandidateMap[$authority])) {
            $idCandidates = $this->authorityCandidateMap[$authority];
        } else {
            $idCandidates = $this->candidates;
        }
        foreach ($idCandidates as $idCandidate) {
            if (empty($request['Attributes'][$idCandidate][0])) {
                continue;
            }
            try {
                $idValue = $this->parseUserId($request['Attributes'][$idCandidate][0]);
            } catch (Exception $e) {
                $this->logger::debug(
                    "[OpaqueSmartID] generateUserId: Failed to generate user ID based on candidate "
                    . $idCandidate . " attribute: " . $e->getMessage()
                );
                continue;
            }
            $this->logger::debug(
                "[OpaqueSmartID] generateUserId: Generating opaque user ID based on " . $idCandidate . ': ' . $idValue
            );
            if ($this->addAuthority && array_key_exists($authority, $this->authorityMap)) {
                $this->logger::notice(
                    "[OpaqueSmartID] generateUserId: authorityMap: " . var_export($authority, true)
                    . " = " . var_export($this->authorityMap[$authority], true)
                );
                $authority = $this->authorityMap[$authority];
            }
            if ($this->addAuthority && !in_array($authority, $this->skipAuthorityList, true)) {
                $this->logger::debug("[OpaqueSmartID] generateUserId: authority=" . var_export($authority, true));
                $smartId = ($this->addCandidate ? $idCandidate . ':' : '') . $idValue . '!' . $authority;
            } else {
                $smartId = ($this->addCandidate ? $idCandidate . ':' : '') . $idValue;
            }
            $salt = $this->configUtils->getSecretSalt();
            $hashedUid = hash("sha256", $smartId . '!' . $salt);
            if (isset($this->scope)) {
                $hashedUid .= '@' . $this->scope;
            }
            $this->logger::notice(
                "[OpaqueSmartID] generateUserId: externalId=" . var_export($smartId, true)
                . ", internalId=" . var_export($hashedUid, true)
            );
            return $hashedUid;
        }

        return null;
    }

    /**
     * @param   array  $request
     * @param          $idpMetadata
     *
     * @return void
     * @throws \Exception
     */
    private function copyUserId(array &$request, $idpMetadata): void
    {
        foreach ($this->cuidCandidates as $idCandidate) {
            if (empty($request['Attributes'][$idCandidate][0])) {
                continue;
            }
            $idValue = $request['Attributes'][$idCandidate][0];
            $this->logger::debug(
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
                // todo: Check why the %% are there. With twig they are probably redundant
                'attributes' => $this->cuidCandidates,
                'idpname' => $this->getIdPDisplayName($request),
                'idpemailaddress' => $this->getIdPEmailAddress($idpMetadata),
                'basedir' => Configuration::getInstance()->getString('baseurlpath'),
                'returnurl' => $request[State::RESTART]
            ]
        );
    }

    /**
     * @param   array  $request
     *
     * @return array|null
     */
    private function getAuthority(array $request): ?array
    {
        if (!empty($request['saml:AuthenticatingAuthority'])) {
            return array_values(array_slice($request['saml:AuthenticatingAuthority'], -1))[0];
        }
        return null;
    }

    /**
     * @param $attribute
     *
     * @return string
     * @throws Exception
     */
    private function parseUserId($attribute): string
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

    /**
     * @param   array  $idpMetadata
     *
     * @return  string  IdPs list of emails
     */
    private function getIdPEmailAddress(array $idpMetadata): string
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

    /**
     * @param   array  $idpMetadata
     *
     * @return array
     */
    private function getIdPTags(array $idpMetadata): array
    {
        if (!empty($idpMetadata['tags'])) {
            return $idpMetadata['tags'];
        }

        return [];
    }

    /**
     * @param   array  $request
     *
     * @return string
     * @throws \SimpleSAML\Error\MetadataNotFound
     */
    private function getIdPDisplayName(array $request): string
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

    /**
     * @param   array  $request
     *
     * @return array
     * @throws \SimpleSAML\Error\MetadataNotFound
     */
    private function getIdPMetadata(array $request): array
    {
        // If the module is active on a bridge,
        // $request['saml:sp:IdP'] will contain an entry id for the remote IdP.
        if (!empty($request['saml:sp:IdP'])) {
            $idpEntityId = $request['saml:sp:IdP'];
            return MetaDataStorageHandler::getMetadataHandler()->getMetaData($idpEntityId, 'saml20-idp-remote');
        }

        return $request['Source'];
    }

    /**
     * Inject the \SimpleSAML\Logger dependency.
     *
     * @param \SimpleSAML\Logger $logger
     */
    public function setLogger(Logger $logger): void
    {
        $this->logger = $logger;
    }

    /**
     * @param   string  $errorCode
     * @param   array   $parameters
     *
     * @return void
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    private function showError(string $errorCode, array $parameters): void
    {
        // Save state and redirect
        // The path matches the name of the route
        $url = Module::getModuleURL('userid/error');
        $params = [
          'errorCode' => $errorCode,
          // Serialize the parameters
          'parameters' => urlencode(base64_encode(json_encode($parameters)))
        ];

        $httpUtils = new Utils\HTTP();
        $httpUtils->redirectTrustedURL($url, $params);
    }
}
