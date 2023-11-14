<?php

declare(strict_types=1);

namespace SimpleSAML\Module\userid\Auth\Process;

use SimpleSAML\Auth\ProcessingFilter;
use SimpleSAML\Auth\State;
use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Module;
use SimpleSAML\XHTML\Template;

/**
 * This is a SimpleSAMLphp authentication processing filter for
 * making attribute(s) mandatory.
 * If the IdP doesn't release these attributes then the authentication
 * chain will stop with an error message displayed in the UI.
 *
 * Example configuration:
 *
 *    authproc = [
 *       ...
 *       '60' => [
 *           'class' => 'userid:RequiredAttributes',
 *           'attributes' => [
 *               'givenName',
 *               'sn',
 *               'mail',
 *               'eduPersonScopedAffiliation',
 *           ],
 *           'custom_resolutions' => [
 *               'https://www.example1.org/' => 'Error message foo',
 *               'https://www.example2.org/' => 'Error message foo bar',
 *           ],
 *       ],
 *
 * @author Nicolas Liampotis <nliam@grnet.gr>
 */
class RequiredAttributes extends ProcessingFilter
{
    /**
     * @var \SimpleSAML\Logger|string
     * @psalm-var \SimpleSAML\Logger|class-string
     */
    protected $logger = Logger::class;

    /**
     * The list of required attribute(s).
     */
    private array $attributes = [
        'givenName',
        'sn',
        'mail',
    ];

    /**
     * A mapping for entityIDs and custom error message.
     * It's a list of entityIDs as keys and the messages as values.
     */
    private array $customResolutions = [];

    /**
     * @param   array  $config
     * @param          $reserved
     */
    public function __construct(array $config, $reserved)
    {
        parent::__construct($config, $reserved);

        assert('is_array($config)');

        if (array_key_exists('attributes', $config)) {
            $this->attributes = $config['attributes'];
            if (!is_array($this->attributes)) {
                throw new Exception(
                    '[RequiredAttributes] authproc configuration error: \'attributes\' should be an array.'
                );
            }
        }

        if (array_key_exists('custom_resolutions', $config)) {
            $this->customResolutions = $config['custom_resolutions'];
            if (!is_array($this->attributes)) {
                throw new Exception(
                    '[RequiredAttributes] authproc configuration error: \'custom_resolutions\' should be an array.'
                );
            }
        }
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

        $missingAttributes = [];
        foreach ($this->attributes as $attribute) {
            if (empty($request['Attributes'][$attribute])) {
                $missingAttributes[] = $attribute;
            }
        }
        $this->logger::debug("[RequiredAttributes] process: missingAttributes=" . var_export($missingAttributes, true));
        if (empty($missingAttributes)) {
            return;
        }

        $idpEntityId = $this->getIdpEntityId($request);
        $idpMetadata = $this->getIdpMetadata($request);
        $idpName = $this->getIdPDisplayName($idpMetadata);
        if (is_null($idpName)) {
            $idpName = $idpEntityId;
        }
        $idpEmailAddress = $this->getIdpEmailAddress($idpMetadata);
        $baseUrl = Configuration::getInstance()->getString('baseurlpath');
        $errorParams = [
            'attributes' => $missingAttributes,
            'idpname' => $idpName,
            'idpemailadress' => $idpEmailAddress,
            'basedir' => $baseUrl,
            'restarturl' => $request[State::RESTART]
        ];
        if (!empty($this->customResolutions["$idpEntityId"])) {
            $errorParams['%CUSTOMRESOLUTION%'] = $this->customResolutions["$idpEntityId"];
        }
        $this->showError('MISSINGATTRIBUTE', $errorParams);
    }

    /**
     * @param   array  $idpMetadata
     *
     * @return string
     */
    private function getIdpEmailAddress(array $idpMetadata): string
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
     * @return string|null
     */
    private function getIdPDisplayName(array $idpMetadata): ?string
    {
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

        return null;
    }

    /**
     * @param   array  $request
     *
     * @return string
     */
    private function getIdpEntityId(array $request): string
    {
        assert('array_key_exists("entityid", $request["Source"])');

        // If the module is active on a bridge,
        // $request['saml:sp:IdP'] will contain an entry id for the remote IdP.
        if (!empty($request['saml:sp:IdP'])) {
            return $request['saml:sp:IdP'];
        }

        return $request['Source']['entityid'];
    }

    /**
     * @param   array  $request
     *
     * @return array
     * @throws \SimpleSAML\Error\MetadataNotFound
     */
    private function getIdpMetadata(array $request): array
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
     * @param   string  $errorCode
     * @param   array   $parameters
     *
     * @return void
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    private function showError(string $errorCode, array $parameters): void
    {
        // Save state and redirect
        $url = Module::getModuleURL('/userid/errorReport');
        $params = [
          'errorCode' => $errorCode,
          'parameters' => $parameters
        ];

        $httpUtils = new Utils\HTTP();
        $httpUtils->redirectTrustedURL($url, $params);
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
}
