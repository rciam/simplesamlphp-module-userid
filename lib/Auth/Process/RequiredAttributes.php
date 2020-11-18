<?php

namespace SimpleSAML\Module\userid\Auth\Process;

use SimpleSAML\Auth\ProcessingFilter;
use SimpleSAML\Auth\State;
use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Metadata\MetaDataStorageHandler;
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
     * The list of required attribute(s).
     */
    private $attributes = [
        'givenName',
        'sn',
        'mail',
    ];

    /**
     * A mapping for entityIDs and custom error message.
     * It's a list of entityIDs as keys and the messages as values.
     */
    private $customResolutions = [];

    public function __construct($config, $reserved)
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
    public function process(&$request)
    {
        assert('is_array($request)');
        assert('array_key_exists("Attributes", $request)');

        $missingAttributes = [];
        foreach ($this->attributes as $attribute) {
            if (empty($request['Attributes'][$attribute])) {
                $missingAttributes[] = $attribute;
            }
        }
        Logger::debug("[RequiredAttributes] process: missingAttributes=" . var_export($missingAttributes, true));
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
            '%ATTRIBUTES%' => $missingAttributes,
            '%IDPNAME%' => $idpName,
            '%IDPEMAILADDRESS%' => $idpEmailAddress,
            '%BASEDIR%' => $baseUrl,
            '%RESTARTURL%' => $request[State::RESTART]
        ];
        if (!empty($this->customResolutions["$idpEntityId"])) {
            $errorParams['%CUSTOMRESOLUTION%'] = $this->customResolutions["$idpEntityId"];
        }
        $this->showError('MISSINGATTRIBUTE', $errorParams);
    }

    private function getIdpEmailAddress($idpMetadata)
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

    private function getIdPDisplayName($idpMetadata)
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

    private function getIdpEntityId($request)
    {
        assert('array_key_exists("entityid", $request["Source"])');

        // If the module is active on a bridge,
        // $request['saml:sp:IdP'] will contain an entry id for the remote IdP.
        if (!empty($request['saml:sp:IdP'])) {
            return $request['saml:sp:IdP'];
        } else {
            return $request['Source']['entityid'];
        }
    }

    private function getIdpMetadata($request)
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

    private function showError($errorCode, $errorParams)
    {
        $globalConfig = Configuration::getInstance();
        $t = new Template($globalConfig, 'userid:error.tpl.php');
        $t->data['errorCode'] = $errorCode;
        $t->data['parameters'] = $errorParams;
        $t->show();
        exit();
    }
}
