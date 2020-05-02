<?php

/**
 * This is a SimpleSAMLphp authentication processing filter for
 * making attribute(s) mandatory.
 * If the IdP doesn't release these attributes then the authentication
 * chain will stop with an error message displayed in the UI.
 *
 * Example configuration:
 *
 *    authproc = array(
 *       ...
 *       '60' => array(
 *           'class' => 'userid:RequiredAttributes',
 *           'attributes' => array(
 *               'givenName',
 *               'sn',
 *               'mail',
 *               'eduPersonScopedAffiliation',
 *           ),
 *           'custom_resolutions' => array(
 *               'https://www.example1.org/' => 'Error message foo',
 *               'https://www.example2.org/' => 'Error message foo bar',
 *           ),
 *       ),
 *
 * @author Nicolas Liampotis <nliam@grnet.gr>
 */

class sspmod_userid_Auth_Process_RequiredAttributes extends SimpleSAML_Auth_ProcessingFilter
{

    /**
     * The list of required attribute(s).
     */
    private $attributes = array(
        'givenName',
        'sn',
        'mail',
    );

    /**
     * A mapping for entityIDs and custom error message.
     * It's a list of entityIDs as keys and the messages as values.
     */
    private $customResolutions = [];

    public function __construct($config, $reserved) {
        parent::__construct($config, $reserved);

        assert('is_array($config)');

        if (array_key_exists('attributes', $config)) {
            $this->attributes = $config['attributes'];
            if (!is_array($this->attributes)) {
                throw new Exception('RequiredAttributes authproc configuration error: \'attributes\' should be an array.');
            }
        }

        if (array_key_exists('custom_resolutions', $config)) {
            $this->customResolutions = $config['custom_resolutions'];
            if (!is_array($this->attributes)) {
                throw new Exception('RequiredAttributes authproc configuration error: \'custom_resolutions\' should be an array.');
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

        $missingAttributes = [];
        foreach ($this->attributes as $attribute) {
            if (empty($request['Attributes'][$attribute])) {
                 $missingAttributes[] = $attribute;
            }
        }
        SimpleSAML_Logger::debug("[RequiredAttributes] missingAttributes=" . var_export($missingAttributes, true));
        if (empty($missingAttributes)) {
            return;
        }

        $idpEntityId = $this->getIdPEntityId($request);
        $idpMetadata = $this->getIdPMetadata($request);
        $idpName = $this->getIdPDisplayName($idpMetadata);
        if (is_null($idpName)) {
            $idpName = $idpEntityId;
        }
        $idpEmailAddress = $this->getIdPEmailAddress($idpMetadata);
        $baseUrl = SimpleSAML_Configuration::getInstance()->getString('baseurlpath');
        $errorParams = array(
            '%ATTRIBUTES%' => $missingAttributes,
            '%IDPNAME%' => $idpName,
            '%IDPEMAILADDRESS%' => $idpEmailAddress,
            '%BASEDIR%' => $baseUrl,
            '%RESTARTURL%' => $request[SimpleSAML_Auth_State::RESTART]
        );
        if (!empty($this->customResolutions["$idpEntityId"])) {
            $errorParams['%CUSTOMRESOLUTION%'] = $this->customResolutions["$idpEntityId"];
        }
        $this->showError('MISSINGATTRIBUTE', $errorParams);
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

    private function getIdPEntityId($request)
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

    private function getIdPMetadata($request)
    {
        // If the module is active on a bridge,
        // $request['saml:sp:IdP'] will contain an entry id for the remote IdP.
        if (!empty($request['saml:sp:IdP'])) {
            $idpEntityId = $request['saml:sp:IdP'];
            return SimpleSAML_Metadata_MetaDataStorageHandler::getMetadataHandler()->getMetaData($idpEntityId, 'saml20-idp-remote');
        } else {
            return $request['Source'];
        }
    }

    private function showError($errorCode, $errorParams)
    {
        $globalConfig = SimpleSAML_Configuration::getInstance();
        $t = new SimpleSAML_XHTML_Template($globalConfig, 'userid:error.tpl.php');
        $t->data['errorCode'] = $errorCode;
        $t->data['parameters'] = $errorParams;
        $t->show();
        exit();
    }

}
