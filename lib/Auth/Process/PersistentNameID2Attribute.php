<?php

namespace SimpleSAML\Module\userid\Auth\Process;

use SAML2\Constants;
use SimpleSAML\Auth\ProcessingFilter;
use SimpleSAML\Logger;

/**
 * Authentication processing filter for generating an attribute from the persistent NameID.
 *
 * Example configuration:
 *
 *    authproc = [
 *       ...
 *       '61' => [
 *           'class' => 'userid:PersistentNameID2Attribute',
 *           'attribute' => 'eduPersonTargetedID',
 *           'nameId' => true,
 *       ],
 *
 * @package SimpleSAMLphp
 */
class PersistentNameID2Attribute extends ProcessingFilter
{

    /**
     * The attribute we should save the NameID in.
     *
     * @var string
     */
    private $attribute;


    /**
     * Whether we should insert it as a \SAML2\XML\saml\NameID object.
     *
     * @var boolean
     */
    private $nameId;


    /**
     * Initialise this filter, parse configuration.
     *
     * @param array $config Configuration information about this filter.
     * @param mixed $reserved For future use.
     */
    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);
        assert('is_array($config)');

        if (isset($config['attribute'])) {
            $this->attribute = (string) $config['attribute'];
        } else {
            $this->attribute = 'eduPersonTargetedID';
        }

        if (isset($config['nameId'])) {
            $this->nameId = (bool) $config['nameId'];
        } else {
            $this->nameId = true;
        }
    }


    /**
     * Store a NameID to attribute.
     *
     * @param array &$state The request state.
     */
    public function process(&$state)
    {
        assert('is_array($state)');

        if (!empty($state['Attributes'][$this->attribute])) {
            return;
        }

        if (
            !isset($state['saml:sp:NameID'])
            || $state['saml:sp:NameID']->getFormat() !== Constants::NAMEID_PERSISTENT
        ) {
            Logger::warning(
                '[PersistentNameID2Attribute] process: Unable to generate ' . $this->attribute
                . ' attribute because no persistent NameID was available.'
            );
            return;
        }

        // @var \SAML2\XML\saml\NameID $nameID
        $spNameId = $state['saml:sp:NameID'];

        $state['Attributes'][$this->attribute] = [(!$this->nameId) ? $spNameId->getValue() : $spNameId];
    }
}
