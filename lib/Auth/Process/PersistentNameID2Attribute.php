<?php


/**
 * Authentication processing filter for generating an attribute from the persistent NameID.
 *
 * @package SimpleSAMLphp
 */
class sspmod_userid_Auth_Process_PersistentNameID2Attribute extends SimpleSAML_Auth_ProcessingFilter
{

    /**
     * The attribute we should save the NameID in.
     *
     * @var string
     */
    private $attribute;


    /**
     * Whether we should insert it as a saml:NameID element.
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

        if (!isset($state['saml:sp:NameID']) || $state['saml:sp:NameID']->Format !== \SAML2\Constants::NAMEID_PERSISTENT) {
            SimpleSAML\Logger::warning(
                'Unable to generate ' . $this->attribute 
                . ' attribute because no persistent NameID was available.'
            );
            return;
        }

        // @var \SAML2\XML\saml\NameID $nameID
        $nameID = $state['saml:sp:NameID'];

        $state['Attributes'][$this->attribute] = array((!$this->nameId) ? $nameID->value : $nameID);
    }
}
