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
 *       ),
 *
 * @author Nicolas Liampotis <nliam@grnet.gr>
 */
class sspmod_userid_Auth_Process_OpaqueSmartID extends SimpleSAML_Auth_ProcessingFilter {

	/**
	 * The list of candidate attribute(s) to be used for the new ID attribute.
	 */
	private $_candidates = array(
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
	private $_id_attribute = 'smart_id';

	/**
	 * Whether to append the AuthenticatingAuthority, separated by '!'
	 * This only works when SSP is used as a gateway.
	 */
	private $_add_authority = true;

	/**
	 * Whether to prepend the CandidateID, separated by ':'
	 */
	private $_add_candidate = true;

        /**
         * The scope of the generated ID attribute (optional).
         */
        private $_scope;        

	/**
	 * Whether to assign the generated user identifier to the `UserID` 
         * state parameter
	 */
	private $_set_userid_attribute = true;


	public function __construct($config, $reserved) {
		parent::__construct($config, $reserved);

		assert('is_array($config)');

		if (array_key_exists('candidates', $config)) {
			$this->_candidates = $config['candidates'];
			if (!is_array($this->_candidates)) {
				throw new Exception('HashedSmartID authproc configuration error: \'candidates\' should be an array.');
			}
		}

		if (array_key_exists('id_attribute', $config)) {
			$this->_id_attribute = $config['id_attribute'];
			if (!is_string($this->_id_attribute)) {
				throw new Exception('HashedSmartID authproc configuration error: \'id_attribute\' should be a string.');
			}
		}

		if (array_key_exists('add_authority', $config)) {
			$this->_add_authority = $config['add_authority'];
			if (!is_bool($this->_add_authority)) {
				throw new Exception('HashedSmartID authproc configuration error: \'add_authority\' should be a boolean.');
			}
		}

		if (array_key_exists('add_candidate', $config)) {
			$this->_add_candidate = $config['add_candidate'];
			if (!is_bool($this->_add_candidate)) {
				throw new Exception('HashedSmartID authproc configuration error: \'add_candidate\' should be a boolean.');
			}
		}

		if (array_key_exists('scope', $config)) {
			$this->_scope = $config['scope'];
			if (!is_string($this->_scope)) {
				throw new Exception('HashedSmartID authproc configuration error: \'scope\' should be a string.');
			}
		}

		if (array_key_exists('set_userid_attribute', $config)) {
			$this->_set_userid_attribute = $config['set_userid_attribute'];
			if (!is_bool($this->_set_userid_attribute)) {
				throw new Exception('OpaqueSmartID authproc configuration error: \'set_userid_attribute\' should be a boolean.');
			}
		}
	}

	private function addID($attributes, $request) {
		foreach ($this->_candidates as $idCandidate) {
			if (isset($attributes[$idCandidate][0])) {
                                SimpleSAML_Logger::debug("Generating hashed ID based on "
                                    .$idCandidate.':'.$attributes[$idCandidate][0]);
				if(($this->_add_authority) && (isset($request['saml:AuthenticatingAuthority'][0]))) {
					$smartID = ($this->_add_candidate ? $idCandidate.':' : '').$attributes[$idCandidate][0] . '!' . $request['saml:AuthenticatingAuthority'][0];
				} else {
					$smartID = ($this->_add_candidate ? $idCandidate.':' : '').$attributes[$idCandidate][0];
				}
				$salt = SimpleSAML\Utils\Config::getSecretSalt();
				$hashedUID = hash("sha256", $smartID.'!'.$salt);
				if (isset($this->_scope)) {
					return $hashedUID.'@'.$this->_scope;
				}
				return $hashedUID;
			}
		}
		/*
		* At this stage no usable id_candidate has been detected.
		*/
		throw new SimpleSAML_Error_Exception('This service needs at least one of the following
		attributes to identity users: '.implode(', ', $this->_candidates).'. Unfortunately not
		one of them was detected. Please ask your institution administrator to release one of
		them, or try using another identity provider.');
	}


	/**
	 * Apply filter to add or replace attributes.
	 *
	 * Add or replace existing attributes with the configured values.
	 *
	 * @param array &$request  The current request
	 */
	public function process(&$request) {
		assert('is_array($request)');
		assert('array_key_exists("Attributes", $request)');

		$ID = $this->addID($request['Attributes'], $request);

		if (isset($ID)) {
			$request['Attributes'][$this->_id_attribute] = array($ID);
			if ($this->_set_userid_attribute) {
				$request['UserID'] = $ID;
			}
		}
	}
}
