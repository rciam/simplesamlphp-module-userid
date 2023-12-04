<?php

declare(strict_types=1);

namespace SimpleSAML\Module\userid\Controller;

use SAML2\Constants as C;
use SimpleSAML\Assert\Assert;
use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Module\adfs\IdP\ADFS as ADFS_IdP;
use SimpleSAML\Session;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Symfony\Component\VarExporter\VarExporter;
use Twig\TwigFunction;

/**
 * Controller class for the admin module.
 *
 * This class serves the federation views available in the module.
 *
 * @package SimpleSAML\Module\admin
 */
class ErrorReport
{
    /**
     * Sandbox constructor.
     *
     * @param \SimpleSAML\Configuration $config The configuration to use.
     * @param \SimpleSAML\Session $session The current user session.
     */
    public function __construct(
      protected Configuration $config,
      protected Session $session
    ) {
    }

    /**
     * Display the sandbox page
     *
     * @return \SimpleSAML\XHTML\Template
     */
    public function main(Request $request, string $as = null): Template
    {
        $errorCode = $request->query->get('errorCode');
        $parameters = $request->query->get('parameters');

        $parameters = json_decode(base64_decode(urldecode($parameters)));

        Logger::debug('parameters:' . var_export($parameters, true));
        
        // redirect the user back to this page to clear the POST request
        $t = new Template($this->config, 'userid:errorreport.twig');
        $t->data['errorCode'] = $errorCode;
        foreach ($parameters as $key => $val) {
            $t->data[$key] = $val;
        }

        $twig = $t->getTwig();
        // TWIG does not have an htmlspecialchars function. We will pass in the one from php
        $twig->addFunction(new TwigFunction('htmlspecialchars', 'htmlspecialchars'));

        return $t;
    }

}
