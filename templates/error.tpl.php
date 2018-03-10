<?php
$this->data['header'] = $this->t('{userid:error:header}');

$this->data['head'] = <<<EOF
<meta name="robots" content="noindex, nofollow" />
<meta name="googlebot" content="noarchive, nofollow" />
EOF;

$this->includeAtTemplateBase('includes/header.php');
?>
    <h2><?php echo $this->t('{userid:error:title}'); ?></h2>
<?php
    echo('<p>' . $this->t('{userid:error:descr_'.$this->data['errorCode'].'}', $this->data['parameters']) . '</p>');

    echo('<p><a href="' . htmlspecialchars($this->data['parameters']['%BASEDIR%'] . 'saml2/idp/initSLO.php?RelayState=' . urlencode($this->data['parameters']['%RESTARTURL%'])) . '">' . $this->t('{userid:error:retry}') . '</a></p>');
?>

<?php
$this->includeAtTemplateBase('includes/footer.php');
