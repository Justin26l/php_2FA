<?php
require_once 'TwoFactorAuthenticate.php';

$TFA = new TwoFactorAuthenticate();

$secret = $TFA->randomSecret();

$QRimg = $TFA->getQR('Provider Name', $secret, 'Title');

?>

<h1>Time-based One Time Pass (TOTP)</h1>
<img src="<?=$QRimg?>" /><br/>

Secret: <?=$secret?><br/>

QR Code in next 5 min : <br />
<ol>
<?php 
    for ( $i = 0; $i < 10; $i++ ) {
        $advanceTime = time() + ($i * 30);
        echo '<li>' . $TFA->getCode($secret, $advanceTime ) . '</li>';
    };
?>
<ol>