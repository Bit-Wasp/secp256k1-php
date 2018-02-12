--TEST--
secp256k1_ec_pubkey_combine returns false if parameter parsing fails
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$combinedPubKey = null;
$badCtx = tmpfile();
$result = secp256k1_ec_pubkey_combine($badCtx, $combinedPubKey, []);
echo gettype($result) . PHP_EOL;
echo ($result ? "true" : "false") . PHP_EOL;

?>
--EXPECT--
secp256k1_ec_pubkey_combine(): supplied resource is not a valid secp256k1_context resource
boolean
false