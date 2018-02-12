--TEST--
secp256k1_ec_pubkey_combine returns false if parameter parsing fails
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });
$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$seckey = hex2bin('7ccca75d019dbae79ac4266501578684ee64eeb3c9212105f7a3bdc0ddb0f27e');
$pubKeys = [tmpfile()];

$combinedPubKey = null;
$result = secp256k1_ec_pubkey_combine($ctx, $combinedPubKey, $pubKeys);
echo gettype($result) . PHP_EOL;
echo ($result ? "true" : "false") . PHP_EOL;

?>
--EXPECT--
secp256k1_ec_pubkey_combine(): supplied resource is not a valid secp256k1_pubkey resource
boolean
false