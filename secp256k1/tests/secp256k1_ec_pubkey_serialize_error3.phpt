--TEST--
secp256k1_ec_pubkey_serialize returns false if pubkey is incorrect resource type
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

\set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$context = \secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
$pubKeyOut = '';
$pub = tmpfile();
$result = \secp256k1_ec_pubkey_serialize($context, $pubKeyOut, $pub, 1);
echo \gettype($result) . PHP_EOL;
echo ($result ? "true" : "false") . PHP_EOL;

?>

--EXPECT--
secp256k1_ec_pubkey_serialize(): supplied resource is not a valid secp256k1_pubkey resource
boolean
false
