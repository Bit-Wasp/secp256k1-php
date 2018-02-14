--TEST--
secp256k1_ec_pubkey_negate returns false if context is wrong resource type
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });
$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$badPubKey = tmpfile();

$result = secp256k1_ec_pubkey_negate($ctx, $badPubKey);
echo gettype($result) . PHP_EOL;
echo ($result ? "true" : "false") . PHP_EOL;

?>
--EXPECT--
secp256k1_ec_pubkey_negate(): supplied resource is not a valid secp256k1_pubkey resource
boolean
false