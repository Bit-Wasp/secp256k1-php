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

$pubKeyIn = pack("H*", "02227cedfab55d1b7642d47a5ac92638ed8822a23c3ddadf88defea45a37f5935e");

$pubKeyOut = '';
$pubKey = null;
$result = \secp256k1_ec_pubkey_parse($ctx, $pubKey, $pubKeyIn);
echo $result . PHP_EOL;

$badCtx = tmpfile();
$result = secp256k1_ec_pubkey_negate($badCtx, $pubKey);
echo gettype($result) . PHP_EOL;
echo ($result ? "true" : "false") . PHP_EOL;

?>
--EXPECT--
1
secp256k1_ec_pubkey_negate(): supplied resource is not a valid secp256k1_context resource
boolean
false