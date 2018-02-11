--TEST--
secp256k1_ec_pubkey_serialize returns false if provided incorrect context type
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

\set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$context = \secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
$pubIn = pack("H*", "02227cedfab55d1b7642d47a5ac92638ed8822a23c3ddadf88defea45a37f5935e");
$pub = null;
$result = \secp256k1_ec_pubkey_parse($context, $pub, $pubIn);

$contextBad = \tmpfile();

$pubKeyOut = '';
$result = \secp256k1_ec_pubkey_serialize($contextBad, $pubKeyOut, $pub, 1);
echo \gettype($result) . PHP_EOL;
echo ($result ? "true" : "false") . PHP_EOL;

?>

--EXPECT--
secp256k1_ec_pubkey_serialize(): supplied resource is not a valid secp256k1_context resource
boolean
false
