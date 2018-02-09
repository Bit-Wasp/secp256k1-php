--TEST--
secp256k1_ec_pubkey_parse errors if context is wrong resource type
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$ctx = tmpfile();

$key = hex2bin("02227cedfab55d1b7642d47a5ac92638ed8822a23c3ddadf88defea45a37f5935e");
$pubKey = null;
$result = secp256k1_ec_pubkey_parse($ctx, $pubKey, $key);
echo gettype($result) . PHP_EOL;
echo ($result ? "true" : "false") . PHP_EOL;

?>
--EXPECT--
secp256k1_ec_pubkey_parse(): supplied resource is not a valid secp256k1_context resource
boolean
false
