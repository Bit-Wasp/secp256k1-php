--TEST--
secp256k1_ec_privkey_tweak_mul errors if context is wrong resource type
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$key = str_repeat("A", 32);
$keyTweak = str_repeat("A", 32);

$context = tmpfile();
$result = secp256k1_ec_privkey_tweak_mul($context, $key, $keyTweak);
echo gettype($result) . PHP_EOL;
echo ($result ? "true" : "false") . PHP_EOL;

?>
--EXPECT--
secp256k1_ec_privkey_tweak_mul(): supplied resource is not a valid secp256k1_context resource
boolean
false