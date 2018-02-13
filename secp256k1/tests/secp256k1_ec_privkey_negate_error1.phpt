--TEST--
secp256k1_ec_privkey_negate returns false if context is wrong resource type
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$keyTweak = str_repeat("A", 32);
$context = tmpfile();
$result = secp256k1_ec_privkey_negate($context, $keyTweak);
echo gettype($result) . PHP_EOL;
echo ($result ? "true" : "false") . PHP_EOL;

?>
--EXPECT--
secp256k1_ec_privkey_negate(): supplied resource is not a valid secp256k1_context resource
boolean
false