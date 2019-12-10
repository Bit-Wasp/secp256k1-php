--TEST--
secp256k1_xonly_pubkey_parse errors if context is wrong resource type
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$key = str_repeat("A", 32);
$keyOut = null;
$context = tmpfile();
$result = secp256k1_xonly_pubkey_parse($context, $keyOut, $key);
echo $result . PHP_EOL;

?>
--EXPECT--
secp256k1_xonly_pubkey_parse(): supplied resource is not a valid secp256k1_context resource
0