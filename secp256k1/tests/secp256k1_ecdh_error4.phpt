--TEST--
secp256k1_ecdh returns false if public key is the wrong resource type
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
$priv1 = str_pad('', 32, "\x41");
$priv2 = str_pad('', 32, "\x40");

$pub1 = tmpfile();

$secret = '';
$result = \secp256k1_ecdh($context, $secret, $pub1, $priv2);
echo gettype($result).PHP_EOL;
echo ($result ? "true" : "false") . PHP_EOL;

?>
--EXPECT--
secp256k1_ecdh(): supplied resource is not a valid secp256k1_pubkey resource
boolean
false