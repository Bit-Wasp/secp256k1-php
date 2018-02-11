--TEST--
secp256k1_ecdh returns false if context is the wrong resource type
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

/** @var resource $pub1 */
$pub1 = null;
$result = \secp256k1_ec_pubkey_create($context, $pub1, $priv1);
echo $result . PHP_EOL;

$secret = '';
$badCtx = tmpfile();
$result = \secp256k1_ecdh($badCtx, $secret, $pub1, $priv2);
echo gettype($result).PHP_EOL;
echo ($result ? "true" : "false") . PHP_EOL;

?>
--EXPECT--
1
secp256k1_ecdh(): supplied resource is not a valid secp256k1_context resource
boolean
false