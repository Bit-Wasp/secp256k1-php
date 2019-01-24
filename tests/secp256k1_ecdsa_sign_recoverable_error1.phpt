--TEST--
secp256k1_ecdsa_sign_recoverable errors if provided an invalid resource as a context
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

// fixture came from our signatures.yml
$msg32 = \pack("H*", "9e5755ec2f328cc8635a55415d0e9a09c2b6f2c9b0343c945fbbfe08247a4cbe");
$priv = \pack("H*", "31a84594060e103f5a63eb742bd46cf5f5900d8406e2726dedfc61c7cf43ebad");

$ctx = tmpfile();

$sig = null;
$result = secp256k1_ecdsa_sign_recoverable($ctx, $sig, $msg32, $priv);
echo $result . PHP_EOL;

?>
--EXPECT--
secp256k1_ecdsa_sign_recoverable(): supplied resource is not a valid secp256k1_context resource
0