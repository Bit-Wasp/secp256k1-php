--TEST--
secp256k1_schnorrsig_sign errors if msg parameter is not 32 bytes
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!function_exists("secp256k1_schnorrsig_verify")) print "skip no schnorrsig support";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

// fixture came from our signatures.yml
$msg32 = \pack("H*", "9e5755ec2f328cc8635a55415d");
$priv = \pack("H*", "31a84594060e103f5a63eb742bd46cf5f5900d8406e2726dedfc61c7cf43ebad");

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$keypair = null;
$result = secp256k1_keypair_create($ctx, $keypair, $priv);
echo $result.PHP_EOL;

$sig = null;
try {
    secp256k1_schnorrsig_sign($ctx, $sig, $msg32, $keypair);
} catch (\Exception $e) {
    echo $e->getMessage() . PHP_EOL;
}

?>
--EXPECT--
1
secp256k1_schnorrsig_sign(): Parameter 3 should be 32 bytes
