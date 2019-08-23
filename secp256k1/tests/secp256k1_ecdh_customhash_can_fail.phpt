--TEST--
secp256k1_ecdh - a custom hash function can cause operation to fail
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!function_exists("secp256k1_ecdh")) print "skip no ecdh support";
?>
--FILE--
<?php

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
$priv1 = str_pad('', 32, "\x41");
$priv2 = str_pad('', 32, "\x40");

/** @var resource $pub1 */
$pub1 = null;
$result = \secp256k1_ec_pubkey_create($context, $pub1, $priv1);
echo $result . PHP_EOL;

// Function we suppose is equivalent to upstreams default hash fxn
$callbackReturning = function ($returnVal) {
    return function (&$output, $x, $y) use ($returnVal) {
        echo "in callback\n";
        return $returnVal;
    };
};
$cbFalse = function (&$output, $x, $y) {
    return false;
};
$cbZero = function (&$output, $x, $y) {
    return 0;
};
echo "return 0\n";
$secret = '';
$result = \secp256k1_ecdh($context, $secret, $pub1, $priv2, $cbZero, 32, NULL);
echo $result . PHP_EOL;

echo "return false\n";
$secret = '';
$result = \secp256k1_ecdh($context, $secret, $pub1, $priv2, $cbFalse, 32, NULL);
echo $result . PHP_EOL;

?>
--EXPECT--
1
return 0
0
return false
0
