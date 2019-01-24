--TEST--
secp256k1_ec_pubkey_combine returns false if combination operation fails
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });
$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$seckeyOne = pack("H*", '0000000000000000000000000000000000000000000000000000000000000001');
$seckeyNMinusOne = pack("H*", 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140');
$pubKeyOne = null;
$pubKeyNMinusOne = null;

$result = secp256k1_ec_pubkey_create($ctx, $pubKeyOne, $seckeyOne);
echo $result . PHP_EOL;

$result = secp256k1_ec_pubkey_create($ctx, $pubKeyNMinusOne, $seckeyNMinusOne);
echo $result . PHP_EOL;

$combinedPubKey = null;
$result = secp256k1_ec_pubkey_combine($ctx, $combinedPubKey, [$pubKeyOne, $pubKeyNMinusOne]);
echo $result . PHP_EOL;

?>
--EXPECT--
1
1
0