--TEST--
secp256k1_ec_seckey_verify works
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$secKeyOne = str_repeat("\x00", 31) . "\x01";
$secKeyOrderMinusOne = pack("H*", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140");
$secKeyOrder = pack("H*", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

$result = secp256k1_ec_seckey_verify($context, $secKeyOne);
echo $result . PHP_EOL;

$result = secp256k1_ec_seckey_verify($context, $secKeyOrderMinusOne);
echo $result . PHP_EOL;

$result = secp256k1_ec_seckey_verify($context, $secKeyOrder);
echo $result . PHP_EOL;

?>
--EXPECT--
1
1
0