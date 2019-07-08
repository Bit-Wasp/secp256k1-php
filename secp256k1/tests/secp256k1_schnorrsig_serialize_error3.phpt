--TEST--
secp256k1_schnorrsig_serialize errors if secp256k1_schnorrsig is wrong resource type
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

$sig = hex2bin("7a8e3bdc7c64f31b119a849e8bb39ddbdc0a64abd4cadcc5cfc15d3ec06354ed4719389aedb16b2dd13552eed546b24350d6e636ac454ea72afc1ffd0cf421b7");
// serializes signature again
$schnorrsig = tmpfile();

$sigout = '';
$result = secp256k1_schnorrsig_serialize($ctx, $sigout, $schnorrsig);
echo $result . PHP_EOL;
echo unpack("H*", $sigout)[1].PHP_EOL;

?>
--EXPECT--
secp256k1_schnorrsig_serialize(): supplied resource is not a valid secp256k1_schnorrsig resource
0