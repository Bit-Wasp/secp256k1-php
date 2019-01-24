--TEST--
secp256k1_ecdh works
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
$priv1 = str_pad('', 32, "\x41");
$priv2 = str_pad('', 32, "\x40");
$expectedSecret = '238c14f420887f8e9bfa78bc9bdded1975f0bb6384e33b4ebbf7a8c776844aec';

/** @var resource $pub1 */
$pub1 = null;
$result = \secp256k1_ec_pubkey_create($context, $pub1, $priv1);
echo $result . PHP_EOL;

$secret = '';
$result = \secp256k1_ecdh($context, $secret, $pub1, $priv2);
echo $result . PHP_EOL;
echo unpack("H*", $secret)[1].PHP_EOL;

?>
--EXPECT--
1
1
238c14f420887f8e9bfa78bc9bdded1975f0bb6384e33b4ebbf7a8c776844aec
