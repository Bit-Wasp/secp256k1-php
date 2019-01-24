--TEST--
secp256k1_ecdsa_sign fails when seckey is invalid
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

// fixture came from our signatures.yml
$sigIn = hex2bin("30440220132382ca59240c2e14ee7ff61d90fc63276325f4cbe8169fc53ade4a407c2fc802204d86fbe3bde6975dd5a91fdc95ad6544dcdf0dab206f02224ce7e2b151bd82ab");
$msg32 = \pack("H*", "9e5755ec2f328cc8635a55415d0e9a09c2b6f2c9b0343c945fbbfe08247a4cbe");
$priv = \pack("H*", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

$ctx = \secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$sig = null;
$result = \secp256k1_ecdsa_sign($ctx, $sig, $msg32, $priv);
echo $result . PHP_EOL;

?>
--EXPECT--
0