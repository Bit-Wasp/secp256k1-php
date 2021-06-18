--TEST--
secp256k1_xonly_pubkey_tweak_add_check errors if internal pubkey is wrong resource type
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!constant_exists("SECP256K1_XONLY_PUBKEY_RES_NAME")) print "skip no extrakeys support";
?>
--FILE--
<?php
set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$seckey = pack("H*", "0000000000000000000000000000000000000000000000000000000000000003");
$tweak32 = pack("H*", "0000000000000000000000000000000000000000000000000000000000000001");

$keypair = null;
$result = secp256k1_keypair_create($ctx, $keypair, $seckey);
echo $result . PHP_EOL;

$internalPub = null;
$internalPubParity = null;
$result = secp256k1_keypair_xonly_pub($ctx, $internalPub, $internalPubParity, $keypair);
echo $result . PHP_EOL;

$result = secp256k1_keypair_xonly_tweak_add($ctx, $keypair, $tweak32);
echo $result . PHP_EOL;

$tweakedPub = null;
$tweakedPubParity = null;
$result = secp256k1_keypair_xonly_pub($ctx, $tweakedPub, $tweakedPubParity, $keypair);
echo $result . PHP_EOL;

$tweakedPubKey32 = '';
$result = secp256k1_xonly_pubkey_serialize($ctx, $tweakedPubKey32, $tweakedPub);
echo $result . PHP_EOL;

echo unpack("H*", $tweakedPubKey32)[1] . PHP_EOL;

$tweakedParity = null;
$result = secp256k1_xonly_pubkey_tweak_add_check($ctx, $tweakedPubKey32, $tweakedPubParity, tmpfile(), $tweak32);
echo $result.PHP_EOL;

?>
--EXPECT--
1
1
1
1
1
e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13
secp256k1_xonly_pubkey_tweak_add_check(): supplied resource is not a valid secp256k1_xonly_pubkey resource
0