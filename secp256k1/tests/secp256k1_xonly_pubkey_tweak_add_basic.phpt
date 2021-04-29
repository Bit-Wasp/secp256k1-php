--TEST--
secp256k1_xonly_pubkey_tweak_add works
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!constant_exists("SECP256K1_XONLY_PUBKEY_RES_NAME")) print "skip no extrakeys support";
?>
--FILE--
<?php
$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$seckey = pack("H*", "0000000000000000000000000000000000000000000000000000000000000003");
$keypair1 = null;
$result = secp256k1_keypair_create($ctx, $keypair1, $seckey);
echo $result . PHP_EOL;

$tweak32 = pack("H*", "0000000000000000000000000000000000000000000000000000000000000001");
$result = secp256k1_keypair_xonly_tweak_add($ctx, $keypair1, $tweak32);
echo $result . PHP_EOL;

$pub1 = null;
$result = secp256k1_keypair_pub($ctx, $pub1, $keypair1);
echo $result . PHP_EOL;

$pub1raw = '';
$result = secp256k1_ec_pubkey_serialize($ctx, $pub1raw, $pub1, SECP256K1_EC_COMPRESSED);
echo $result . PHP_EOL;

echo unpack("H*", $pub1raw)[1] . PHP_EOL;

$keypair2 = null;
$result = secp256k1_keypair_create($ctx, $keypair2, $seckey);

$pub2 = null;
$parity = null;
$result = secp256k1_keypair_xonly_pub($ctx, $pub2, $parity, $keypair2);
echo $result . PHP_EOL;

$tweakAddResult = null;
$result = secp256k1_xonly_pubkey_tweak_add($ctx, $tweakAddResult, $pub2, $tweak32);
echo $result . PHP_EOL;

$pub2raw = '';
$result = secp256k1_xonly_pubkey_serialize($ctx, $pub2raw, $tweakAddResult);
echo $result . PHP_EOL;

echo unpack("H*", $pub2raw)[1] . PHP_EOL;
?>
--EXPECT--
1
1
1
1
02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13
1
1
1
e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13