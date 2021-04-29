--TEST--
secp256k1_keypair_pub works
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!constant_exists("SECP256K1_XONLY_PUBKEY_RES_NAME")) print "skip no extrakeys support";
?>
--FILE--
<?php
$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

$seckey = pack("H*", "0000000000000000000000000000000000000000000000000000000000000003");
$keypair = null;
$result = secp256k1_keypair_create($ctx, $keypair, $seckey);
echo $result . PHP_EOL;

$pub = null;
$result = secp256k1_keypair_pub($ctx, $pub, $keypair);
echo $result . PHP_EOL;

$xonlyPub32 = '';
$result = secp256k1_ec_pubkey_serialize($ctx, $xonlyPub32, $pub, SECP256K1_EC_COMPRESSED);
echo $result . PHP_EOL;

echo unpack("H*", $xonlyPub32)[1] . PHP_EOL;

?>
--EXPECT--
1
1
1
02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9