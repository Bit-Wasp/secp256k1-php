--TEST--
secp256k1_keypair_sec works
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

$sec = null;
$result = secp256k1_keypair_sec($ctx, $sec, $keypair);
echo $result . PHP_EOL;

echo unpack("H*", $sec)[1] . PHP_EOL;

?>
--EXPECT--
1
1
0000000000000000000000000000000000000000000000000000000000000003