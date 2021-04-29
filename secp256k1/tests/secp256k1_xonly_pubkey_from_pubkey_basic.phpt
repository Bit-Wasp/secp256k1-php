--TEST--
secp256k1_xonly_pubkey_from_pubkey works
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!constant_exists("SECP256K1_XONLY_PUBKEY_RES_NAME")) print "skip no extrakeys support";
?>
--FILE--
<?php
$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$seckey = pack("H*", "0000000000000000000000000000000000000000000000000000000000000003");
$pubkey = null;
$result = secp256k1_ec_pubkey_create($ctx, $pubkey, $seckey);
echo $result . PHP_EOL;

$xonlyPubKey = null;
$parity = null;
$result = secp256k1_xonly_pubkey_from_pubkey($ctx, $xonlyPubKey, $parity, $pubkey);
echo $result . PHP_EOL;

echo "Parity $parity\n";

$pub1raw = '';
$result = secp256k1_xonly_pubkey_serialize($ctx, $pub1raw, $xonlyPubKey);
echo $result . PHP_EOL;

echo unpack("H*", $pub1raw)[1] . PHP_EOL;

?>
--EXPECT--
1
1
Parity 0
1
f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9