--TEST--
secp256k1_ec_pubkey_negate works
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php
$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$pubKeyIn = pack("H*", "02227cedfab55d1b7642d47a5ac92638ed8822a23c3ddadf88defea45a37f5935e");

$pubKeyOut = '';
$pubKey = null;
$result = \secp256k1_ec_pubkey_parse($ctx, $pubKey, $pubKeyIn);

$result = \secp256k1_ec_pubkey_serialize($ctx, $pubKeyOut, $pubKey, 1);
echo unpack("H*", $pubKeyOut)[1] . PHP_EOL;

$result = \secp256k1_ec_pubkey_negate($ctx, $pubKey);
echo $result . PHP_EOL;

$pubKeySer = null;
$result = \secp256k1_ec_pubkey_serialize($ctx, $pubKeySer, $pubKey, 1);
echo $result . PHP_EOL;
echo bin2hex($pubKeySer) . PHP_EOL;

$result = \secp256k1_ec_pubkey_negate($ctx, $pubKey);
echo $result . PHP_EOL;

$result = \secp256k1_ec_pubkey_serialize($ctx, $pubKeyOut, $pubKey, 1);
echo $result . PHP_EOL;
echo unpack("H*", $pubKeyOut)[1] . PHP_EOL;

?>
--EXPECT--
02227cedfab55d1b7642d47a5ac92638ed8822a23c3ddadf88defea45a37f5935e
1
1
03227cedfab55d1b7642d47a5ac92638ed8822a23c3ddadf88defea45a37f5935e
1
1
02227cedfab55d1b7642d47a5ac92638ed8822a23c3ddadf88defea45a37f5935e
