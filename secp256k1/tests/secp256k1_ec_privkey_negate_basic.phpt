--TEST--
secp256k1_ec_privkey_negate works
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php
$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

$privKey = pack("H*", "0000000000000000000000000000000000000000000000000000000000000001");
$result = secp256k1_ec_privkey_negate($ctx, $privKey);
echo $result . PHP_EOL;
echo unpack("H*", $privKey)[1] . PHP_EOL;

$result = secp256k1_ec_privkey_negate($ctx, $privKey);
echo $result . PHP_EOL;
echo unpack("H*", $privKey)[1] . PHP_EOL;

?>
--EXPECT--
1
fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140
1
0000000000000000000000000000000000000000000000000000000000000001