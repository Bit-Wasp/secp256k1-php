--TEST--
secp256k1_keypair_pub returns 0 if context is wrong resource type
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!constant_exists("SECP256K1_XONLY_PUBKEY_RES_NAME")) print "skip no extrakeys support";
?>
--FILE--
<?php
set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

$seckey = pack("H*", "0000000000000000000000000000000000000000000000000000000000000003");
$keypair = null;
$result = secp256k1_keypair_create($ctx, $keypair, $seckey);
echo $result . PHP_EOL;

$pub = null;
$result = secp256k1_keypair_pub(tmpfile(), $pub, $keypair);
echo $result . PHP_EOL;

?>
--EXPECT--
1
secp256k1_keypair_pub(): supplied resource is not a valid secp256k1_context resource
0