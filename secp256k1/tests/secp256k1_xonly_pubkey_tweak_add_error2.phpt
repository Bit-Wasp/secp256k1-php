--TEST--
secp256k1_xonly_pubkey_tweak_add errors when context is wrong type
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
$keypair1 = null;
$result = secp256k1_keypair_create($ctx, $keypair1, $seckey);
echo $result . PHP_EOL;

$tweak32 = pack("H*", "0000000000000000000000000000000000000000000000000000000000000001");
$result = secp256k1_keypair_xonly_tweak_add(tmpfile(), $keypair1, $tweak32);
echo $result . PHP_EOL;

?>
--EXPECT--
1
secp256k1_keypair_xonly_tweak_add(): supplied resource is not a valid secp256k1_context resource
0