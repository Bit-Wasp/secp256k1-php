--TEST--
secp256k1_xonly_pubkey_tweak_add errors when xonly pubkey is wrong resource type
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

$keypair2 = null;
$result = secp256k1_keypair_create($ctx, $keypair2, $seckey);
echo $result . PHP_EOL;

$pub2 = null;
$parity = null;
$result = secp256k1_keypair_xonly_pub($ctx, $pub2, $parity, $keypair2);
echo $result . PHP_EOL;

$tweakAddResult = null;
$result = secp256k1_xonly_pubkey_tweak_add($ctx, $tweakAddResult, tmpfile(), $tweak32);
echo $result . PHP_EOL;

?>
--EXPECT--
1
1
secp256k1_xonly_pubkey_tweak_add(): supplied resource is not a valid secp256k1_xonly_pubkey resource
0
