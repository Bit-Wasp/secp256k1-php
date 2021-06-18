--TEST--
secp256k1_xonly_pubkey_from_pubkey errors when context is wrong type
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
$pubkey = null;
$result = secp256k1_ec_pubkey_create($ctx, $pubkey, $seckey);
echo $result . PHP_EOL;

$xonlyPubKey = null;
$parity = null;
$result = secp256k1_xonly_pubkey_from_pubkey(tmpfile(), $xonlyPubKey, $parity, $pubkey);
echo $result . PHP_EOL;

?>
--EXPECT--
1
secp256k1_xonly_pubkey_from_pubkey(): supplied resource is not a valid secp256k1_context resource
0
