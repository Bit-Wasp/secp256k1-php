--TEST--
secp256k1_keypair_xonly_pub errors if keypair is wrong resource type
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!function_exists("secp256k1_keypair_create")) print "skip no extrakeys support";
?>
--FILE--
<?php
set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

$xonly = null;
$parity = null;
$result = secp256k1_keypair_xonly_pub($ctx, $xonly, $parity, tmpfile());
echo $result . PHP_EOL;

?>
--EXPECT--
secp256k1_keypair_xonly_pub(): supplied resource is not a valid secp256k1_keypair resource
0
