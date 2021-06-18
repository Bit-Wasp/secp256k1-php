--TEST--
secp256k1_xonly_pubkey_tweak_add_check errors if parameter parsing fails
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!constant_exists("SECP256K1_XONLY_PUBKEY_RES_NAME")) print "skip no extrakeys support";
?>
--FILE--
<?php
set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$result = secp256k1_xonly_pubkey_tweak_add_check();
echo $result . PHP_EOL;

?>
--EXPECT--
secp256k1_xonly_pubkey_tweak_add_check() expects exactly 5 parameters, 0 given
0