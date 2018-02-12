--TEST--
secp256k1_ecdsa_recover returns false if parameter parsing (signature) fails
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$context = \secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
$recid = 1;
$compressed = 0;
$sigIn = pack("H*", 'fe5fe404f3d8c21e1204a08c38ff3912d43c5a22541d2f1cdc4977cbcad240015a3b6e9040f62cacf016df4fef9412091592e4908e5e3a7bd2a42a4d1be01951');

$msg = pack("H*", '03acc83ba10066e791d51e8a8eb90ec325feea7251cb8f979996848fff551d13');
$privateKey = pack("H*", 'fbb80e8a0f8af4fb52667e51963ac9860c192981f329debcc5d123a492a726af');

$s = tmpfile();

$recPubKey = '';
$result = secp256k1_ecdsa_recover($context, $recPubKey, $s, $msg);
echo gettype($result) . PHP_EOL;
echo ($result ? "true" : "false") . PHP_EOL;

?>
--EXPECT--
secp256k1_ecdsa_recover(): supplied resource is not a valid secp256k1_ecdsa_recoverable_signature resource
boolean
false
