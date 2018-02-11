--TEST--
ecdsa_signature_parse_der_lax returns false if parameter parsing fails
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$result = ecdsa_signature_parse_der_lax();
echo gettype($result) . PHP_EOL;
echo ($result ? "true" : "false") . PHP_EOL;

?>
--EXPECT--
ecdsa_signature_parse_der_lax() expects exactly 3 parameters, 0 given
boolean
false