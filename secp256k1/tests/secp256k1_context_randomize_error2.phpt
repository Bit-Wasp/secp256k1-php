--TEST--
secp256k1_context_randomize returns false if missing flags argument
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$result = secp256k1_context_randomize();
echo $result . PHP_EOL;

?>
--EXPECT--
secp256k1_context_randomize() expects at least 1 parameter, 0 given
0
