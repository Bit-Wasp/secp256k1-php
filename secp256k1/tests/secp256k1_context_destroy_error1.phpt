--TEST--
secp256k1_context_destroy returns false if provided the wrong resource type
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$handle = tmpfile();
$result = secp256k1_context_destroy($handle);
echo gettype($result) . PHP_EOL;
echo ($result ? "true" : "false") . PHP_EOL;

?>
--EXPECT--
secp256k1_context_destroy(): supplied resource is not a valid secp256k1_context resource
boolean
false