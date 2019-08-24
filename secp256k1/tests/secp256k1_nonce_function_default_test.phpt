--TEST--
secp256k1_nonce_function_default returns a result
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$output = '';
$msg32 = str_repeat('A', 32);
$key32 = str_repeat('Z', 32);
$algo = NULL;

$result = secp256k1_nonce_function_default($output, $msg32, $key32, $_algo=null, $_data=null, $_attempt=0);
echo $result . PHP_EOL;
echo unpack("H*", $output)[1] . PHP_EOL;

$result = secp256k1_nonce_function_default($output, $msg32, $key32, $_algo=null, $_data=null, $_attempt=1);
echo $result . PHP_EOL;
echo unpack("H*", $output)[1] . PHP_EOL;

$result = secp256k1_nonce_function_default($output, $msg32, $key32, $_algo=str_repeat("W", 16), $_data=null, $_attempt=0);
echo $result . PHP_EOL;
echo unpack("H*", $output)[1] . PHP_EOL;

$result = secp256k1_nonce_function_default($output, $msg32, $key32, $_algo=null, $_data=str_repeat("F", 32), $_attempt=0);
echo $result . PHP_EOL;
echo unpack("H*", $output)[1] . PHP_EOL;

?>
--EXPECT--
1
16e98a1b0eac623f8f2b8106288510f47aa499f4061788ee67808096b77ad7be
1
7b3c36437a157ef1ebb16f33259c8920b4b23c448115f013211669d8b13c6e64
1
e85cb42a7c3e55985672168de30e534d1ce4e9634378e36299722c78ab893f73
1
e40f838b9929bd8f4b99102221aa93f56b02ddee9e54709c7dab13e8f3d7ee8c