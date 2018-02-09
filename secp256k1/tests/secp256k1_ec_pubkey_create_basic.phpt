--TEST--
secp256k1_ec_pubkey_create works
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php
$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
$seckey = hex2bin('7ccca75d019dbae79ac4266501578684ee64eeb3c9212105f7a3bdc0ddb0f27e');
$pubKey = null;
$result = secp256k1_ec_pubkey_create($ctx, $pubKey, $seckey);
echo $result . PHP_EOL;

$pubKeyCompressed1 = '';
$result = secp256k1_ec_pubkey_serialize($ctx, $pubKeyOut, $pubKey, 1);
echo $result . PHP_EOL;
echo unpack("H*", $pubKeyOut)[1] . PHP_EOL;

$pubKeyUncompressed1 = '';
$result = secp256k1_ec_pubkey_serialize($ctx, $pubKeyOut, $pubKey, 0);
echo $result . PHP_EOL;
echo unpack("H*", $pubKeyOut)[1] . PHP_EOL;

?>
--EXPECT--
1
1
03e9a06e539d6bf5cf1ca5c41b59121fa3df07a338322405a312c67b6349a707e9
1
04e9a06e539d6bf5cf1ca5c41b59121fa3df07a338322405a312c67b6349a707e94c181c5fe89306493dd5677143a329065606740ee58b873e01642228a09ecf9d
