--TEST--
secp256k1_ec_privkey_tweak_mul case where referenced zvals are being modified. Only the provided copy should be modified.
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$mainKey = str_repeat("\x00", 31) . "\x08";
$secKey8 = str_repeat("\x00", 31) . "\x02";

class Something {
    private $key;
    public function __construct($key) {
        $this->key = $key;
    }
    public function getKey() {
        return $this->key;
    }
}

echo unpack("H*", $mainKey)[1] . PHP_EOL;
$something = new Something($mainKey);
$copyKey = $something->getKey();

$result = secp256k1_ec_privkey_tweak_mul($context, $copyKey, $secKey8);
echo $result . PHP_EOL;
echo unpack("H*", $copyKey)[1] . PHP_EOL;
echo unpack("H*", $mainKey)[1] . PHP_EOL;

?>
--EXPECT--
0000000000000000000000000000000000000000000000000000000000000008
1
0000000000000000000000000000000000000000000000000000000000000010
0000000000000000000000000000000000000000000000000000000000000008