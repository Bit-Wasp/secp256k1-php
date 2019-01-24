--TEST--
Case where referenced zvals are being modified. Only the provided copy should be modified.
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
$mainKey = "0123abcd0123abcd0123abcd0123abcd";
$secKeyOne = str_repeat("\x00", 31) . "\x01";

class Something {
    private $key;
    public function __construct($key) {
        $this->key = $key;
    }
    public function getKey() {
        return $this->key;
    }
}

echo $mainKey . PHP_EOL;
$something = new Something($mainKey);
$copyKey = $something->getKey();

$result = secp256k1_ec_privkey_tweak_add($context, $copyKey, $secKeyOne);
echo $result . PHP_EOL;
echo $copyKey . PHP_EOL;
echo $mainKey . PHP_EOL;

?>
--EXPECT--
0123abcd0123abcd0123abcd0123abcd
1
0123abcd0123abcd0123abcd0123abce
0123abcd0123abcd0123abcd0123abcd