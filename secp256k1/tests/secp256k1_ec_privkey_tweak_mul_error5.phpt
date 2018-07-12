--TEST--
secp256k1_ec_privkey_tweak_mul type error using strict_types and wrong type
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (PHP_VERSION_ID < 70200) print "skip, <php7.2";
?>
--FILE--
<?php
declare(strict_types=1);
$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$secKey = -1;
$tweak = str_repeat("a", 32);

try {
    \secp256k1_ec_privkey_tweak_mul($context, $secKey, $tweak);
} catch (\Error $e) {
    echo get_class($e) . PHP_EOL;
    $error = $e->getMessage();
    // php7.3 changes integer -> int. convert to int always, test against that
    if ($error === "Argument 2 passed to secp256k1_ec_privkey_tweak_mul() must be of the type string, integer given") {
        $error = "Argument 2 passed to secp256k1_ec_privkey_tweak_mul() must be of the type string, int given";
    }
    echo $error . PHP_EOL;
}

?>
--EXPECT--
TypeError
Argument 2 passed to secp256k1_ec_privkey_tweak_mul() must be of the type string, int given