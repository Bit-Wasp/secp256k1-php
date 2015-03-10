<?php

$publicKey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
$msg = "fb3a3384783921e1bc394229481209f29f70c588f1c8092cb7e43fdcadcfe241";
$sig = "3045022100987ceade6a304fc5823ab38f99fc3c5f772a2d3e89ea05931e2726105fc53b9e0220601fc3231f35962c714fcbce5c95b427496edc7ae8b3d12e93791d7629795b62";

$t = microtime(true);
secp256k1_init();

$tt = microtime(true) - $t;
var_dump("init took {$tt}s");

$t = microtime(true);
$cnt = (isset($argv[1]) ? $argv[1] : 1);
$ok = 0;
for ($i = 0; $i < $cnt; $i++) {
    $result = secp256k1_ecdsa_verify(pack("H*", $msg), pack("H*", $sig), pack("H*", $publicKey));

    if ($result === 1) {
        $ok += 1;
    } else {
        throw new \Exception("Failed! result={$i} (success count so far; {$ok})");
    }
}

$tt = microtime(true) - $t;
var_dump("{$cnt} verify loops took {$tt}s");

