<?php

namespace BitWasp\Secp256k1Tests;


class Secp256k1EcdsaRecoverCompactTest extends TestCase
{
    public function testVerifyCompact()
    {
        $privateKey = pack("H*", 'fbb80e8a0f8af4fb52667e51963ac9860c192981f329debcc5d123a492a726af');
        $publicKey = '';
        $this->assertEquals(1, secp256k1_ec_pubkey_create($privateKey, 0, $publicKey));

        $msg = pack("H*", '03acc83ba10066e791d51e8a8eb90ec325feea7251cb8f979996848fff551d13');
        $sig = pack("H*", 'fe5fe404f3d8c21e1204a08c38ff3912d43c5a22541d2f1cdc4977cbcad240015a3b6e9040f62cacf016df4fef9412091592e4908e5e3a7bd2a42a4d1be01951');
        $recid = 1;

        $compressed = 0;
        $recPubKey = '';
        $this->assertEquals(1, secp256k1_ecdsa_recover_compact($msg, $sig, $recid, $compressed, $recPubKey));
        $this->assertEquals($publicKey, $recPubKey);
    }

    public function getErroneousTypeVectors()
    {
        $msg32 = pack("H*", '03acc83ba10066e791d51e8a8eb90ec325feea7251cb8f979996848fff551d13');
        $sig = pack("H*", 'fe5fe404f3d8c21e1204a08c38ff3912d43c5a22541d2f1cdc4977cbcad240015a3b6e9040f62cacf016df4fef9412091592e4908e5e3a7bd2a42a4d1be01951');
        $recid = 1;
        $compressed = 0;

        $array = array();
        $class = new Secp256k1EcdsaRecoverCompactTest;
        $resource = openssl_pkey_new();

        return [
            [$array, $sig, $recid, $compressed],
            [$msg32, $array, $recid, $compressed],
            [$msg32, $sig, $array, $compressed],
            [$msg32, $sig, $recid, $array],

            [$resource, $sig, $recid, $array],
            [$msg32, $resource, $recid, $compressed],
            [$msg32, $sig, $resource, $compressed],
            [$msg32, $sig, $recid, $resource],

            [$class, $sig, $recid, $compressed],
            [$msg32, $class, $recid, $compressed],
            [$msg32, $sig, $class, $compressed],
            [$msg32, $sig, $recid, $class]
        ];
    }

    /**
     * @dataProvider getErroneousTypeVectors
     * @expectedException PHPUnit_Framework_Error_Warning
     */
    public function testErroneousTypes($msg32, $sig, $recid, $compressed)
    {
        $publicKey = '';
        \secp256k1_ecdsa_recover_compact($msg32, $sig, $recid, $compressed, $publicKey);
    }


}