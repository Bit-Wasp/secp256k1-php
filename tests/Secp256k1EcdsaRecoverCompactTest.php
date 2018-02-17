<?php

namespace BitWasp\Secp256k1Tests;

class Secp256k1EcdsaRecoverCompactTest extends TestCase
{
   public function testVerifyCompact()
    {

        $context = \secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        $recid = 1;
        $compressed = 0;

        $sig = pack("H*", 'fe5fe404f3d8c21e1204a08c38ff3912d43c5a22541d2f1cdc4977cbcad240015a3b6e9040f62cacf016df4fef9412091592e4908e5e3a7bd2a42a4d1be01951');
        /** @var resource $s */
        $s = '';

        $this->assertEquals(1, secp256k1_ecdsa_recoverable_signature_parse_compact($context, $s, $sig, $recid));

        $privateKey = pack("H*", 'fbb80e8a0f8af4fb52667e51963ac9860c192981f329debcc5d123a492a726af');

        $publicKey = null;
        $this->assertEquals(1, secp256k1_ec_pubkey_create($context, $publicKey, $privateKey));

        $ePubKey = '';
        $this->assertEquals(1, secp256k1_ec_pubkey_serialize($context, $ePubKey, $publicKey, $compressed));

        $msg = pack("H*", '03acc83ba10066e791d51e8a8eb90ec325feea7251cb8f979996848fff551d13');

        $recPubKey = null;
        $this->assertEquals(1, secp256k1_ecdsa_recover($context, $recPubKey, $s, $msg));

        $serPubKey = '';
        $this->assertEquals(1, secp256k1_ec_pubkey_serialize($context, $serPubKey, $recPubKey, $compressed));
        $this->assertEquals($ePubKey, $serPubKey);
    }
}
