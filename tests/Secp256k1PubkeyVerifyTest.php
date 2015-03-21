<?php

namespace BitWasp\Secp256k1Tests;

use Symfony\Component\Yaml\Yaml;

class Secp256k1PubkeyVerifyTest extends TestCase
{

    public function getVectors()
    {
        $parser = new Yaml();
        $data = $parser->parse(__DIR__ . '/data/pubkey_create.yml');

        $fixtures = [];
        foreach ($data['vectors'] as $vector) {
            $fixtures[] = [$vector['pubkey']];
        }
        return $fixtures;
    }

    /**
     * @dataProvider getVectors
     */
    public function testVerifiesPublicKey($pubkey)
    {
        $this->genericTest($pubkey, 1);
    }

    /**
     * @param $pubkey
     * @param $eVerify
     */
    private function genericTest($pubkey, $eVerify)
    {
        $pubkey = $this->toBinary32($pubkey);
        $this->assertEquals($eVerify, secp256k1_ec_pubkey_verify($pubkey));
    }
}
