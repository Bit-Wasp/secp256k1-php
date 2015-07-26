<?php

namespace BitWasp\Secp256k1Tests;

use Symfony\Component\Yaml\Yaml;

class Secp256k1PubkeyVerifyTest extends TestCase
{

    public function getVectors()
    {
        $parser = new Yaml();
        $data = $parser->parse(__DIR__ . '/data/pubkey_create.yml');

        $context = TestCase::getContext();
        $fixtures = array();
        foreach ($data['vectors'] as $vector) {
            $fixtures[] = array($context, $vector['pubkey']);
        }
        return $fixtures;
    }

    /**
     * @dataProvider getVectors
     */
    public function testVerifiesPublicKey($context, $pubkey)
    {
        $this->genericTest($context, $pubkey, 1);
    }

    /**
     * @param $pubkey
     * @param $eVerify
     */
    private function genericTest($context, $pubkey, $eVerify)
    {
        $pubkey = $this->toBinary32($pubkey);
        $this->assertEquals($eVerify, secp256k1_ec_pubkey_verify($context, $pubkey));
    }
}
