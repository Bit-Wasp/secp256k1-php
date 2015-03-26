<?php

namespace BitWasp\Secp256k1Tests;

use Symfony\Component\Yaml\Yaml;

class Secp256k1PubkeyCreateTest extends TestCase
{
    /**
     * @return array
     */
    public function getVectors()
    {
        $parser = new Yaml();
        $data = $parser->parse(__DIR__ . '/data/pubkey_create.yml');

        $fixtures = array();
        foreach ($data['vectors'] as $vector) {
            $fixtures[] = array(
                $vector['seckey'],
                $vector['compressed'],
                $vector['pubkey']
            );
        }
        return $fixtures;
    }

    /**
     * @dataProvider getVectors
     */
    public function testCreatesPubkey($hexPrivKey, $expectedCompressed, $expectedPubKey)
    {
        $this->genericTest($hexPrivKey, 1, $expectedCompressed, 1);
        $this->genericTest($hexPrivKey, 0, $expectedPubKey, 1);
    }

    /**
     * @param $hexPrivkey
     * @param $fcompressed
     * @param $expectedKey
     * @param $eResult
     */
    public function genericTest($hexPrivkey, $fcompressed, $expectedKey, $eResult)
    {
        $secretKey = $this->toBinary32($hexPrivkey);

        $pubkey = '';
        $this->assertEquals($eResult, secp256k1_ec_pubkey_create($secretKey, $fcompressed, $pubkey));
        $this->assertEquals(bin2hex($pubkey), $expectedKey);
        $this->assertEquals(($fcompressed ? 33 : 65), strlen($pubkey));
    }
}
