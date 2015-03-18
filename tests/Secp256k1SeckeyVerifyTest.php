<?php

namespace Afk11\Secp256k1Tests;

use Symfony\Component\Yaml\Yaml;

class Secp256k1SeckeyVerifyTest extends TestCase
{
    public function getVectors()
    {
        $parser = new Yaml();
        $data = $parser->parse(__DIR__ . '/data/pubkey_create.yml');

        $fixtures = [];
        foreach ($data['vectors'] as $vector) {
            $fixtures[] = [$vector['seckey']];
        }
        return $fixtures;
    }

    /**
     * @dataProvider getVectors
     */
    public function testSecp256k1_ec_seckey_verify($hexPrivKey)
    {
        $sec = $this->toBinary32($hexPrivKey);
        $this->assertEquals(1, \secp256k1_ec_seckey_verify($sec));
    }

}
