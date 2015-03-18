<?php

namespace Afk11\Secp256k1Tests;

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
    public function testSecp256k1_ec_pubkey_verify($pubkey)
    {#
        $pubkey = $this->toBinary32($pubkey);

        $this->assertEquals(1, secp256k1_ec_pubkey_verify($pubkey));
    }
}
