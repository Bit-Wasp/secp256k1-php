<?php

namespace Afk11\Secp256k1Tests;

use Symfony\Component\Yaml\Yaml;

class Secp256k1PubkeyCreateTest extends TestCase
{

    public function getVectors()
    {
        $parser = new Yaml();
        $data = $parser->parse(__DIR__ . '/data/pubkey_create.yml');

        $fixtures = [];
        foreach ($data['vectors'] as $vector) {
            $fixtures[] = [$vector['seckey'], $vector['compressed'], $vector['pubkey']];
        }
        return $fixtures;
    }

    /**
     * @dataProvider getVectors
     */
    public function testCreatesPubkey($hexPrivKey, $compressed, $expectedPubKey)
    {
        $pubkey = '';
        $pubkeylen = 0;
        $sec = $this->toBinary32($hexPrivKey);

        $this->assertEquals(1, secp256k1_ec_pubkey_create($pubkey, $pubkeylen, $sec, $compressed));
        $this->assertEquals(bin2hex($pubkey), $expectedPubKey);
        $this->assertEquals(($compressed ? 33 : 65), $pubkeylen);
        unset($pubkey);
        unset($pubkeylen);

    }
}
