<?php

namespace BitWasp\Secp256k1Tests;

use Symfony\Component\Yaml\Yaml;

class Secp256k1SeckeyVerifyTest extends TestCase
{
    public function getVectors()
    {
        $parser = new Yaml();
        $data = $parser->parse(__DIR__ . '/data/pubkey_create.yml');

        $fixtures = array();
        foreach ($data['vectors'] as $vector) {
            $fixtures[] = array($vector['seckey']);
        }
        return $fixtures;
    }

    /**
     * @dataProvider getVectors
     */
    public function testVerfiesSeckey($hexPrivKey)
    {
        $this->genericTest($hexPrivKey, 1);
    }

    /**
     * @param string $privkey
     * @param bool $eVerify
     */
    public function genericTest($privkey, $eVerify)
    {
        $sec = $this->toBinary32($privkey);
        $this->assertEquals($eVerify, \secp256k1_ec_seckey_verify($sec));
    }

}
