<?php

namespace BitWasp\Secp256k1Tests;

use Symfony\Component\Yaml\Yaml;

class Secp256k1PubkeyTweakAddTest extends TestCase
{

    /**
     * @return array
     */
    public function getVectors()
    {
        $stop = 0;
        $parser = new Yaml();
        $data = $parser->parse(__DIR__ . '/data/secp256k1_pubkey_tweak_add.yml');

        $context = TestCase::getContext();
        $fixtures = array();
        foreach ($data['vectors'] as $c => $vector) {
            if ($stop && $c >= 2)
                break;
            $fixtures[] = array(
                $context,
                $vector['publicKey'],
                $vector['tweak'],
                $vector['tweaked']
            );
        }
        return $fixtures;
    }

    /**
     * @dataProvider getVectors
     */
    public function testAddsToPubkey($context, $publicKey, $tweak, $expectedPublicKey)
    {
        $this->genericTest(
            $context,
            $publicKey,
            $tweak,
            $expectedPublicKey,
            1
        );
    }

    /**
     * @param $publicKey
     * @param $tweak
     * @param $expectedPublicKey
     * @param $eAdd
     */
    private function genericTest($context, $publicKey, $tweak, $expectedPublicKey, $eAdd)
    {
        $publicKey = $this->toBinary32($publicKey);
        $tweak = $this->toBinary32($tweak);
        $result = secp256k1_ec_pubkey_tweak_add($context, $publicKey, $tweak);
        $this->assertEquals($eAdd, $result);
        $this->assertEquals(bin2hex($publicKey), $expectedPublicKey);
    }
}
