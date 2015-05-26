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

        $fixtures = array();
        foreach ($data['vectors'] as $c => $vector) {
            if ($stop && $c >= 2) {
                break;
            }
            $fixtures[] = array(
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
    public function testAddsToPubkey($publicKey, $tweak, $expectedPublicKey)
    {
        $this->genericTest(
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
    private function genericTest($publicKey, $tweak, $expectedPublicKey, $eAdd)
    {
        $publicKey = $this->toBinary32($publicKey);
        $tweak = $this->toBinary32($tweak);
        $ctx = $this->context();
        $result = secp256k1_ec_pubkey_tweak_add($ctx, $publicKey, $tweak);
        $this->assertEquals($eAdd, $result);
        $this->assertEquals(bin2hex($publicKey), $expectedPublicKey);
    }

    public function getErroneousTypeVectors()
    {
        $tweak = $this->pack('0af79b2b747548d59a4a765fb73a72bc4208d00b43d0606c13d332d5c284b0ef');
        $publicKey = $this->pack('041a2756dd506e45a1142c7f7f03ae9d3d9954f8543f4c3ca56f025df66f1afcba6086cec8d4135cbb5f5f1d731f25ba0884fc06945c9bbf69b9b543ca91866e79');

        $array = array();
        $class = new self;
        $resource = openssl_pkey_new();

        return [
            // Only test second value, first is zVal to tested elsewhere
            [$publicKey, $array],
            [$publicKey, $resource],
            [$publicKey, $class]
        ];
    }

    /**
     * @dataProvider getErroneousTypeVectors
     * @expectedException PHPUnit_Framework_Error_Warning
     */
    public function testErroneousTypes($pubkey, $tweak)
    {
        $ctx = $this->context();
        $r = \secp256k1_ec_pubkey_tweak_add($ctx, $pubkey, $tweak);
    }/**/

    /**
     * @expectedException \Exception
     */
    public function testEnforceZvalString()
    {
        $tweak = $this->pack('0af79b2b747548d59a4a765fb73a72bc4208d00b43d0606c13d332d5c284b0ef');
        $ctx = $this->context();
        $pubkey = array();
        \secp256k1_ec_pubkey_tweak_add($ctx, $pubkey, $tweak);
    }
}
