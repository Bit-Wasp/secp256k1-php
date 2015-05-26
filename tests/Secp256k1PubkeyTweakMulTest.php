<?php

namespace BitWasp\Secp256k1Tests;

use Symfony\Component\Yaml\Yaml;

class Secp256k1PubkeyTweakMulTest extends TestCase
{

    /**
     * @return array
     */
    public function getVectors()
    {
        $limit = 0;
        $parser = new Yaml();
        $data = $parser->parse(__DIR__ . '/data/secp256k1_pubkey_tweak_mul.yml');

        $fixtures = array();
        foreach ($data['vectors'] as $c => $vector) {
            if ($limit && $c >= $limit) {
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
    public function testMultipliesByPubkey($publicKey, $tweak, $expectedPublicKey)
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
     * @param $eMul
     */
    private function genericTest($publicKey, $tweak, $expectedPublicKey, $eMul)
    {
        $publicKey = $this->toBinary32($publicKey);
        $tweak = $this->toBinary32($tweak);
        $result = secp256k1_ec_pubkey_tweak_mul($publicKey, $tweak);
        $this->assertEquals($eMul, $result);
        $this->assertEquals($expectedPublicKey, bin2hex($publicKey));
    }

    public function getErroneousTypeVectors()
    {
        $tweak = $this->pack('0af79b2b747548d59a4a765fb73a72bc4208d00b43d0606c13d332d5c284b0ef');
        $publicKey = $this->pack('041a2756dd506e45a1142c7f7f03ae9d3d9954f8543f4c3ca56f025df66f1afcba6086cec8d4135cbb5f5f1d731f25ba0884fc06945c9bbf69b9b543ca91866e79');

        $array = array();
        $class = new self;
        $resource = openssl_pkey_new();

        return [
            // Only test second parameter, first is zval so tested elsewhere
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
        $r = \secp256k1_ec_pubkey_tweak_add($pubkey, $tweak);
    }/**/

    /**
     * @expectedException \Exception
     */
    public function testEnforceZvalString()
    {
        $tweak = $this->pack('0af79b2b747548d59a4a765fb73a72bc4208d00b43d0606c13d332d5c284b0ef');
        $publicKey = array();
        \secp256k1_ec_pubkey_tweak_mul($publicKey, $tweak);
    }
}
