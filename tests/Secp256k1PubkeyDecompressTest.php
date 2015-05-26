<?php

namespace BitWasp\Secp256k1Tests;

use Symfony\Component\Yaml\Yaml;

class Secp256k1PubkeyDecompressTest extends TestCase
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
                $vector['compressed'],
                $vector['pubkey']
            );
        }
        return $fixtures;
    }

    /**
     * @dataProvider getVectors
     */
    public function testDecompressesPubkey($expectedCompressed, $expectedUncompressed)
    {
        $publickey = $this->toBinary32($expectedCompressed);

        $ctx = $this->context();
        $result = secp256k1_ec_pubkey_decompress($ctx, $publickey);
        $this->assertEquals(1, $result, 'check for success');
        $this->assertEquals($expectedUncompressed, bin2hex($publickey));
    }

    /**
     *
     */
    public function testByRef()
    {
        $o = $this->toBinary32("03ca473d3c0cccbf600d1c89fa33b7f6b1f2b4c66f1f11986701f4b6cc4f54c360");
        $a = $this->toBinary32("03ca473d3c0cccbf600d1c89fa33b7f6b1f2b4c66f1f11986701f4b6cc4f54c360");
        $b = $a;

        $ctx = $this->context();
        $r = secp256k1_ec_pubkey_decompress($ctx, $b);
        
        $this->assertEquals(1, $r);
        $this->assertTrue($b != $o, '$b is decompressed');
        $this->assertTrue($a == $o, '$a is not decompressed');
        
    }

     public function getErroneousTypeVectors()
     {
        $array = array();
        $class = new self;
        $resource = openssl_pkey_new();

        return [
            [$array],
            [$resource],
            [$class]
        ];
        }

    /**
     * @dataProvider getErroneousTypeVectors
     * @expectedException \Exception
     *
    public function testErroneousTypes($key)
    {
        $ctx = $this->context();
        $r = \secp256k1_ec_pubkey_decompress($ctx, $key);
    }/**/
}
