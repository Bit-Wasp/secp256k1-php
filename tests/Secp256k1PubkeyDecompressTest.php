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
        $decompressed = '';
        $result = secp256k1_ec_pubkey_decompress($publickey, $decompressed);
        $this->assertEquals(1, $result, 'check for success');
        $this->assertEquals($expectedUncompressed, bin2hex($decompressed));
    }

}
