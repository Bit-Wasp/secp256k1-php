<?php

namespace Afk11\Secp256k1Tests;

class Secp256k1PubkeyDecompressTest extends TestCase
{
    private $fixtures = [
        [
            "03ca473d3c0cccbf600d1c89fa33b7f6b1f2b4c66f1f11986701f4b6cc4f54c360",
            "04ca473d3c0cccbf600d1c89fa33b7f6b1f2b4c66f1f11986701f4b6cc4f54c3603e812db2fe13480d3967944586101173f530e8ab6419596ac5e78c832a3a23eb"
        ],
        [
            "031cde64fdd802995bca9f4403424baaa9634fba991e523bc30fbe791f07ad7fb6",
            "041cde64fdd802995bca9f4403424baaa9634fba991e523bc30fbe791f07ad7fb633f8f5972d49772bbe80f26fac99e7c12f6cea8f110017568e29db8c0c6e61af"
        ],
        [
            "02217cb9f60120f15e6137b549cae132e40de72b53ecb2ecac86eae4ae4bdcfbbd",
            "04217cb9f60120f15e6137b549cae132e40de72b53ecb2ecac86eae4ae4bdcfbbdca76c7ae901bc667d964dfccc40c7b7135b104e5d7d85b8c17f3f4de48135958"
        ],
        [
            "0316b1356d96deee8b2721650cd3252dee3cc762335d639240db5e20502f465d76",
            "0416b1356d96deee8b2721650cd3252dee3cc762335d639240db5e20502f465d7660a67693e0a0c68fb7bb585308e76dcb70c6ce739b1b5df5861492e621f5536f"
        ],
        [
            "026bf17c5d160f0d71e0f4cad6b0e519a0c29c1857ea1a4adedaa2e58bf9caf4b5",
            "046bf17c5d160f0d71e0f4cad6b0e519a0c29c1857ea1a4adedaa2e58bf9caf4b5641d10a1c7e0369b449e2840d937fe28227dba5a2bcbd164c1a87c84e047c948"
        ],
        [
            "031ea828f50080022338541438770f307edf9ee8fbe665b6411db8a44b393e9c35",
            "041ea828f50080022338541438770f307edf9ee8fbe665b6411db8a44b393e9c358df5c5940095233acf0b7451e3daed3e34bfc1ec16fd541ccf67af6fe84c6abf"
        ],
        [
            "031e738ae43e720c0a6daacb9831f9571c554b1563f3d7d7aefeb04b1b605df1df",
            "041e738ae43e720c0a6daacb9831f9571c554b1563f3d7d7aefeb04b1b605df1dfb8754f06152f01511eeafa723ef1b44070c06a2b7fd1a83a3c7aecee8782dd1f"
        ],
        [
            "03c5ea5b63bca0885e78926989e450391d9110a30c0c37658718ee2fdee5eeb5d4",
            "04c5ea5b63bca0885e78926989e450391d9110a30c0c37658718ee2fdee5eeb5d40f1443cb990e4a19229265e89df86abb670dd940d5a5e39a41037f7106318c31"
        ],
        [
            "02954767043dd552934db618936108cf1a62f702e6597b249878e9c33310a4c23c",
            "04954767043dd552934db618936108cf1a62f702e6597b249878e9c33310a4c23ce03ec6ca2f30a2781fba283487bda61ffa7180277bae053fd1ebef027a7c7f40"
        ],
        [
            "03fe11f63a7b1e129a4e26137fb9a7c615718d2fac42e6edde0239b03604a25de8",
            "04fe11f63a7b1e129a4e26137fb9a7c615718d2fac42e6edde0239b03604a25de84e4bea573e41ed8bb4b218e929062d23d945c500cebd2aa7b1f515742b4fe5dd"
        ],
        [
            "021ad18624812e8ef10ecd52f8c3c2c7c17f9d17d17e3a7de41da0076298509cea",
            "041ad18624812e8ef10ecd52f8c3c2c7c17f9d17d17e3a7de41da0076298509ceaeb80f99bb189f8a545a7546313a1bc7906566a94e9c42e7dd3ac3906d349c2a0"
        ],
        [
            "030093c6ece7bb692f370971a583bf7cf3ee7cf874c7e00ab18ae086dc70387230",
            "040093c6ece7bb692f370971a583bf7cf3ee7cf874c7e00ab18ae086dc70387230620223e036c603f7f5884c7d1ad19e01998db9084df570a3c9af045ad27e48fd"
        ]
    ];


    public function getVectors()
    {
        return $this->fixtures;
    }

    /**
     * @dataProvider getVectors
     */
    public function testDecompressesPubkey($publickey, $expectedUncompressed)
    {
        $publickey = $this->toBinary32($publickey);
        $pubkeylen = strlen($publickey);

        $result = secp256k1_ec_pubkey_decompress($publickey, $pubkeylen);
        $this->assertEquals(1, $result);
        $this->assertEquals(bin2hex($publickey), $expectedUncompressed);
        $this->assertEquals(65, $pubkeylen);
    }
}