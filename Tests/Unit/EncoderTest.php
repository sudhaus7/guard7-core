<?php

namespace SUDHAUS7\Guard7Core\Tests\Unit;

use PHPUnit\Framework\TestCase;
use stdClass;
use SUDHAUS7\Guard7Core\Openssl\Key;
use SUDHAUS7\Guard7Core\Tests\Mockups\ConfigAdapter;
use SUDHAUS7\Guard7Core\Tests\Mockups\InvalidConfigAdapter;
use SUDHAUS7\Guard7Core\Tools\Decoder;
use SUDHAUS7\Guard7Core\Tools\Encoder;
use function is_array;

/**
 * @covers \SUDHAUS7\Guard7Core\Tools\Encoder
 * @covers SUDHAUS7\Guard7Core\Openssl\Key
 * @covers SUDHAUS7\Guard7Core\Openssl\Service::encode
 * @covers SUDHAUS7\Guard7Core\Service\ChecksumService::calculate
 * @covers SUDHAUS7\Guard7Core\Openssl\Service::decode
 * @covers SUDHAUS7\Guard7Core\Tools\Decoder::decode
 */
class EncoderTest extends TestCase
{
    public function testCanBeInstantiated(): void
    {
        $encoder = new Encoder(new ConfigAdapter());
        $this->assertInstanceOf(Encoder::class, $encoder);
    }
    public function testSetContentOnInstantiate(): void
    {
        $encoder = new Encoder(new ConfigAdapter(), [], 'content to encode');
        $this->assertInstanceOf(Encoder::class, $encoder);
    }
    public function testSetArrayContent(): void
    {
        $encoder = new Encoder(new ConfigAdapter());
        $encoder->setContent(['content to encode']);
        $this->assertInstanceOf(Encoder::class, $encoder);
    }
    public function testSetObjectContent(): void
    {
        $encoder = new Encoder(new ConfigAdapter());
        $content = new stdClass();
        $content->xxx = 'content';
        $encoder->setContent($content);
        $this->assertInstanceOf(Encoder::class, $encoder);
    }

    /**
     * @covers \SUDHAUS7\Guard7Core\Openssl\Key
     * @covers \SUDHAUS7\Guard7Core\Service\ChecksumService
     */
    public function testAddPublicKey(): void
    {
        $key = Key::createNewKey()->unlock();

        $encoder = new Encoder(new ConfigAdapter());
        $encoder->addPubkey($key->getPublicKey());
        $keys = $encoder->getPubkeys();
        $encoder->setPubkeys($keys);
        $this->assertEquals($keys[0], $key->getPublicKey());
        $checksums = $encoder->getChecksums();
        $this->assertTrue(is_array($checksums) && !empty($checksums) && sizeof($checksums)===1);
    }
    /**
     * @covers \SUDHAUS7\Guard7Core\Openssl\Key
     */
    public function testSetMethod(): void
    {
        $config = new ConfigAdapter();
        $encoder = new Encoder($config, [], null, $config->getDefaultMethod());
        $this->assertEquals($encoder->getMethod(), $config->getDefaultMethod());
        $encoder->setMethod('aes128');
        $this->assertEquals($encoder->getMethod(), 'aes128');
    }
    
    
    /**
     * @throws \SUDHAUS7\Guard7Core\Exceptions\KeyNotReadableException
     * @throws \SUDHAUS7\Guard7Core\Exceptions\SealException
     * @throws \SUDHAUS7\Guard7Core\Exceptions\WrongKeyPassException
     */
    public function testRunSimpleEncoding(): void
    {
        $key = Key::createNewKey()->unlock();
        $config = new ConfigAdapter();
        $encoder = new Encoder($config);
        $encoder->addPubkey($key->getPublicKey());
        $encoder->setContent('payload');
        $data = $encoder->run();
        $this->assertNotNull($data);
        $this->assertStringStartsWith($config->getDefaultMethod(), $data);
    }
    /**
     * @throws \SUDHAUS7\Guard7Core\Exceptions\KeyNotReadableException
     * @throws \SUDHAUS7\Guard7Core\Exceptions\SealException
     * @throws \SUDHAUS7\Guard7Core\Exceptions\WrongKeyPassException
     */
    public function testSimpleRunDecode(): void
    {
        $key = Key::createNewKey()->unlock();
        $config = new ConfigAdapter();
        $encoder = new Encoder($config);
        $encoder->addPubkey($key->getPublicKey());
        $encoder->setContent('payload');
        $data = $encoder->run();
       
        $payload = Decoder::decode($config, $key, $data);
        $this->assertEquals('payload', $payload);
        
    }
    
    public function testArrayEncodeDecode() : void
    {
        $key = Key::createNewKey()->unlock();
        $config = new ConfigAdapter();
        $encoder = new Encoder($config);
        $encoder->addPubkey($key->getPublicKey());
        $encoder->setContent(['x'=>1]);
        $data = $encoder->run();
        $this->assertNotNull($data);
        $this->assertStringStartsWith($config->getDefaultMethod(), $data);
        $payload = Decoder::decode($config, $key, $data);
        $this->assertIsArray($payload);
        $this->assertEquals(1, $payload['x']);
    }
    
    public function testObjectEncodeDecode() : void
    {
        $payload = new stdClass();
        $payload->x = 1;
        $key = Key::createNewKey()->unlock();
        $config = new ConfigAdapter();
        $encoder = new Encoder($config);
        $encoder->addPubkey($key->getPublicKey());
        $encoder->setContent($payload);
        $data = $encoder->run();
        $this->assertNotNull($data);
        $this->assertStringStartsWith($config->getDefaultMethod(), $data);
        $payloaddecoded = Decoder::decode($config, $key, $data);
        $this->assertIsObject($payloaddecoded);
        $this->assertEquals($payloaddecoded->x, $payload->x);
    }
    
    public function testNonExistendEncoderClass() : void
    {
        $config = new InvalidConfigAdapter();
        $encoder = new Encoder($config);
        $this->assertNull($encoder->run());
    
        $key = Key::createNewKey()->unlock();
        $decoder =  Decoder::decode($config,$key,'data');
        $this->assertNull($decoder);
        
    }
    
    public function testEncodeArray() : void
    {
        $payload = ['x'=>1,'y'=>2,'z'=>3];
        
        $key = Key::createNewKey()->unlock();
        $config = new ConfigAdapter();
        list($encodedArray,$checksumms) = Encoder::encodeArray($config, $payload, ['x','y'], [$key->getPublicKey()]);
    
        $this->assertEquals(3, $encodedArray['z']);
        $this->assertNotEquals(2, $encodedArray['y']);
        $this->assertStringStartsWith($config->getDefaultMethod(), $encodedArray['x']);
        
    }
}
