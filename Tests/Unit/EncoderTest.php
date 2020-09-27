<?php

namespace SUDHAUS7\Guard7Core\Tests\Unit;

use SUDHAUS7\Guard7Core\Openssl\Key;
use SUDHAUS7\Guard7Core\Tests\Mockups\ConfigAdapter;
use SUDHAUS7\Guard7Core\Tools\Encoder;
use PHPUnit\Framework\TestCase;

/**
 * @covers \SUDHAUS7\Guard7Core\Tools\Encoder
 */
class EncoderTest extends TestCase
{
    public function testCanBeInstantiated() : void
    {
        $encoder = new Encoder(new ConfigAdapter());
        $this->assertInstanceOf(Encoder::class, $encoder);
    }
    public function testSetContentOnInstantiate() : void
    {
        $encoder = new Encoder(new ConfigAdapter(),[],'content to encode');
        $this->assertInstanceOf(Encoder::class, $encoder);
    }
    public function testSetArrayContent() : void
    {
        $encoder = new Encoder(new ConfigAdapter());
        $encoder->setContent(['content to encode']);
        $this->assertInstanceOf(Encoder::class, $encoder);
    }
    public function testSetObjectContent() : void
    {
        $encoder = new Encoder(new ConfigAdapter());
        $content = new \stdClass();
        $content->xxx = 'content';
        $encoder->setContent($content);
        $this->assertInstanceOf(Encoder::class, $encoder);
    }
    
    /**
     * @covers \SUDHAUS7\Guard7Core\Openssl\Key
     * @covers \SUDHAUS7\Guard7Core\Service\ChecksumService
     */
    public function testAddPublicKey():void
    {
        $key = Key::createNewKey()->unlock();
        
        $encoder = new Encoder(new ConfigAdapter());
        $encoder->addPubkey($key->getPublicKey());
        $keys = $encoder->getPubkeys();
        $encoder->setPubkeys($keys);
        $this->assertEquals($keys[0], $key->getPublicKey());
        $checksums = $encoder->getChecksums();
        $this->assertTrue(\is_array($checksums) && !empty($checksums) && sizeof($checksums)===1);
        
    }
    /**
     * @covers \SUDHAUS7\Guard7Core\Openssl\Key
     */
    public function testSetMethod():void
    {
        $config = new ConfigAdapter();
        $encoder = new Encoder($config,[],null,$config->getDefaultMethod());
        $this->assertEquals($encoder->getMethod(), $config->getDefaultMethod());
        $encoder->setMethod('aes128');
        $this->assertEquals($encoder->getMethod(),'aes128');
        
    }
    
    /**
     * @covers SUDHAUS7\Guard7Core\Openssl\Key
     * @covers SUDHAUS7\Guard7Core\Openssl\Service
     * @covers SUDHAUS7\Guard7Core\Service\ChecksumService::calculate
     */
    public function testRunSimpleEncoding():void
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
}
