<?php


namespace SUDHAUS7\Guard7Core\Tests\Mockups;


class ConfigAdapter implements \SUDHAUS7\Guard7Core\Interfaces\ConfigurationAdapterInterface
{
    
    public function getDefaultMethod(): string
    {
        return 'aes128';
    }
    
    public function getCryptLibrary(): string
    {
        return 'Openssl';
    }
}
