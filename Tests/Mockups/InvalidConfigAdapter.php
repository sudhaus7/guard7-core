<?php


namespace SUDHAUS7\Guard7Core\Tests\Mockups;


use SUDHAUS7\Guard7Core\Interfaces\ConfigurationAdapterInterface;

class InvalidConfigAdapter implements ConfigurationAdapterInterface
{
    public function getDefaultMethod(): string
    {
        return 'aes129';
    }
    
    public function getCryptLibrary(): string
    {
        return 'Xoxo';
    }
    public function getKeySize(): int
    {
        return 204;
    }
}
