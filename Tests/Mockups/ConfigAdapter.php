<?php


namespace SUDHAUS7\Guard7Core\Tests\Mockups;

use SUDHAUS7\Guard7Core\Interfaces\ConfigurationAdapterInterface;

class ConfigAdapter implements ConfigurationAdapterInterface
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
