<?php
/**
 * Created by PhpStorm.
 * User: frank
 * Date: 31.01.18
 * Time: 15:29
 */

namespace SUDHAUS7\Guard7Core\Tools;

use SUDHAUS7\Guard7Core\Exceptions\MissingKeyException;
use SUDHAUS7\Guard7Core\Exceptions\UnlockException;
use SUDHAUS7\Guard7Core\Exceptions\WrongKeyPassException;
use SUDHAUS7\Guard7Core\Interfaces\ConfigurationAdapterInterface;
use SUDHAUS7\Guard7Core\Interfaces\CryptExtensionInterface;
use SUDHAUS7\Guard7Core\Interfaces\CryptExtensionService;
use function class_exists;
use function class_implements;
use function in_array;
use function strtolower;

/**
 * Class Decoder
 * @package SUDHAUS7\Guard7Core\Tools
 */
class Decoder
{
    /**
     * @param mixed $data
     * @param CryptExtensionInterface $key
     * @param string|null $password
     * @return mixed
     * @throws MissingKeyException
     * @throws UnlockException
     */
    public static function decode(ConfigurationAdapterInterface $configuration, CryptExtensionInterface $key, $data, string $password = null)
    {
        $serviceClass = '\\SUDHAUS7\\Guard7Core\\'.ucfirst(strtolower($configuration->getCryptLibrary())).'\\Service';
        if (class_exists($serviceClass) && in_array(CryptExtensionService::class, class_implements($serviceClass))) {
            return $serviceClass::decode($data, $key, $password);
        }
        return null;
    }
}
