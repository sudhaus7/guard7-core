<?php
/**
 * Created by PhpStorm.
 * User: frank
 * Date: 31.01.18
 * Time: 15:29
 */

namespace SUDHAUS7\Guard7Core\Tools;

use SUDHAUS7\Guard7Core\Exceptions\SealException;
use SUDHAUS7\Guard7Core\Interfaces\ConfigurationAdapterInterface;
use SUDHAUS7\Guard7Core\Interfaces\CryptExtensionService;
use SUDHAUS7\Guard7Core\Service\ChecksumService;
use function class_exists;
use function class_implements;
use function in_array;
use function is_object;
use function json_encode;
use function serialize;
use function strtolower;

class Encoder
{

    /**
     * @var array
     */
    protected $pubkeys = [];


    /**
     * @var string
     */
    protected $content = '';

    /**
     * @var string
     */
    protected $method = 'RC4';

    /**
     * @var ConfigurationAdapterInterface
     */
    protected $configurationAdapter;

    /**
     * @var ChecksumService
     */
    private $checksumService;

    /**
     * Encoder constructor.
     *
     * @param mixed|null $content
     * @param array $pubKeys
     * @param string|null $method
     */
    public function __construct(ConfigurationAdapterInterface $configurationAdapter, array $pubKeys = [], $content=null, string $method = null)
    {
        $this->configurationAdapter = $configurationAdapter;
        $this->checksumService  = new ChecksumService();
        if ($method === null) {
            $method  = $this->configurationAdapter->getDefaultMethod();
        }
        if ($content) {
            $this->setContent($content);
        }
        $this->setPubkeys($pubKeys);
        $this->setMethod($method);
    }

    /**
     * @param mixed $content
     */
    public function setContent($content): void
    {
        if (is_array($content)) {
            $content = 'json:'.json_encode($content);
        }
        if (is_object($content)) {
            $content = 'serialized:'.serialize($content);
        }
        $this->content = $content;
    }

    /**
     * @return string
     * @throws SealException
     */
    public function run(): ?string
    {
        $serviceClass = '\\SUDHAUS7\\Guard7Core\\'.ucfirst(strtolower($this->configurationAdapter->getCryptLibrary())).'\\Service';
        if (class_exists($serviceClass) && in_array(CryptExtensionService::class, class_implements($serviceClass))) {
            return $serviceClass::encode($this->method, $this->pubkeys, $this->content);
        }
        return null;
    }

    /**
     * @param string $key
     */
    public function addPubkey(string $key): void
    {
        $checksum = $this->checksumService->calculate($key);
        $this->pubkeys[$checksum] = $key;
    }

    /**
     * @return array
     */
    public function getChecksums()
    {
        return array_keys($this->pubkeys);
    }

    /**
     * @return array
     */
    public function getPubkeys(): array
    {
        return array_values($this->pubkeys);
    }

    /**
     * @param array $pubkeys
     */
    public function setPubkeys(array $pubkeys): void
    {
        foreach ($pubkeys as $key) {
            $checksum = $this->checksumService->calculate($key);
            $this->pubkeys[$checksum] = $key;
        }
    }

    /**
     * @return string
     */
    public function getMethod(): string
    {
        return $this->method;
    }

    /**
     * @param string $method
     */
    public function setMethod(string $method): void
    {

        //$valid = ['RC4','AES128','AES256','DES'];
        $valid = openssl_get_cipher_methods(true);
        if (in_array($method, $valid, true)) {
            $this->method = $method;
        }
    }


    /**
     * @param ConfigurationAdapterInterface $configuration
     * @param array $row
     * @param array $fields
     * @param array $publicKeys
     * @param null $method
     * @return array
     * @throws SealException
     */
    public static function encodeArray(ConfigurationAdapterInterface $configuration, array $row, array $fields, array $publicKeys, $method = null)
    {
        if ($method === null) {
            $method  = $configuration->getDefaultMethod();
        }
        $checksums = null;
        foreach ($fields as $field) {
            if (isset($row[$field]) && !empty($row[$field])) {
                $encoder = new self($configuration, $publicKeys, $row[$field], $method);
                $row[$field] = $encoder->run();
                if (!$checksums) {
                    $checksums = $encoder->getChecksums();
                }
            }
        }
        return [$row,$checksums];
    }
}
