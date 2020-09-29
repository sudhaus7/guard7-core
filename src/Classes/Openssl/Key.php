<?php


namespace SUDHAUS7\Guard7Core\Openssl;

use Exception;
use SUDHAUS7\Guard7Core\Exceptions\KeyNotReadableException;
use SUDHAUS7\Guard7Core\Exceptions\KeyNotUnlockedYetException;
use SUDHAUS7\Guard7Core\Exceptions\WrongKeyPassException;
use SUDHAUS7\Guard7Core\Interfaces\CryptExtensionInterface;
use SUDHAUS7\Guard7Core\Service\ChecksumService;
use function openssl_free_key;
use function openssl_pkey_export;
use function openssl_pkey_new;

final class Key implements CryptExtensionInterface
{

    /**
     * @var resource|false
     */
    private $resource;
    /**
     * @var string
     */
    private $private;
    /**
     * @var string
     */
    private $public;


    /**
     * openssl defaults
     * @var array
     */
    public static $DEFAULTS = [
        "digest_alg" => "sha512",
        "private_key_bits" => 4096,
        "private_key_type" => OPENSSL_KEYTYPE_RSA,
    ];


    /**
     * @var ChecksumService
     */
    private $checksumService;

    /**
     * @inheritDoc
     */
    public function __construct(string $privatekey, string $password=null, string $publickey = null)
    {
        $this->checksumService = new ChecksumService();
        $this->private = $privatekey;
        if ($publickey === null) {
            try {
                $this->unlock($password);
            } catch (Exception $e) {
                // at this point it is ok if we cannot be unlock yet
            }
        }
    }

    /**
     *
     */
    public function __destruct()
    {
        if ($this->resource) {
            openssl_free_key($this->resource);
        }
    }

    /**
     * @inheritDoc
     */
    public static function createNewKey(string $password = null): CryptExtensionInterface
    {
        /** @var resource $res */
        $res = openssl_pkey_new(self::$DEFAULTS);

        openssl_pkey_export($res, $privatekey);
        /** @var array $details */
        $details = openssl_pkey_get_details($res);
        $publickey = $details["key"];
        if ($password) {
            openssl_pkey_export($res, $privatekey, $password);
        }
        openssl_free_key($res);

        return new self($privatekey, $password, $publickey);
    }

    /**
     * @inheritDoc
     */
    public function getKey(): string
    {
        return $this->private;
    }

    /**
     * @inheritDoc
     */
    public function getPublicKey(): string
    {
        if (!$this->public) {
            throw new KeyNotUnlockedYetException('Key not unlocked yet', 1601043319);
        }
        return $this->public;
    }

    /**
     * @inheritDoc
     */
    public function checksumPrivate(): string
    {
        return $this->checksumService->calculate($this->private);
    }


    /**
     * @inheritDoc
     */
    public function checksumPublic(): string
    {
        return $this->checksumService->calculate($this->getPublicKey());
    }

    /**
     * @inheritDoc
     */
    public function lock(string $password): bool
    {
        if ($this->resource) {
            openssl_pkey_export($this->resource, $privatekey, $password);
            $this->private = $privatekey;
        }
        return false;
    }

    /**
     * @inheritDoc
     */
    public function unlock(string $password = null): CryptExtensionInterface
    {
        
        if ($password !== null) {
            $resource = openssl_pkey_get_private($this->private, $password);
            if (!$resource) {
                throw new WrongKeyPassException("Can not read Private Key (password given)", 1601039943);
            }
            $this->resource = $resource;
        }

        if ($password === null) {
            $resource = openssl_pkey_get_private($this->private);
            if (!$resource) {
                throw new KeyNotReadableException("Can not read Private Key", 1601067642);
            }
            $this->resource = $resource;
        }

        if (empty($this->public) && $this->resource) {
            /** @var array $details */
            $details = openssl_pkey_get_details($this->resource);
            $this->public = $details["key"];
        }
        return $this;
    }

    /**
     * @inheritDoc
     */
    public static function import(string $data): CryptExtensionInterface
    {
        return new Key($data);
    }

    /**
     * @inheritDoc
     *
     */

    /**
     * @inheritDoc
     * @throws KeyNotReadableException
     * @throws WrongKeyPassException
     */
    public function export(string $password = null): CryptExtensionInterface
    {
        if (!$this->resource) {
            $this->unlock($password);
        }
    
        /** @phpstan-ignore-next-line */
        openssl_pkey_export($this->resource, $out);
       
        return new Key($out);
    }

    /**
     * @return bool|mixed|resource
     */
    public function getResource()
    {
        return $this->resource;
    }
}
