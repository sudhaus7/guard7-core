<?php


namespace SUDHAUS7\Guard7Core\Service;

class ChecksumService
{

    /**
     * @var array
     */
    private static $ENDLINES = [
        '-----END PUBLIC KEY-----',
        '-----END PRIVATE KEY-----',
        '-----END RSA PRIVATE KEY-----',
        '-----END ENCRYPTED PRIVATE KEY-----'
    ];

    /**
     * @var array
     */
    private static $STARTLINES = [
        '-----BEGIN PUBLIC KEY-----',
        '-----BEGIN PRIVATE KEY-----',
        '-----BEGIN RSA PRIVATE KEY-----',
        '-----BEGIN ENCRYPTED PRIVATE KEY-----'
    ];

    /**
     * @param string $key
     * @return string
     */
    public function calculate(string $key): string
    {
        $key = trim($key);
        $lines = explode("\n", $key);
        $core = '';
        $active = false;
        foreach ($lines as $line) {
            $line = trim($line);

            if ($active && \in_array($line, self::$ENDLINES, true)) {
                $active = false;
            }

            if ($active) {
                $core .= $line;
            }
            if (!$active && \in_array($line, self::$STARTLINES, true)) {
                $active = true;
            }
        }
        return sha1($core);
    }
}
