<?php

declare(strict_types=1);
/**
 * #logic 做事不讲究逻辑，再努力也只是重复犯错
 * ## 何为相思：不删不聊不打扰，可否具体点：曾爱过。何为遗憾：你来我往皆过客，可否具体点：再无你。.
 * @version 1.0.0
 * @author @小小只^v^ <littlezov@qq.com>  littlezov@qq.com
 * @link     https://github.com/littlezo
 * @document https://github.com/littlezo/wiki
 * @license  https://github.com/littlezo/MozillaPublicLicense/blob/main/LICENSE
 *
 */
namespace Littler\Encryption\Command;

use Hyperf\Command\Command as HyperfCommand;
use Hyperf\Contract\ConfigInterface;

class GenKeyCommand extends HyperfCommand
{
    /**
     * 生成key.
     *
     * @var \Hyperf\Contract\ConfigInterface
     */
    protected $config;

    public function __construct(ConfigInterface $config)
    {
        $this->config = $config;
        parent::__construct('gen:key');
    }

    public function configure()
    {
        parent::configure();
        $this->setDescription('Create a secret key or key-pair for littler/encryption');
    }

    /**
     * 处理当前命令.
     */
    public function handle()
    {
        // $driverName = $this->choice('Select driver', array_keys($this->config->get('encryption.driver')), 'rsa');
        $keys = $this->generateRandomKey('rsa');
        if ($keys) {
            foreach ($keys as $key => $value) {
                $envPath = BASE_PATH . '/.env';

                if (! file_exists($envPath)) {
                    $this->line('.env file not is exists!', 'error');
                }

                if ($this->contains(file_get_contents($envPath), $this->upper('RSA_' . $key)) === false) {
                    file_put_contents($envPath, "\n{$this->upper('RSA_' . $key)}={$value}\n", FILE_APPEND);
                } else {
                    file_put_contents($envPath, preg_replace(
                        "~{$this->upper('RSA_' . $key)}\\s*=\\s*[^\n]*~",
                        "{$this->upper('RSA_' . $key)}=\"{$value}\"",
                        file_get_contents($envPath)
                    ));
                }
                $this->line('<comment>' . $key . ': ' . $this->get_private_key($value) . '</comment>');
            }
        } else {
            $this->line('<comment>' . $keys . '</comment>');
        }
    }

    public function upper(string $value): string
    {
        return mb_strtoupper($value, 'UTF-8');
    }

    /*获取私有key字符串 重新格式化 为保证任何key都可以识别*/
    public static function get_private_key($private_key)
    {
        $search = [
            '-----BEGIN PRIVATE KEY-----', // 自定义头部
            '-----END PRIVATE KEY-----', // 自定义尾部
            "\n",
            "\r",
            "\r\n",
        ];
        return $private_key;
        return $private_key = str_replace($search, '', $private_key);
        // return $search[0] . PHP_EOL . wordwrap($private_key, 64, "\n", true) . PHP_EOL . $search[1];
    }

    /*获取公共key字符串 重新格式化 为保证任何key都可以识别*/
    public static function get_public_key($public_key)
    {
        $search = [
            '-----BEGIN PUBLIC KEY-----', // 自定义头部
            '-----END PUBLIC KEY-----', // 自定义尾部
            "\n",
            "\r",
            "\r\n",
        ];
        return $public_key;
        return $public_key = str_replace($search, '', $public_key);
        // return $search[0] . PHP_EOL . wordwrap($public_key, 64, "\n", true) . PHP_EOL . $search[1];
    }

    /**
     * 为应用程序生成一个随机密钥。
     *e.
     * @return array||string
     */
    protected function generateRandomKey(string $driverName)
    {
        $config = $this->config->get("encryption.driver.{$driverName}");
        return call([$config['class'], 'generateKey'], ['options' => $config['options']]);
    }

    protected function contains(string $haystack, $needles): bool
    {
        foreach ((array) $needles as $needle) {
            if ($needle != '' && mb_strpos($haystack, $needle) !== false) {
                return true;
            }
        }

        return false;
    }
}
