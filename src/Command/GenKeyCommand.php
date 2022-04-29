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
     * 处理当前命令
     */
    public function handle()
    {
        $driverName = $this->choice('Select driver', array_keys($this->config->get('encryption.driver')));

        $keys = $this->generateRandomKey($driverName);
        if ($keys) {
            foreach ($keys as $key => $value) {
                $this->line('<comment>' . $key . ": " . $value . '</comment>');
            }
        }
        $this->line('<comment>' . $keys . '</comment>');
    }

    /**
     * 为应用程序生成一个随机密钥。
     *
     * @return array||string
     */
    protected function generateRandomKey(string $driverName)
    {
        $config = $this->config->get("encryption.driver.{$driverName}");
        return call([$config['class'], 'generateKey'], [['options' => $config['options']]]);
    }
}
