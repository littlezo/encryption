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

namespace Littler\Encryption;

use Hyperf\Contract\ConfigInterface;
use InvalidArgumentException;
use Littler\Encryption\Contract\DriverInterface;
use Littler\Encryption\Contract\EncryptionInterface;
use Littler\Encryption\Driver\AesDriver;

class EncryptionManager implements EncryptionInterface
{
    /**
     * 配置实例
     *
     * @var \Hyperf\Contract\ConfigInterface
     */
    protected $config;

    /**
     * 创建的“驱动程序”数组
     *
     * @var \Littler\Encryption\Contract\DriverInterface[]
     */
    protected $drivers = [];

    public function __construct(ConfigInterface $config)
    {
        $this->config = $config;
    }

    public function encrypt($value, bool $serialize = true): string
    {
        return $this->getDriver()->encrypt($value, $serialize);
    }

    public function decrypt(string $payload, bool $unserialize = true)
    {
        return $this->getDriver()->decrypt($payload, $unserialize);
    }

    /**
     * 获取驱动程序实例
     *
     * @return \Littler\Encryption\Contract\AsymmetricDriverInterface|\Littler\Encryption\Contract\SymmetricDriverInterface
     */
    public function getDriver(?string $name = null): DriverInterface
    {
        if (isset($this->drivers[$name]) && $this->drivers[$name] instanceof DriverInterface) {
            return $this->drivers[$name];
        }

        $name = $name ?: $this->config->get('encryption.default', 'aes');

        $config = $this->config->get("encryption.driver.{$name}");
        if (empty($config) or empty($config['class'])) {
            throw new InvalidArgumentException(sprintf('The encryption driver config %s is invalid.', $name));
        }

        $driverClass = $config['class'] ?? AesDriver::class;

        $driver = make($driverClass, ['options' => $config['options'] ?? []]);

        return $this->drivers[$name] = $driver;
    }
}
