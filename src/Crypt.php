<?php

declare(strict_types=1);

/**
 * #logic 做事不讲究逻辑，再努力也只是重复犯错
 * ## 何为相思：不删不聊不打扰，可否具体点：曾爱过。何为遗憾：你来我往皆过客，可否具体点：再无你。
 * @version 1.0.0
 * @author @小小只^v^ <littlezov@qq.com>  littlezov@qq.com
 * @link     https://github.com/littlezo
 * @document https://github.com/littlezo/wiki
 * @license  https://github.com/littlezo/MozillaPublicLicense/blob/main/LICENSE
 *
 */

namespace Littler\Encryption;

use Hyperf\Utils\ApplicationContext;
use Littler\Encryption\Contract\DriverInterface;
use Littler\Encryption\Contract\EncryptionInterface;

abstract class Crypt
{
    public static function getDriver(?string $name = null): DriverInterface
    {
        return ApplicationContext::getContainer()->get(EncryptionInterface::class)->getDriver($name);
    }

    public static function encrypt($value, int $type, bool $serialize = true, ?string $driverName = null): string
    {
        return static::getDriver($driverName)->encrypt($value, $type, $serialize);
    }

    public static function decrypt(string $payload, int $type, bool $unserialize = true, ?string $driverName = null): mixed
    {
        return static::getDriver($driverName)->decrypt($payload, $type, $unserialize);
    }
}
