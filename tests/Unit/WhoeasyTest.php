<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Tests\Unit;

use Klkvsk\Whoeasy\Config;
use Klkvsk\Whoeasy\Enum\AuthLevel;
use Klkvsk\Whoeasy\Enum\QueryMode;
use Klkvsk\Whoeasy\QueryOptions;
use Klkvsk\Whoeasy\Whoeasy;
use PHPUnit\Framework\TestCase;

class WhoeasyTest extends TestCase
{
    public function testCreateWithDefaults(): void
    {
        $whoeasy = Whoeasy::create();
        $config = $whoeasy->getConfig();

        $this->assertSame(QueryMode::PreferRdap, $config->defaultMode);
        $this->assertNull($config->proxyUri);
        $this->assertSame(30, $config->whoisTimeout);
        $this->assertSame(15, $config->rdapTimeout);
    }

    public function testCreateWithCustomConfig(): void
    {
        $config = new Config(
            defaultMode: QueryMode::WhoisOnly,
            proxyUri: 'socks5://proxy:1080',
            whoisTimeout: 60,
            rdapTimeout: 30,
        );
        $whoeasy = Whoeasy::create($config);

        $this->assertSame(QueryMode::WhoisOnly, $whoeasy->getConfig()->defaultMode);
        $this->assertSame('socks5://proxy:1080', $whoeasy->getConfig()->proxyUri);
        $this->assertSame(60, $whoeasy->getConfig()->whoisTimeout);
        $this->assertSame(30, $whoeasy->getConfig()->rdapTimeout);
    }

    public function testWhoisOnlyThrowsLogicException(): void
    {
        $whoeasy = Whoeasy::create();
        $options = new QueryOptions(mode: QueryMode::WhoisOnly);

        $this->expectException(\LogicException::class);
        $whoeasy->query('example.com', $options);
    }

    public function testQueryOptionsDefaults(): void
    {
        $options = new QueryOptions();

        $this->assertNull($options->mode);
        $this->assertSame(AuthLevel::Auth, $options->authLevel);
        $this->assertNull($options->proxyUri);
        $this->assertNull($options->timeout);
    }
}
