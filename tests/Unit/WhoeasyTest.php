<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Tests\Unit;

use Klkvsk\Whoeasy\QueryMode;
use Klkvsk\Whoeasy\QueryOptions;
use Klkvsk\Whoeasy\Whoeasy;
use PHPUnit\Framework\TestCase;

class WhoeasyTest extends TestCase
{
    public function testCreateWithDefaults(): void
    {
        $whoeasy = Whoeasy::create();
        $defaults = $whoeasy->getDefaultOptions();

        $this->assertNull($defaults->mode);
        $this->assertNull($defaults->proxyUri);
        $this->assertNull($defaults->whoisTimeout);
        $this->assertNull($defaults->rdapTimeout);
    }

    public function testCreateWithCustomOptions(): void
    {
        $options = new QueryOptions(
            mode: QueryMode::WhoisOnly,
            proxyUri: 'socks5://proxy:1080',
            whoisTimeout: 60,
            rdapTimeout: 30,
        );
        $whoeasy = Whoeasy::create($options);

        $this->assertSame(QueryMode::WhoisOnly, $whoeasy->getDefaultOptions()->mode);
        $this->assertSame('socks5://proxy:1080', $whoeasy->getDefaultOptions()->proxyUri);
        $this->assertSame(60, $whoeasy->getDefaultOptions()->whoisTimeout);
        $this->assertSame(30, $whoeasy->getDefaultOptions()->rdapTimeout);
    }

    public function testQueryOptionsDefaults(): void
    {
        $options = new QueryOptions();

        $this->assertEquals(QueryOptions::DEFAULT_MODE, $options->mode);
        $this->assertNull($options->proxyUri);
        $this->assertEquals(QueryOptions::DEFAULT_TIMEOUT, $options->whoisTimeout);
        $this->assertEquals(QueryOptions::DEFAULT_TIMEOUT, $options->rdapTimeout);
        $this->assertEquals(QueryOptions::DEFAULT_MAX_REFERRALS, $options->maxReferrals);
        $this->assertEquals(QueryOptions::DEFAULT_RECURSIVE, $options->recursive);
    }
}
