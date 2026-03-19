<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Tests\Unit;

use Klkvsk\Whoeasy\Exception\InvalidArgumentException;
use Klkvsk\Whoeasy\Registry\QueryType;
use Klkvsk\Whoeasy\Registry\ServerRegistry;
use PHPUnit\Framework\TestCase;

class ServerRegistryTest extends TestCase
{
    private ServerRegistry $registry;

    protected function setUp(): void
    {
        $this->registry = new ServerRegistry();
    }

    public function testResolveDomainCom(): void
    {
        $info = $this->registry->resolve('example.com');
        $this->assertSame(QueryType::Domain, $info->queryType);
        $this->assertSame('whois.verisign-grs.com', $info->whoisServer);
        $this->assertNotNull($info->rdapUrl);
        $this->assertStringContainsString('verisign', $info->rdapUrl);
    }

    public function testResolveDomainOrg(): void
    {
        $info = $this->registry->resolve('example.org');
        $this->assertSame(QueryType::Domain, $info->queryType);
        $this->assertSame('whois.pir.org', $info->whoisServer);
        $this->assertNotNull($info->rdapUrl);
    }

    public function testResolveCcTld(): void
    {
        $info = $this->registry->resolve('example.de');
        $this->assertSame(QueryType::Domain, $info->queryType);
        $this->assertSame('whois.denic.de', $info->whoisServer);
    }

    public function testResolveIpv4(): void
    {
        $info = $this->registry->resolve('8.8.8.8');
        $this->assertSame(QueryType::Ipv4, $info->queryType);
        $this->assertNotNull($info->whoisServer);
    }

    public function testResolveIpv6(): void
    {
        $info = $this->registry->resolve('2001:4860:4860::8888');
        $this->assertSame(QueryType::Ipv6, $info->queryType);
        $this->assertNotNull($info->whoisServer);
    }

    public function testResolveAsn(): void
    {
        $info = $this->registry->resolve('AS15169');
        $this->assertSame(QueryType::Asn, $info->queryType);
        $this->assertNotNull($info->whoisServer);
    }

    public function testUnsupportedQueryThrows(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->registry->resolve('!!!invalid!!!');
    }

    public function testLookupTld(): void
    {
        $result = $this->registry->lookupTld('com');
        $this->assertNotNull($result);
        $this->assertSame('whois.verisign-grs.com', $result[0]);

        $this->assertNull($this->registry->lookupTld('zzzzzznonexistent'));
    }

    public function testQueryTypeGuess(): void
    {
        $this->assertSame(QueryType::Domain, QueryType::guess('example.com'));
        $this->assertSame(QueryType::Ipv4, QueryType::guess('192.168.1.1'));
        $this->assertSame(QueryType::Ipv4, QueryType::guess('192.168.0.0/16'));
        $this->assertSame(QueryType::Ipv6, QueryType::guess('2001:db8::1'));
        $this->assertSame(QueryType::Asn, QueryType::guess('AS12345'));
        $this->assertSame(QueryType::NicHandle, QueryType::guess('HANDLE-a'));
    }

    public function testArinQueryFormat(): void
    {
        $info = $this->registry->resolve('8.8.8.8');
        $this->assertSame('n + %s', $info->queryFormat);
    }

    public function testDenicQueryFormat(): void
    {
        $info = $this->registry->resolve('example.de');
        $this->assertSame('-T dn %s', $info->queryFormat);
    }

    public function testJprsQueryFormat(): void
    {
        $info = $this->registry->resolve('example.jp');
        if ($info->whoisServer === 'whois.jprs.jp') {
            $this->assertSame('%s/e', $info->queryFormat);
        }
    }

    public function testComHasNoQueryFormat(): void
    {
        $info = $this->registry->resolve('example.com');
        $this->assertNull($info->queryFormat);
    }
}
