<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Tests\Unit\Registry;

use Klkvsk\Whoeasy\Enum\QueryType;
use Klkvsk\Whoeasy\Exception\InvalidArgumentException;
use Klkvsk\Whoeasy\Registry\ServerRegistry;
use PHPUnit\Framework\TestCase;

class ServerRegistryTest extends TestCase
{
    public function testResolveDomainCom(): void
    {
        $registry = new ServerRegistry();
        $info = $registry->resolve('example.com');

        $this->assertSame(QueryType::Domain, $info->queryType);
        $this->assertSame('whois.verisign-grs.com', $info->whoisServer);
        $this->assertNotNull($info->rdapUrl);
        $this->assertTrue($info->hasWhois());
        $this->assertTrue($info->hasRdap());
    }

    public function testResolveIpv4(): void
    {
        $registry = new ServerRegistry();
        $info = $registry->resolve('8.8.8.8');

        $this->assertSame(QueryType::Ipv4, $info->queryType);
        $this->assertNotNull($info->whoisServer);
        $this->assertTrue($info->hasWhois());
    }

    public function testResolveAsn(): void
    {
        $registry = new ServerRegistry();
        $info = $registry->resolve('AS15169');

        $this->assertSame(QueryType::Asn, $info->queryType);
        $this->assertNotNull($info->whoisServer);
    }

    public function testUnsupportedQuery(): void
    {
        $registry = new ServerRegistry();
        $this->expectException(InvalidArgumentException::class);
        $registry->resolve('not-a-valid-query!!!');
    }
}
