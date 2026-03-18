<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Tests\Unit\Rdap;

use Klkvsk\Whoeasy\Enum\QueryType;
use Klkvsk\Whoeasy\Parser\Rdap\RdapParser;
use Klkvsk\Whoeasy\Result\Info\AsnInfo;
use Klkvsk\Whoeasy\Result\Info\DomainInfo;
use Klkvsk\Whoeasy\Result\Info\IpInfo;
use PHPUnit\Framework\TestCase;

class RdapParserTest extends TestCase
{
    private RdapParser $parser;

    protected function setUp(): void
    {
        $this->parser = new RdapParser();
    }

    private static function loadFixture(string $filename): array
    {
        $path = __DIR__ . '/../../Fixtures/rdap/' . $filename;
        return json_decode(file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
    }

    public function testParseDomainFixture(): void
    {
        $json = self::loadFixture('domain-example.com.json');
        $domain = $this->parser->parse($json, QueryType::Domain);

        $this->assertInstanceOf(DomainInfo::class, $domain);
        $this->assertSame('EXAMPLE.COM', $domain->name);
        $this->assertContains('client delete prohibited', $domain->status);
        $this->assertNotNull($domain->createdDate);
        $this->assertStringContainsString('1995-08-14', $domain->createdDate);
        $this->assertNotNull($domain->expiresDate);
        $this->assertStringContainsString('2025-08-13', $domain->expiresDate);
        $this->assertNotNull($domain->updatedDate);

        // Nameservers
        $this->assertCount(2, $domain->nameservers);
        $this->assertSame('a.iana-servers.net', $domain->nameservers[0]->hostname);
        $this->assertSame('b.iana-servers.net', $domain->nameservers[1]->hostname);

        // Registrar entity
        $this->assertNotNull($domain->registrar);
        $this->assertSame('RESERVED-Internet Assigned Numbers Authority', $domain->registrar->name);

        // Registrant contact
        $this->assertNotEmpty($domain->contacts);
    }

    public function testParseIpFixture(): void
    {
        $json = self::loadFixture('ip-8.8.8.8.json');
        $ip = $this->parser->parse($json, QueryType::Ipv4);

        $this->assertInstanceOf(IpInfo::class, $ip);
        $this->assertSame('GOGL', $ip->networkName);
        $this->assertSame('8.8.8.0 - 8.8.8.255', $ip->range);
        $this->assertNotNull($ip->createdDate);
        $this->assertNotEmpty($ip->contacts);
    }

    public function testParseAsnFixture(): void
    {
        $json = self::loadFixture('autnum-15169.json');
        $asn = $this->parser->parse($json, QueryType::Asn);

        $this->assertInstanceOf(AsnInfo::class, $asn);
        $this->assertSame(15169, $asn->asn);
        $this->assertSame('GOOGLE', $asn->name);
        $this->assertNotNull($asn->createdDate);
        $this->assertNotEmpty($asn->contacts);
    }

    public function testParseDomainWithEmptyEntities(): void
    {
        $domain = $this->parser->parse([
            'objectClassName' => 'domain',
            'ldhName' => 'minimal.test',
            'entities' => [],
        ], QueryType::Domain);

        $this->assertInstanceOf(DomainInfo::class, $domain);
        $this->assertSame('minimal.test', $domain->name);
        $this->assertNull($domain->registrar);
        $this->assertEmpty($domain->contacts);
    }

    public function testParseUnknownObjectClassFallsToDomain(): void
    {
        $result = $this->parser->parse([
            'objectClassName' => 'unknown_type',
            'ldhName' => 'fallback.test',
        ], QueryType::Domain);

        $this->assertInstanceOf(DomainInfo::class, $result);
    }
}
