<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Tests\Unit\Rdap;

use Klkvsk\Whoeasy\Enum\QueryType;
use Klkvsk\Whoeasy\Parser\Rdap\RdapParser;
use Klkvsk\Whoeasy\Result\StructuredResult;
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
        $result = $this->parser->parse($json, QueryType::Domain);

        $this->assertInstanceOf(StructuredResult::class, $result);
        $this->assertNotNull($result->domain);
        $this->assertSame('EXAMPLE.COM', $result->domain->name);
        $this->assertContains('client delete prohibited', $result->domain->status);
        $this->assertNotNull($result->domain->createdDate);
        $this->assertStringContainsString('1995-08-14', $result->domain->createdDate);
        $this->assertNotNull($result->domain->expiresDate);
        $this->assertStringContainsString('2025-08-13', $result->domain->expiresDate);
        $this->assertNotNull($result->domain->updatedDate);

        // Nameservers
        $this->assertCount(2, $result->domain->nameservers);
        $this->assertSame('a.iana-servers.net', $result->domain->nameservers[0]->hostname);
        $this->assertSame('b.iana-servers.net', $result->domain->nameservers[1]->hostname);

        // Registrar entity
        $this->assertNotNull($result->domain->registrar);
        $this->assertSame('RESERVED-Internet Assigned Numbers Authority', $result->domain->registrar->name);

        // Registrant contact
        $this->assertNotEmpty($result->domain->contacts);
    }

    public function testParseIpFixture(): void
    {
        $json = self::loadFixture('ip-8.8.8.8.json');
        $result = $this->parser->parse($json, QueryType::Ipv4);

        $this->assertInstanceOf(StructuredResult::class, $result);
        $this->assertNotNull($result->ip);
        $this->assertSame('GOGL', $result->ip->networkName);
        $this->assertSame('8.8.8.0 - 8.8.8.255', $result->ip->range);
        $this->assertNotNull($result->ip->createdDate);
        $this->assertNotEmpty($result->ip->contacts);
    }

    public function testParseAsnFixture(): void
    {
        $json = self::loadFixture('autnum-15169.json');
        $result = $this->parser->parse($json, QueryType::Asn);

        $this->assertInstanceOf(StructuredResult::class, $result);
        $this->assertNotNull($result->asn);
        $this->assertSame(15169, $result->asn->asn);
        $this->assertSame('GOOGLE', $result->asn->name);
        $this->assertNotNull($result->asn->createdDate);
        $this->assertNotEmpty($result->asn->contacts);
    }

    public function testParseDomainWithEmptyEntities(): void
    {
        $result = $this->parser->parse([
            'objectClassName' => 'domain',
            'ldhName' => 'minimal.test',
            'entities' => [],
        ], QueryType::Domain);

        $this->assertInstanceOf(StructuredResult::class, $result);
        $this->assertNotNull($result->domain);
        $this->assertSame('minimal.test', $result->domain->name);
        $this->assertNull($result->domain->registrar);
        $this->assertEmpty($result->domain->contacts);
    }

    public function testParseUnknownObjectClassFallsToDomain(): void
    {
        $result = $this->parser->parse([
            'objectClassName' => 'unknown_type',
            'ldhName' => 'fallback.test',
        ], QueryType::Domain);

        $this->assertInstanceOf(StructuredResult::class, $result);
        $this->assertNotNull($result->domain);
    }
}
