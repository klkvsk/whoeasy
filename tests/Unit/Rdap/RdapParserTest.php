<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Tests\Unit\Rdap;

use Klkvsk\Whoeasy\Client\Rdap\RdapParser;
use Klkvsk\Whoeasy\Client\Rdap\RdapResponse;
use Klkvsk\Whoeasy\Parser\Data\AsnResult;
use Klkvsk\Whoeasy\Parser\Data\DomainResult;
use Klkvsk\Whoeasy\Parser\Data\IpResult;
use PHPUnit\Framework\Attributes\DataProvider;
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

    private static function makeResponse(array $json): RdapResponse
    {
        return new RdapResponse(
            server: 'https://test.rdap.example',
            url: 'https://test.rdap.example/test',
            httpCode: 200,
            json: $json,
            rawBody: json_encode($json),
        );
    }

    public function testParseDomainFixture(): void
    {
        $json = self::loadFixture('domain-example.com.json');
        $response = self::makeResponse($json);
        $result = $this->parser->parse($response);

        $this->assertInstanceOf(DomainResult::class, $result);
        $this->assertSame('EXAMPLE.COM', $result->name);
        $this->assertStringContainsString('client delete prohibited', $result->status);
        $this->assertNotNull($result->created);
        $this->assertSame('1995-08-14', $result->created->format('Y-m-d'));
        $this->assertNotNull($result->expires);
        $this->assertSame('2025-08-13', $result->expires->format('Y-m-d'));
        $this->assertNotNull($result->changed);

        // Nameservers
        $this->assertCount(2, $result->nameservers);
        $this->assertSame('a.iana-servers.net', $result->nameservers[0]);
        $this->assertSame('b.iana-servers.net', $result->nameservers[1]);

        // Registrar entity
        $this->assertNotNull($result->registrar);
        $this->assertSame('RESERVED-Internet Assigned Numbers Authority', $result->registrar->name);

        // Registrant contact
        $this->assertNotEmpty($result->contacts);
    }

    public function testParseIpFixture(): void
    {
        $json = self::loadFixture('ip-8.8.8.8.json');
        $response = self::makeResponse($json);
        $result = $this->parser->parse($response);

        $this->assertInstanceOf(IpResult::class, $result);
        $this->assertSame('GOGL', $result->name);
        $this->assertSame('8.8.8.0 - 8.8.8.255', $result->range);
        $this->assertNotNull($result->created);

        // Owner
        $this->assertNotNull($result->owner);
        $this->assertSame('Google LLC', $result->owner->name);

        // Abuse contact
        $this->assertNotEmpty($result->contacts);
        $abuseContact = $result->contacts[0];
        $this->assertSame('abuse', $abuseContact->type);
        $this->assertSame('network-abuse@google.com', $abuseContact->email);
    }

    public function testParseAsnFixture(): void
    {
        $json = self::loadFixture('autnum-15169.json');
        $response = self::makeResponse($json);
        $result = $this->parser->parse($response);

        $this->assertInstanceOf(AsnResult::class, $result);
        $this->assertSame('AS15169', $result->asn);
        $this->assertSame('GOOGLE', $result->name);
        $this->assertNotNull($result->created);

        // Owner
        $this->assertNotNull($result->owner);
        $this->assertSame('Google LLC', $result->owner->name);

        // Tech contact
        $this->assertNotEmpty($result->contacts);
        $techContact = $result->contacts[0];
        $this->assertSame('tech', $techContact->type);
        $this->assertSame('arin-contact@google.com', $techContact->email);
    }

    public function testParseDomainWithEmptyEntities(): void
    {
        $response = self::makeResponse([
            'objectClassName' => 'domain',
            'ldhName' => 'minimal.test',
            'entities' => [],
        ]);

        $result = $this->parser->parse($response);

        $this->assertInstanceOf(DomainResult::class, $result);
        $this->assertSame('minimal.test', $result->name);
        $this->assertNull($result->registrar);
        $this->assertEmpty($result->contacts);
    }

    public function testParseUnknownObjectClassFallsToDomain(): void
    {
        $response = self::makeResponse([
            'objectClassName' => 'unknown_type',
            'ldhName' => 'fallback.test',
        ]);

        $result = $this->parser->parse($response);
        $this->assertInstanceOf(DomainResult::class, $result);
    }
}
