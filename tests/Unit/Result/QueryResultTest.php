<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Tests\Unit\Result;

use Klkvsk\Whoeasy\Client\Exception\NotFoundException;
use Klkvsk\Whoeasy\Client\Exception\RateLimitException;
use Klkvsk\Whoeasy\Result\Hop\RdapHop;
use Klkvsk\Whoeasy\Result\Hop\WhoisHop;
use Klkvsk\Whoeasy\Result\Info\AsnInfo;
use Klkvsk\Whoeasy\Result\Info\DomainInfo;
use Klkvsk\Whoeasy\Result\Info\Field\Contact;
use Klkvsk\Whoeasy\Result\Info\Field\ContactType;
use Klkvsk\Whoeasy\Result\Info\Field\Nameserver;
use Klkvsk\Whoeasy\Result\Info\Field\Registrar;
use Klkvsk\Whoeasy\Result\Info\IpInfo;
use Klkvsk\Whoeasy\Result\ProtocolResult;
use Klkvsk\Whoeasy\Result\QueryResult;
use PHPUnit\Framework\TestCase;

class QueryResultTest extends TestCase
{
    public function testDomainResultToArray(): void
    {
        $info = new DomainInfo(
            name: 'example.com',
            registrar: new Registrar(
                name: 'Example Registrar',
                ianaId: '1234',
                url: 'https://example-registrar.com',
                abuseEmail: 'abuse@example-registrar.com',
            ),
            createdDate: '2000-01-01T00:00:00Z',
            updatedDate: '2024-01-01T00:00:00Z',
            expiresDate: '2025-01-01T00:00:00Z',
            status: ['clientTransferProhibited'],
            nameservers: [
                new Nameserver('ns1.example.com', '1.2.3.4'),
                new Nameserver('ns2.example.com'),
            ],
            contacts: [
                new Contact(
                    type: ContactType::Registrant,
                    name: 'John Doe',
                    email: 'john@example.com',
                ),
            ],
        );

        $result = new QueryResult(
            info: $info,
            whois: new ProtocolResult(
                info: $info,
                hops: [
                    new WhoisHop(
                        server: 'whois.verisign-grs.com',
                        query: 'example.com',
                        rawText: 'Domain Name: EXAMPLE.COM',
                        info: new DomainInfo(name: 'EXAMPLE.COM'),
                    ),
                    new WhoisHop(
                        server: 'whois.example-registrar.com',
                        query: 'example.com',
                        rawText: 'Domain Name: example.com',
                        info: $info,
                    ),
                ],
            ),
        );

        $array = $result->toArray();

        $this->assertSame('example.com', $array['info']['name']);
        $this->assertSame('Example Registrar', $array['info']['registrar']['name']);
        $this->assertSame('1234', $array['info']['registrar']['ianaId']);
        $this->assertCount(2, $array['info']['nameservers']);
        $this->assertSame('ns1.example.com', $array['info']['nameservers'][0]['hostname']);
        $this->assertSame('1.2.3.4', $array['info']['nameservers'][0]['ipv4']);
        $this->assertArrayNotHasKey('ipv6', $array['info']['nameservers'][0]);
        $this->assertCount(1, $array['info']['contacts']);
        $this->assertSame('registrant', $array['info']['contacts'][0]['type']);

        // Check whois hops
        $this->assertCount(2, $array['whois']['hops']);
        $this->assertSame('whois.verisign-grs.com', $array['whois']['hops'][0]['server']);
        $this->assertSame('whois.example-registrar.com', $array['whois']['hops'][1]['server']);
    }

    public function testDeterministicOutput(): void
    {
        $makeResult = fn () => new QueryResult(
            info: new DomainInfo(
                name: 'example.com',
                status: ['ok'],
                nameservers: [new Nameserver('ns1.example.com')],
            ),
        );

        $this->assertSame(
            json_encode($makeResult()->toArray()),
            json_encode($makeResult()->toArray()),
        );
    }

    public function testIpInfoToArray(): void
    {
        $info = new IpInfo(
            range: '8.8.8.0/24',
            networkName: 'GOOGLE',
            country: 'US',
        );

        $array = $info->toArray();
        $this->assertSame('8.8.8.0/24', $array['range']);
        $this->assertSame('GOOGLE', $array['networkName']);
    }

    public function testAsnInfoToArray(): void
    {
        $info = new AsnInfo(
            asn: 15169,
            name: 'GOOGLE',
            country: 'US',
        );

        $array = $info->toArray();
        $this->assertSame(15169, $array['asn']);
        $this->assertSame('GOOGLE', $array['name']);
    }

    public function testHasRetryableErrors(): void
    {
        $result = new QueryResult(
            whois: new ProtocolResult(
                hops: [
                    new WhoisHop(
                        server: 'whois.example.com',
                        query: 'example.com',
                        rawText: '',
                        error: new RateLimitException('rate limited'),
                    ),
                ],
            ),
        );

        $this->assertTrue($result->hasRetryableErrors());
    }

    public function testHasNoRetryableErrors(): void
    {
        $result = new QueryResult(
            info: new DomainInfo(),
            whois: new ProtocolResult(
                info: new DomainInfo(),
                hops: [
                    new WhoisHop(
                        server: 'whois.example.com',
                        query: 'example.com',
                        rawText: 'Domain Name: example.com',
                    ),
                ],
            ),
        );

        $this->assertFalse($result->hasRetryableErrors());
    }

    public function testIsNonExistingDomain(): void
    {
        $result = new QueryResult(
            rdap: new ProtocolResult(
                hops: [
                    new RdapHop(
                        server: 'rdap.verisign.com',
                        query: 'nonexistent.com',
                        url: 'https://rdap.verisign.com/com/v1/domain/nonexistent.com',
                        json: null,
                        rawBody: '',
                        error: new NotFoundException('not found'),
                    ),
                ],
            ),
        );

        $this->assertTrue($result->isNotFound());
    }

    public function testIsNotNonExistingDomain(): void
    {
        $result = new QueryResult(
            info: new DomainInfo(),
        );

        $this->assertFalse($result->isNotFound());
    }
}
