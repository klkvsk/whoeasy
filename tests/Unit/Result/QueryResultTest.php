<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Tests\Unit\Result;

use Klkvsk\Whoeasy\Enum\QueryType;
use Klkvsk\Whoeasy\Parser\Data\ContactType;
use Klkvsk\Whoeasy\Result\AsnInfo;
use Klkvsk\Whoeasy\Result\Contact;
use Klkvsk\Whoeasy\Result\DomainInfo;
use Klkvsk\Whoeasy\Result\HopResponses;
use Klkvsk\Whoeasy\Result\IpInfo;
use Klkvsk\Whoeasy\Result\Nameserver;
use Klkvsk\Whoeasy\Result\QueryResult;
use Klkvsk\Whoeasy\Result\RawResponse;
use Klkvsk\Whoeasy\Result\Registrar;
use Klkvsk\Whoeasy\Result\StructuredResult;
use PHPUnit\Framework\TestCase;

class QueryResultTest extends TestCase
{
    public function testDomainResultToArray(): void
    {
        $result = new QueryResult(
            query: 'example.com',
            result: new StructuredResult(
                queryType: QueryType::Domain,
                domain: new DomainInfo(
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
                ),
            ),
            whois: new HopResponses(
                nonAuth: new RawResponse(
                    server: 'whois.verisign-grs.com',
                    text: 'Domain Name: EXAMPLE.COM',
                ),
                auth: new RawResponse(
                    server: 'whois.example-registrar.com',
                    text: 'Domain Name: example.com',
                ),
            ),
        );

        $array = $result->toArray();

        $this->assertSame('example.com', $array['query']);
        $this->assertSame('domain', $array['result']['queryType']);
        $this->assertSame('example.com', $array['result']['domain']['name']);
        $this->assertSame('Example Registrar', $array['result']['domain']['registrar']['name']);
        $this->assertSame('1234', $array['result']['domain']['registrar']['ianaId']);
        $this->assertCount(2, $array['result']['domain']['nameservers']);
        $this->assertSame('ns1.example.com', $array['result']['domain']['nameservers'][0]['hostname']);
        $this->assertSame('1.2.3.4', $array['result']['domain']['nameservers'][0]['ipv4']);
        $this->assertArrayNotHasKey('ipv6', $array['result']['domain']['nameservers'][0]);
        $this->assertCount(1, $array['result']['domain']['contacts']);
        $this->assertSame('registrant', $array['result']['domain']['contacts'][0]['type']);
    }

    public function testDeterministicOutput(): void
    {
        $makeResult = fn () => new QueryResult(
            query: 'example.com',
            result: new StructuredResult(
                queryType: QueryType::Domain,
                domain: new DomainInfo(
                    name: 'example.com',
                    status: ['ok'],
                    nameservers: [new Nameserver('ns1.example.com')],
                ),
            ),
        );

        $this->assertSame(
            json_encode($makeResult()->toArray()),
            json_encode($makeResult()->toArray()),
        );
    }

    public function testIpResultToArray(): void
    {
        $result = new StructuredResult(
            queryType: QueryType::Ipv4,
            ip: new IpInfo(
                range: '8.8.8.0/24',
                networkName: 'GOOGLE',
                country: 'US',
            ),
        );

        $array = $result->toArray();
        $this->assertSame('ipv4', $array['queryType']);
        $this->assertSame('8.8.8.0/24', $array['ip']['range']);
        $this->assertSame('GOOGLE', $array['ip']['networkName']);
    }

    public function testAsnResultToArray(): void
    {
        $result = new StructuredResult(
            queryType: QueryType::Asn,
            asn: new AsnInfo(
                asn: 15169,
                name: 'GOOGLE',
                country: 'US',
            ),
        );

        $array = $result->toArray();
        $this->assertSame('asn', $array['queryType']);
        $this->assertSame(15169, $array['asn']['asn']);
        $this->assertSame('GOOGLE', $array['asn']['name']);
    }
}
