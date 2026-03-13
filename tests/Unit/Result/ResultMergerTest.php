<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Tests\Unit\Result;

use Klkvsk\Whoeasy\Enum\ContactType;
use Klkvsk\Whoeasy\Enum\QueryType;
use Klkvsk\Whoeasy\Result\AsnInfo;
use Klkvsk\Whoeasy\Result\Contact;
use Klkvsk\Whoeasy\Result\DomainInfo;
use Klkvsk\Whoeasy\Result\IpInfo;
use Klkvsk\Whoeasy\Result\Nameserver;
use Klkvsk\Whoeasy\Result\Registrar;
use Klkvsk\Whoeasy\Result\ResultMerger;
use Klkvsk\Whoeasy\Result\StructuredResult;
use PHPUnit\Framework\TestCase;

class ResultMergerTest extends TestCase
{
    private ResultMerger $merger;

    protected function setUp(): void
    {
        $this->merger = new ResultMerger();
    }

    public function testRdapScalarFieldsTakePriority(): void
    {
        $rdap = new StructuredResult(
            queryType: QueryType::Domain,
            domain: new DomainInfo(name: 'example.com', registrar: 'RDAP Registrar', createdDate: '2020-01-01'),
        );
        $whois = new StructuredResult(
            queryType: QueryType::Domain,
            domain: new DomainInfo(name: 'EXAMPLE.COM', registrar: 'WHOIS Registrar', createdDate: '2020-01-02'),
        );

        $merged = $this->merger->merge($rdap, $whois);

        $this->assertSame('example.com', $merged->domain->name);
        $this->assertSame('RDAP Registrar', $merged->domain->registrar);
        $this->assertSame('2020-01-01', $merged->domain->createdDate);
    }

    public function testWhoisFillsNullScalarFields(): void
    {
        $rdap = new StructuredResult(
            queryType: QueryType::Domain,
            domain: new DomainInfo(name: 'example.com'),
        );
        $whois = new StructuredResult(
            queryType: QueryType::Domain,
            domain: new DomainInfo(
                name: 'EXAMPLE.COM',
                expiresDate: '2025-01-01',
                dnssec: 'signedDelegation',
            ),
        );

        $merged = $this->merger->merge($rdap, $whois);

        $this->assertSame('example.com', $merged->domain->name); // RDAP priority
        $this->assertSame('2025-01-01', $merged->domain->expiresDate); // filled from WHOIS
        $this->assertSame('signedDelegation', $merged->domain->dnssec); // filled from WHOIS
    }

    public function testStatusArraysMergedWithDedup(): void
    {
        $rdap = new StructuredResult(
            queryType: QueryType::Domain,
            domain: new DomainInfo(status: ['active', 'client transfer prohibited']),
        );
        $whois = new StructuredResult(
            queryType: QueryType::Domain,
            domain: new DomainInfo(status: ['active', 'server delete prohibited']),
        );

        $merged = $this->merger->merge($rdap, $whois);

        $this->assertCount(3, $merged->domain->status);
        $this->assertContains('active', $merged->domain->status);
        $this->assertContains('client transfer prohibited', $merged->domain->status);
        $this->assertContains('server delete prohibited', $merged->domain->status);
    }

    public function testNameserversDeduplicatedByHostname(): void
    {
        $rdap = new StructuredResult(
            queryType: QueryType::Domain,
            domain: new DomainInfo(nameservers: [
                new Nameserver('ns1.example.com'),
            ]),
        );
        $whois = new StructuredResult(
            queryType: QueryType::Domain,
            domain: new DomainInfo(nameservers: [
                new Nameserver('NS1.EXAMPLE.COM', ipv4: '1.2.3.4'),
                new Nameserver('ns2.example.com'),
            ]),
        );

        $merged = $this->merger->merge($rdap, $whois);

        $this->assertCount(2, $merged->domain->nameservers);
        // ns1 should have IP filled from WHOIS
        $ns1 = $merged->domain->nameservers[0];
        $this->assertSame('ns1.example.com', $ns1->hostname);
        $this->assertSame('1.2.3.4', $ns1->ipv4);
    }

    public function testContactsMergedByType(): void
    {
        $rdap = new StructuredResult(
            queryType: QueryType::Domain,
            domain: new DomainInfo(contacts: [
                new Contact(type: ContactType::Tech, name: 'RDAP Tech', email: 'tech@rdap.test'),
            ]),
        );
        $whois = new StructuredResult(
            queryType: QueryType::Domain,
            domain: new DomainInfo(contacts: [
                new Contact(type: ContactType::Tech, name: 'WHOIS Tech', phone: '+1-555-0000'),
                new Contact(type: ContactType::Registrant, name: 'Owner', email: 'owner@test.com'),
            ]),
        );

        $merged = $this->merger->merge($rdap, $whois);

        $this->assertCount(2, $merged->domain->contacts);

        // Tech contact: RDAP fields + WHOIS phone fill
        $tech = array_values(array_filter(
            $merged->domain->contacts,
            fn(Contact $c) => $c->type === ContactType::Tech,
        ))[0];
        $this->assertSame('RDAP Tech', $tech->name);
        $this->assertSame('tech@rdap.test', $tech->email);
        $this->assertSame('+1-555-0000', $tech->phone);

        // Registrant: from WHOIS only
        $registrant = array_values(array_filter(
            $merged->domain->contacts,
            fn(Contact $c) => $c->type === ContactType::Registrant,
        ))[0];
        $this->assertSame('Owner', $registrant->name);
    }

    public function testMergeWithOneNullDomain(): void
    {
        $rdap = new StructuredResult(queryType: QueryType::Domain, domain: null);
        $whois = new StructuredResult(
            queryType: QueryType::Domain,
            domain: new DomainInfo(name: 'only-whois.com'),
        );

        $merged = $this->merger->merge($rdap, $whois);
        $this->assertSame('only-whois.com', $merged->domain->name);
    }

    public function testMergeRegistrarInfo(): void
    {
        $rdap = new StructuredResult(
            queryType: QueryType::Domain,
            domain: new DomainInfo(registrarInfo: new Registrar(name: 'RDAP Inc')),
        );
        $whois = new StructuredResult(
            queryType: QueryType::Domain,
            domain: new DomainInfo(registrarInfo: new Registrar(
                name: 'WHOIS Inc',
                url: 'https://registrar.test',
                abuseEmail: 'abuse@registrar.test',
            )),
        );

        $merged = $this->merger->merge($rdap, $whois);

        $this->assertSame('RDAP Inc', $merged->domain->registrarInfo->name);
        $this->assertSame('https://registrar.test', $merged->domain->registrarInfo->url);
        $this->assertSame('abuse@registrar.test', $merged->domain->registrarInfo->abuseEmail);
    }

    public function testMergeIpInfo(): void
    {
        $rdap = new StructuredResult(
            queryType: QueryType::Ipv4,
            ip: new IpInfo(range: '8.8.8.0 - 8.8.8.255', networkName: 'GOGL'),
        );
        $whois = new StructuredResult(
            queryType: QueryType::Ipv4,
            ip: new IpInfo(range: '8.8.8.0/24', country: 'US', description: 'Google DNS'),
        );

        $merged = $this->merger->merge($rdap, $whois);

        $this->assertSame('8.8.8.0 - 8.8.8.255', $merged->ip->range); // RDAP priority
        $this->assertSame('GOGL', $merged->ip->networkName);
        $this->assertSame('US', $merged->ip->country); // from WHOIS
        $this->assertSame('Google DNS', $merged->ip->description); // from WHOIS
    }

    public function testMergeAsnInfo(): void
    {
        $rdap = new StructuredResult(
            queryType: QueryType::Asn,
            asn: new AsnInfo(asn: 15169, name: 'GOOGLE'),
        );
        $whois = new StructuredResult(
            queryType: QueryType::Asn,
            asn: new AsnInfo(asn: 15169, name: 'Google', country: 'US', description: 'Google LLC'),
        );

        $merged = $this->merger->merge($rdap, $whois);

        $this->assertSame(15169, $merged->asn->asn);
        $this->assertSame('GOOGLE', $merged->asn->name); // RDAP priority
        $this->assertSame('US', $merged->asn->country);
        $this->assertSame('Google LLC', $merged->asn->description);
    }
}
