<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Tests\Unit\Result;

use Klkvsk\Whoeasy\Result\Info\AsnInfo;
use Klkvsk\Whoeasy\Result\Info\DomainInfo;
use Klkvsk\Whoeasy\Result\Info\Field\Contact;
use Klkvsk\Whoeasy\Result\Info\Field\ContactType;
use Klkvsk\Whoeasy\Result\Info\Field\Nameserver;
use Klkvsk\Whoeasy\Result\Info\Field\Registrar;
use Klkvsk\Whoeasy\Result\Info\IpInfo;
use Klkvsk\Whoeasy\Result\ResultMerger;
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
        $rdap = new DomainInfo(name: 'example.com', registrar: new Registrar(name: 'RDAP Registrar'), createdDate: '2020-01-01');
        $whois = new DomainInfo(name: 'EXAMPLE.COM', registrar: new Registrar(name: 'WHOIS Registrar'), createdDate: '2020-01-02');

        $merged = $this->merger->merge($rdap, $whois);

        $this->assertInstanceOf(DomainInfo::class, $merged);
        $this->assertSame('example.com', $merged->name);
        $this->assertSame('RDAP Registrar', $merged->registrar->name);
        $this->assertSame('2020-01-01', $merged->createdDate);
    }

    public function testWhoisFillsNullScalarFields(): void
    {
        $rdap = new DomainInfo(name: 'example.com');
        $whois = new DomainInfo(
            name: 'EXAMPLE.COM',
            expiresDate: '2025-01-01',
            dnssec: 'signedDelegation',
        );

        $merged = $this->merger->merge($rdap, $whois);

        $this->assertInstanceOf(DomainInfo::class, $merged);
        $this->assertSame('example.com', $merged->name); // RDAP priority
        $this->assertSame('2025-01-01', $merged->expiresDate); // filled from WHOIS
        $this->assertSame('signedDelegation', $merged->dnssec); // filled from WHOIS
    }

    public function testStatusArraysMergedWithDedup(): void
    {
        $rdap = new DomainInfo(status: ['active', 'client transfer prohibited']);
        $whois = new DomainInfo(status: ['active', 'server delete prohibited']);

        $merged = $this->merger->merge($rdap, $whois);

        $this->assertInstanceOf(DomainInfo::class, $merged);
        $this->assertCount(3, $merged->status);
        $this->assertContains('active', $merged->status);
        $this->assertContains('client transfer prohibited', $merged->status);
        $this->assertContains('server delete prohibited', $merged->status);
    }

    public function testNameserversDeduplicatedByHostname(): void
    {
        $rdap = new DomainInfo(nameservers: [
            new Nameserver('ns1.example.com'),
        ]);
        $whois = new DomainInfo(nameservers: [
            new Nameserver('NS1.EXAMPLE.COM', ipv4: '1.2.3.4'),
            new Nameserver('ns2.example.com'),
        ]);

        $merged = $this->merger->merge($rdap, $whois);

        $this->assertInstanceOf(DomainInfo::class, $merged);
        $this->assertCount(2, $merged->nameservers);
        // ns1 should have IP filled from WHOIS
        $ns1 = $merged->nameservers[0];
        $this->assertSame('ns1.example.com', $ns1->hostname);
        $this->assertSame('1.2.3.4', $ns1->ipv4);
    }

    public function testContactsMergedByType(): void
    {
        // When same-type contacts have conflicting non-null fields (different names),
        // they are preserved as distinct contacts
        $rdap = new DomainInfo(contacts: [
            new Contact(type: ContactType::Tech, name: 'RDAP Tech', email: 'tech@rdap.test'),
        ]);
        $whois = new DomainInfo(contacts: [
            new Contact(type: ContactType::Tech, name: 'WHOIS Tech', phone: '+1-555-0000'),
            new Contact(type: ContactType::Registrant, name: 'Owner', email: 'owner@test.com'),
        ]);

        $merged = $this->merger->merge($rdap, $whois);

        $this->assertInstanceOf(DomainInfo::class, $merged);
        // 3 contacts: RDAP tech, WHOIS tech (distinct names), WHOIS registrant
        $this->assertCount(3, $merged->contacts);

        $techs = array_values(array_filter(
            $merged->contacts,
            fn(Contact $c) => $c->type === ContactType::Tech,
        ));
        $this->assertCount(2, $techs);
        $this->assertSame('RDAP Tech', $techs[0]->name);
        $this->assertSame('tech@rdap.test', $techs[0]->email);
        $this->assertSame('WHOIS Tech', $techs[1]->name);
        $this->assertSame('+1-555-0000', $techs[1]->phone);

        // Registrant: from WHOIS only
        $registrant = array_values(array_filter(
            $merged->contacts,
            fn(Contact $c) => $c->type === ContactType::Registrant,
        ))[0];
        $this->assertSame('Owner', $registrant->name);
    }

    public function testContactsSubsetMerged(): void
    {
        // When one contact is a subset of another (compatible non-null fields),
        // they are merged with primary winning on conflicts
        $rdap = new DomainInfo(contacts: [
            new Contact(type: ContactType::Tech, name: 'Tech Support', email: 'tech@test.com'),
        ]);
        $whois = new DomainInfo(contacts: [
            new Contact(type: ContactType::Tech, name: 'Tech Support', phone: '+1-555-0000'),
        ]);

        $merged = $this->merger->merge($rdap, $whois);

        $this->assertInstanceOf(DomainInfo::class, $merged);
        $this->assertCount(1, $merged->contacts);
        $tech = $merged->contacts[0];
        $this->assertSame('Tech Support', $tech->name);
        $this->assertSame('tech@test.com', $tech->email);   // from RDAP
        $this->assertSame('+1-555-0000', $tech->phone);     // filled from WHOIS
    }

    public function testMergeWithSingleItem(): void
    {
        $whois = new DomainInfo(name: 'only-whois.com');

        $merged = $this->merger->mergeAll($whois);
        $this->assertInstanceOf(DomainInfo::class, $merged);
        $this->assertSame('only-whois.com', $merged->name);
    }

    public function testMergeRegistrarInfo(): void
    {
        $rdap = new DomainInfo(registrar: new Registrar(name: 'RDAP Inc'));
        $whois = new DomainInfo(registrar: new Registrar(
            name: 'WHOIS Inc',
            url: 'https://registrar.test',
            abuseEmail: 'abuse@registrar.test',
        ));

        $merged = $this->merger->merge($rdap, $whois);

        $this->assertInstanceOf(DomainInfo::class, $merged);
        $this->assertSame('RDAP Inc', $merged->registrar->name);
        $this->assertSame('https://registrar.test', $merged->registrar->url);
        $this->assertSame('abuse@registrar.test', $merged->registrar->abuseEmail);
    }

    public function testMergeIpInfo(): void
    {
        $rdap = new IpInfo(range: '8.8.8.0 - 8.8.8.255', networkName: 'GOGL');
        $whois = new IpInfo(range: '8.8.8.0/24', country: 'US', description: 'Google DNS');

        $merged = $this->merger->merge($rdap, $whois);

        $this->assertInstanceOf(IpInfo::class, $merged);
        $this->assertSame('8.8.8.0 - 8.8.8.255', $merged->range); // RDAP priority
        $this->assertSame('GOGL', $merged->networkName);
        $this->assertSame('US', $merged->country); // from WHOIS
        $this->assertSame('Google DNS', $merged->description); // from WHOIS
    }

    public function testMergeAsnInfo(): void
    {
        $rdap = new AsnInfo(asn: 15169, name: 'GOOGLE');
        $whois = new AsnInfo(asn: 15169, name: 'Google', country: 'US', description: 'Google LLC');

        $merged = $this->merger->merge($rdap, $whois);

        $this->assertInstanceOf(AsnInfo::class, $merged);
        $this->assertSame(15169, $merged->asn);
        $this->assertSame('GOOGLE', $merged->name); // RDAP priority
        $this->assertSame('US', $merged->country);
        $this->assertSame('Google LLC', $merged->description);
    }
}
