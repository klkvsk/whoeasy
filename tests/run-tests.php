<?php

/**
 * Lightweight test runner for environments without ext-dom/xml.
 * Provides basic assert methods matching PHPUnit's API.
 *
 * Usage: php tests/run-tests.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

// Minimal assertion library
class AssertionFailure extends RuntimeException {}

function assertSame(mixed $expected, mixed $actual, string $msg = ''): void {
    if ($expected !== $actual) {
        $e = var_export($expected, true);
        $a = var_export($actual, true);
        throw new AssertionFailure($msg ?: "Expected $e, got $a");
    }
}

function assertEquals(mixed $expected, mixed $actual, string $msg = ''): void {
    if ($expected != $actual) {
        $e = var_export($expected, true);
        $a = var_export($actual, true);
        throw new AssertionFailure($msg ?: "Expected $e to equal $a");
    }
}

function assertInstanceOf(string $class, mixed $actual, string $msg = ''): void {
    if (!($actual instanceof $class)) {
        $type = get_debug_type($actual);
        throw new AssertionFailure($msg ?: "Expected instance of $class, got $type");
    }
}

function assertNotNull(mixed $actual, string $msg = ''): void {
    if ($actual === null) {
        throw new AssertionFailure($msg ?: "Expected non-null value");
    }
}

function assertNull(mixed $actual, string $msg = ''): void {
    if ($actual !== null) {
        throw new AssertionFailure($msg ?: "Expected null, got " . var_export($actual, true));
    }
}

function assertCount(int $expected, array|Countable $actual, string $msg = ''): void {
    $count = count($actual);
    if ($count !== $expected) {
        throw new AssertionFailure($msg ?: "Expected count $expected, got $count");
    }
}

function assertNotEmpty(mixed $actual, string $msg = ''): void {
    if (empty($actual)) {
        throw new AssertionFailure($msg ?: "Expected non-empty value");
    }
}

function assertEmpty(mixed $actual, string $msg = ''): void {
    if (!empty($actual)) {
        throw new AssertionFailure($msg ?: "Expected empty value");
    }
}

function assertContains(mixed $needle, array $haystack, string $msg = ''): void {
    if (!in_array($needle, $haystack, true)) {
        throw new AssertionFailure($msg ?: var_export($needle, true) . " not found in array");
    }
}

function assertStringContainsString(string $needle, string $haystack, string $msg = ''): void {
    if (!str_contains($haystack, $needle)) {
        throw new AssertionFailure($msg ?: "'$needle' not found in '$haystack'");
    }
}

// ========================
// Test definitions
// ========================

use Klkvsk\Whoeasy\Client\Rdap\RdapParser;
use Klkvsk\Whoeasy\Client\Rdap\RdapResponse;
use Klkvsk\Whoeasy\Parser\Data\AsnResult;
use Klkvsk\Whoeasy\Parser\Data\DomainResult;
use Klkvsk\Whoeasy\Parser\Data\IpResult;
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
use Klkvsk\Whoeasy\Registry\ServerRegistry;
use Klkvsk\Whoeasy\Registry\ServerInfo;
use Klkvsk\Whoeasy\Exception\UnsupportedQueryException;

function loadFixture(string $filename): array {
    $path = __DIR__ . '/Fixtures/rdap/' . $filename;
    return json_decode(file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
}

function makeResponse(array $json): RdapResponse {
    return new RdapResponse(
        server: 'https://test.rdap.example',
        url: 'https://test.rdap.example/test',
        httpCode: 200,
        json: $json,
        rawBody: json_encode($json),
    );
}

$tests = [];

// --- RdapParser Tests ---

$tests['RdapParser::parseDomainFixture'] = function() {
    $parser = new RdapParser();
    $json = loadFixture('domain-example.com.json');
    $result = $parser->parse(makeResponse($json));

    assertInstanceOf(DomainResult::class, $result);
    assertSame('EXAMPLE.COM', $result->name);
    assertStringContainsString('client delete prohibited', $result->status);
    assertNotNull($result->created);
    assertSame('1995-08-14', $result->created->format('Y-m-d'));
    assertNotNull($result->expires);
    assertSame('2025-08-13', $result->expires->format('Y-m-d'));
    assertNotNull($result->changed);
    assertCount(2, $result->nameservers);
    assertSame('a.iana-servers.net', $result->nameservers[0]);
    assertSame('b.iana-servers.net', $result->nameservers[1]);
    assertNotNull($result->registrar);
    assertSame('RESERVED-Internet Assigned Numbers Authority', $result->registrar->name);
    assertNotEmpty($result->contacts);
};

$tests['RdapParser::parseIpFixture'] = function() {
    $parser = new RdapParser();
    $json = loadFixture('ip-8.8.8.8.json');
    $result = $parser->parse(makeResponse($json));

    assertInstanceOf(IpResult::class, $result);
    assertSame('GOGL', $result->name);
    assertSame('8.8.8.0 - 8.8.8.255', $result->range);
    assertNotNull($result->created);
    assertNotNull($result->owner);
    assertSame('Google LLC', $result->owner->name);
    assertNotEmpty($result->contacts);
    assertSame('abuse', $result->contacts[0]->type);
    assertSame('network-abuse@google.com', $result->contacts[0]->email);
};

$tests['RdapParser::parseAsnFixture'] = function() {
    $parser = new RdapParser();
    $json = loadFixture('autnum-15169.json');
    $result = $parser->parse(makeResponse($json));

    assertInstanceOf(AsnResult::class, $result);
    assertSame('AS15169', $result->asn);
    assertSame('GOOGLE', $result->name);
    assertNotNull($result->created);
    assertNotNull($result->owner);
    assertSame('Google LLC', $result->owner->name);
    assertNotEmpty($result->contacts);
    assertSame('tech', $result->contacts[0]->type);
    assertSame('arin-contact@google.com', $result->contacts[0]->email);
};

$tests['RdapParser::parseMinimalDomain'] = function() {
    $parser = new RdapParser();
    $result = $parser->parse(makeResponse([
        'objectClassName' => 'domain',
        'ldhName' => 'minimal.test',
        'entities' => [],
    ]));

    assertInstanceOf(DomainResult::class, $result);
    assertSame('minimal.test', $result->name);
    assertNull($result->registrar);
    assertEmpty($result->contacts);
};

$tests['RdapParser::unknownObjectClassFallsToDomain'] = function() {
    $parser = new RdapParser();
    $result = $parser->parse(makeResponse([
        'objectClassName' => 'unknown_type',
        'ldhName' => 'fallback.test',
    ]));
    assertInstanceOf(DomainResult::class, $result);
};

// --- ResultMerger Tests ---

$tests['ResultMerger::rdapScalarFieldsTakePriority'] = function() {
    $merger = new ResultMerger();
    $rdap = new StructuredResult(queryType: QueryType::Domain,
        domain: new DomainInfo(name: 'example.com', registrar: 'RDAP Registrar', createdDate: '2020-01-01'));
    $whois = new StructuredResult(queryType: QueryType::Domain,
        domain: new DomainInfo(name: 'EXAMPLE.COM', registrar: 'WHOIS Registrar', createdDate: '2020-01-02'));

    $merged = $merger->merge($rdap, $whois);
    assertSame('example.com', $merged->domain->name);
    assertSame('RDAP Registrar', $merged->domain->registrar);
    assertSame('2020-01-01', $merged->domain->createdDate);
};

$tests['ResultMerger::whoisFillsNullFields'] = function() {
    $merger = new ResultMerger();
    $rdap = new StructuredResult(queryType: QueryType::Domain,
        domain: new DomainInfo(name: 'example.com'));
    $whois = new StructuredResult(queryType: QueryType::Domain,
        domain: new DomainInfo(name: 'EXAMPLE.COM', expiresDate: '2025-01-01', dnssec: 'signedDelegation'));

    $merged = $merger->merge($rdap, $whois);
    assertSame('example.com', $merged->domain->name);
    assertSame('2025-01-01', $merged->domain->expiresDate);
    assertSame('signedDelegation', $merged->domain->dnssec);
};

$tests['ResultMerger::statusArraysMergedWithDedup'] = function() {
    $merger = new ResultMerger();
    $rdap = new StructuredResult(queryType: QueryType::Domain,
        domain: new DomainInfo(status: ['active', 'client transfer prohibited']));
    $whois = new StructuredResult(queryType: QueryType::Domain,
        domain: new DomainInfo(status: ['active', 'server delete prohibited']));

    $merged = $merger->merge($rdap, $whois);
    assertCount(3, $merged->domain->status);
    assertContains('active', $merged->domain->status);
    assertContains('client transfer prohibited', $merged->domain->status);
    assertContains('server delete prohibited', $merged->domain->status);
};

$tests['ResultMerger::nameserversDeduplicatedByHostname'] = function() {
    $merger = new ResultMerger();
    $rdap = new StructuredResult(queryType: QueryType::Domain,
        domain: new DomainInfo(nameservers: [new Nameserver('ns1.example.com')]));
    $whois = new StructuredResult(queryType: QueryType::Domain,
        domain: new DomainInfo(nameservers: [
            new Nameserver('NS1.EXAMPLE.COM', ipv4: '1.2.3.4'),
            new Nameserver('ns2.example.com'),
        ]));

    $merged = $merger->merge($rdap, $whois);
    assertCount(2, $merged->domain->nameservers);
    assertSame('ns1.example.com', $merged->domain->nameservers[0]->hostname);
    assertSame('1.2.3.4', $merged->domain->nameservers[0]->ipv4);
};

$tests['ResultMerger::contactsMergedByType'] = function() {
    $merger = new ResultMerger();
    $rdap = new StructuredResult(queryType: QueryType::Domain,
        domain: new DomainInfo(contacts: [
            new Contact(type: ContactType::Tech, name: 'RDAP Tech', email: 'tech@rdap.test'),
        ]));
    $whois = new StructuredResult(queryType: QueryType::Domain,
        domain: new DomainInfo(contacts: [
            new Contact(type: ContactType::Tech, name: 'WHOIS Tech', phone: '+1-555-0000'),
            new Contact(type: ContactType::Registrant, name: 'Owner', email: 'owner@test.com'),
        ]));

    $merged = $merger->merge($rdap, $whois);
    assertCount(2, $merged->domain->contacts);

    $tech = array_values(array_filter($merged->domain->contacts, fn(Contact $c) => $c->type === ContactType::Tech))[0];
    assertSame('RDAP Tech', $tech->name);
    assertSame('tech@rdap.test', $tech->email);
    assertSame('+1-555-0000', $tech->phone);

    $reg = array_values(array_filter($merged->domain->contacts, fn(Contact $c) => $c->type === ContactType::Registrant))[0];
    assertSame('Owner', $reg->name);
};

$tests['ResultMerger::mergeRegistrarInfo'] = function() {
    $merger = new ResultMerger();
    $rdap = new StructuredResult(queryType: QueryType::Domain,
        domain: new DomainInfo(registrarInfo: new Registrar(name: 'RDAP Inc')));
    $whois = new StructuredResult(queryType: QueryType::Domain,
        domain: new DomainInfo(registrarInfo: new Registrar(name: 'WHOIS Inc', url: 'https://registrar.test', abuseEmail: 'abuse@registrar.test')));

    $merged = $merger->merge($rdap, $whois);
    assertSame('RDAP Inc', $merged->domain->registrarInfo->name);
    assertSame('https://registrar.test', $merged->domain->registrarInfo->url);
    assertSame('abuse@registrar.test', $merged->domain->registrarInfo->abuseEmail);
};

$tests['ResultMerger::mergeIpInfo'] = function() {
    $merger = new ResultMerger();
    $rdap = new StructuredResult(queryType: QueryType::Ipv4,
        ip: new IpInfo(range: '8.8.8.0 - 8.8.8.255', networkName: 'GOGL'));
    $whois = new StructuredResult(queryType: QueryType::Ipv4,
        ip: new IpInfo(range: '8.8.8.0/24', country: 'US', description: 'Google DNS'));

    $merged = $merger->merge($rdap, $whois);
    assertSame('8.8.8.0 - 8.8.8.255', $merged->ip->range);
    assertSame('GOGL', $merged->ip->networkName);
    assertSame('US', $merged->ip->country);
    assertSame('Google DNS', $merged->ip->description);
};

$tests['ResultMerger::mergeAsnInfo'] = function() {
    $merger = new ResultMerger();
    $rdap = new StructuredResult(queryType: QueryType::Asn,
        asn: new AsnInfo(asn: 15169, name: 'GOOGLE'));
    $whois = new StructuredResult(queryType: QueryType::Asn,
        asn: new AsnInfo(asn: 15169, name: 'Google', country: 'US', description: 'Google LLC'));

    $merged = $merger->merge($rdap, $whois);
    assertSame(15169, $merged->asn->asn);
    assertSame('GOOGLE', $merged->asn->name);
    assertSame('US', $merged->asn->country);
    assertSame('Google LLC', $merged->asn->description);
};

$tests['ResultMerger::nullDomainFallsThrough'] = function() {
    $merger = new ResultMerger();
    $rdap = new StructuredResult(queryType: QueryType::Domain, domain: null);
    $whois = new StructuredResult(queryType: QueryType::Domain,
        domain: new DomainInfo(name: 'only-whois.com'));

    $merged = $merger->merge($rdap, $whois);
    assertSame('only-whois.com', $merged->domain->name);
};

// --- ServerRegistry Tests ---

$tests['ServerRegistry::resolveDomainCom'] = function() {
    $registry = new ServerRegistry();
    $info = $registry->resolve('example.com');

    assertSame(QueryType::Domain, $info->queryType);
    assertSame('whois.verisign-grs.com', $info->whoisServer);
    assertNotNull($info->rdapUrl);
    assertStringContainsString('verisign', $info->rdapUrl);
};

$tests['ServerRegistry::resolveDomainOrg'] = function() {
    $registry = new ServerRegistry();
    $info = $registry->resolve('example.org');

    assertSame(QueryType::Domain, $info->queryType);
    assertSame('whois.pir.org', $info->whoisServer);
    assertNotNull($info->rdapUrl);
};

$tests['ServerRegistry::resolveCcTld'] = function() {
    $registry = new ServerRegistry();
    $info = $registry->resolve('example.de');

    assertSame(QueryType::Domain, $info->queryType);
    assertSame('whois.denic.de', $info->whoisServer);
};

$tests['ServerRegistry::resolveIpv4'] = function() {
    $registry = new ServerRegistry();
    $info = $registry->resolve('8.8.8.8');

    assertSame(QueryType::Ipv4, $info->queryType);
    assertNotNull($info->whoisServer);
};

$tests['ServerRegistry::resolveIpv6'] = function() {
    $registry = new ServerRegistry();
    $info = $registry->resolve('2001:4860:4860::8888');

    assertSame(QueryType::Ipv6, $info->queryType);
    assertNotNull($info->whoisServer);
};

$tests['ServerRegistry::resolveAsn'] = function() {
    $registry = new ServerRegistry();
    $info = $registry->resolve('AS15169');

    assertSame(QueryType::Asn, $info->queryType);
    assertNotNull($info->whoisServer);
};

$tests['ServerRegistry::detectQueryType'] = function() {
    assertSame(QueryType::Domain, ServerRegistry::detectQueryType('example.com'));
    assertSame(QueryType::Ipv4, ServerRegistry::detectQueryType('192.168.1.1'));
    assertSame(QueryType::Ipv6, ServerRegistry::detectQueryType('2001:db8::1'));
    assertSame(QueryType::Asn, ServerRegistry::detectQueryType('AS12345'));
};

$tests['ServerRegistry::unsupportedQueryThrows'] = function() {
    $registry = new ServerRegistry();
    $thrown = false;
    try {
        $registry->resolve('!!!invalid!!!');
    } catch (UnsupportedQueryException) {
        $thrown = true;
    }
    assertSame(true, $thrown, 'Expected UnsupportedQueryException');
};

$tests['ServerRegistry::lookupTld'] = function() {
    $registry = new ServerRegistry();
    $result = $registry->lookupTld('com');
    assertNotNull($result);
    assertSame('whois.verisign-grs.com', $result[0]);

    $missing = $registry->lookupTld('zzzzzznonexistent');
    assertNull($missing);
};

// ========================
// Run tests
// ========================

$totalTests = 0;
$passedTests = 0;
$failedTests = 0;
$errors = [];

echo "WhoisParser v2 - Test Suite\n";
echo str_repeat('=', 60) . "\n";

foreach ($tests as $name => $fn) {
    $totalTests++;
    try {
        $fn();
        $passedTests++;
        echo "  PASS  $name\n";
    } catch (Throwable $e) {
        $failedTests++;
        $errors[] = "$name: " . $e->getMessage();
        echo "  FAIL  $name: " . $e->getMessage() . "\n";
    }
}

echo str_repeat('-', 60) . "\n";
echo "Results: $totalTests tests, $passedTests passed, $failedTests failed\n";

if ($failedTests > 0) {
    echo "\nFailed tests:\n";
    foreach ($errors as $error) {
        echo "  - $error\n";
    }
    exit(1);
}

echo "\nAll tests passed!\n";
exit(0);
