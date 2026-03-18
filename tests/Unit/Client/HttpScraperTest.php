<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Tests\Unit\Client;

use Klkvsk\Whoeasy\Client\Whois\HttpScraper;
use Klkvsk\Whoeasy\Exception\NotScrapeableException;
use PHPUnit\Framework\TestCase;

class HttpScraperTest extends TestCase
{
    public function testRdapToWhois(): void
    {
        $rdapJson = json_encode([
            'ldhName' => 'example.ch',
            'status' => ['active', 'locked'],
            'events' => [
                ['eventAction' => 'registration', 'eventDate' => '2000-01-01T00:00:00Z'],
                ['eventAction' => 'last changed', 'eventDate' => '2023-06-15T12:00:00Z'],
            ],
            'entities' => [
                [
                    'roles' => ['registrant'],
                    'vcardArray' => [
                        'vcard',
                        [
                            ['version', [], 'text', '4.0'],
                            ['fn', [], 'text', 'Example AG'],
                            ['adr', [], 'text', ['', '', 'Bahnhofstrasse 1', 'Zurich', '', '8001', 'CH']],
                        ],
                    ],
                    'url' => 'https://example.ch',
                ],
            ],
            'nameservers' => [
                ['ldhName' => 'ns1.example.ch'],
                ['ldhName' => 'ns2.example.ch'],
            ],
        ]);

        $result = HttpScraper::process('ch', $rdapJson);

        $this->assertStringContainsString('domain: example.ch', $result);
        $this->assertStringContainsString('status: active, locked', $result);
        $this->assertStringContainsString('registration date: 2000-01-01T00:00:00Z', $result);
        $this->assertStringContainsString('registrant name: Example AG', $result);
        $this->assertStringContainsString('nameserver: ns1.example.ch', $result);
        $this->assertStringContainsString('nameserver: ns2.example.ch', $result);
    }

    public function testPhAvailable(): void
    {
        $html = '<html><body>Domain is available.</body></html>';
        $result = HttpScraper::process('ph', $html);
        $this->assertSame('Domain is available.', $result);
    }

    public function testPhRegistered(): void
    {
        $html = '<html><body><pre>Domain Name: example.ph
Registrar: Some Registrar
Created: 2020-01-01</pre></body></html>';

        $result = HttpScraper::process('ph', $html);
        $this->assertStringContainsString('Domain Name: example.ph', $result);
        $this->assertStringContainsString('Registrar: Some Registrar', $result);
    }

    public function testPaAvailable(): void
    {
        $html = '<html><body>The domain doesn\'t exist</body></html>';
        $result = HttpScraper::process('pa', $html);
        $this->assertSame('Domain is available.', $result);
    }

    public function testPaRegistered(): void
    {
        $html = '<html><body><ul>
<li>Domain Name: example.pa</li>
<li>Registrar: NIC Panama</li>
<li>Created: 2020-01-01</li>
</ul></body></html>';

        $result = HttpScraper::process('pa', $html);
        $this->assertStringContainsString('Domain Name: example.pa', $result);
        $this->assertStringContainsString('Registrar: NIC Panama', $result);
        $this->assertStringContainsString('Created: 2020-01-01', $result);
    }

    public function testPaNoData(): void
    {
        $html = '<html><body>Some unrecognized content</body></html>';
        $this->expectException(NotScrapeableException::class);
        HttpScraper::process('pa', $html);
    }

    public function testGrAvailable(): void
    {
        $html = '<html><body>does not appear to be registered yet</body></html>';
        $result = HttpScraper::process('gr', $html);
        $this->assertSame('Domain is available.', $result);
    }

    public function testGrRegistered(): void
    {
        $html = '<html><body><pre>Domain Name: example.gr<br>Registrar: Some Registrar<br />Created: 2020-01-01</pre></body></html>';

        $result = HttpScraper::process('gr', $html);
        $this->assertStringContainsString("Domain Name: example.gr\n", $result);
        $this->assertStringContainsString("Registrar: Some Registrar\n", $result);
        $this->assertStringContainsString("Created: 2020-01-01", $result);
        // Verify original newlines were stripped and <br> converted to \n
        $this->assertStringNotContainsString('<br', $result);
    }

    public function testTtRegistered(): void
    {
        if (!extension_loaded('dom')) {
            $this->markTestSkipped('DOM extension required');
        }

        $html = <<<'HTML'
<html><body>
<div class="main">
<table>
<tr><td>Domain Name</td><td>example.tt</td></tr>
<tr><td>Registrant</td><td>Example Corp</td></tr>
<tr><td>Expiration Date</td><td>2025-12-31 &nbsp; ACTIVE</td></tr>
</table>
</div>
</body></html>
HTML;

        $result = HttpScraper::process('tt', $html);
        $this->assertStringContainsString('Domain Name: example.tt', $result);
        $this->assertStringContainsString('Registrant: Example Corp', $result);
        $this->assertStringContainsString('Expiration Date: 2025-12-31', $result);
        $this->assertStringContainsString('Status: ACTIVE', $result);
        $this->assertStringContainsString('Registrar Name: NIC.TT', $result);
        $this->assertStringContainsString('Registrar Email: admin@nic.tt', $result);
    }

    public function testTjNotFound(): void
    {
        if (!extension_loaded('dom')) {
            $this->markTestSkipped('DOM extension required');
        }

        $html = '<html><body>no records found</body></html>';
        $result = HttpScraper::process('tj', $html);
        $this->assertSame('Domain not found', $result);
    }

    public function testTjRegistered(): void
    {
        if (!extension_loaded('dom')) {
            $this->markTestSkipped('DOM extension required');
        }

        $html = <<<'HTML'
<html><body>
<table>
<tr><td class="field">Domain Name</td><td>example.tj</td></tr>
<tr><td class="section">submitted by</td><td></td></tr>
<tr><td class="field">Name</td><td>Example Corp</td></tr>
<tr><td class="section">dns-servers for domain example.tj</td><td></td></tr>
<tr><td class="field">NS1</td><td>ns1.example.tj</td></tr>
<tr><td class="subfield"></td><td>ns2.example.tj</td></tr>
</table>
</body></html>
HTML;

        $result = HttpScraper::process('tj', $html);
        $this->assertStringContainsString('Status: OK', $result);
        $this->assertStringContainsString('Domain Name: example.tj', $result);
        $this->assertStringContainsString('registrant Name: Example Corp', $result);
        $this->assertStringContainsString('Nameservers NS1: ns1.example.tj', $result);
    }

    public function testNotScrapeable(): void
    {
        $this->expectException(NotScrapeableException::class);
        HttpScraper::process('not-scrapeable', '');
    }

    public function testUnknownScraper(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        HttpScraper::process('nonexistent', '');
    }
}
