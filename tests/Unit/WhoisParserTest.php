<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Tests\Unit;

use Klkvsk\Whoeasy\Parser\Whois\WhoisParser;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class WhoisParserTest extends TestCase
{
    private const FIXTURE_DIR = __DIR__ . '/../Fixture/Whois';

    public function testExtractReferralServerVerisign(): void
    {
        $response = <<<EOT
           Domain Name: EXAMPLE.COM
           Registrar: RESERVED-Internet Assigned Numbers Authority
           Registrar WHOIS Server: whois.iana.org
           Updated Date: 2024-08-14T07:01:38Z
        EOT;
        $this->assertSame('whois.iana.org', WhoisParser::extractReferralServer($response));
    }

    public function testExtractReferralServerWithProtocol(): void
    {
        $response = "ReferralServer: whois://whois.markmonitor.com\n";
        $this->assertSame('whois.markmonitor.com', WhoisParser::extractReferralServer($response));
    }

    public function testExtractReferralServerRefer(): void
    {
        $response = "refer:        whois.verisign-grs.com\n";
        $this->assertSame('whois.verisign-grs.com', WhoisParser::extractReferralServer($response));
    }

    public function testExtractReferralServerNone(): void
    {
        $response = "Domain Name: example.com\nRegistrar: Test\n";
        $this->assertNull(WhoisParser::extractReferralServer($response));
    }

    public function testIsRateLimited(): void
    {
        $this->assertTrue(WhoisParser::isRateLimited('You have exceeded your query limit'));
        $this->assertTrue(WhoisParser::isRateLimited('Too many requests'));
        $this->assertFalse(WhoisParser::isRateLimited('Domain Name: example.com'));
    }

    public function testIsNotFound(): void
    {
        $this->assertTrue(WhoisParser::isNotFound('No match for "NOTEXIST.COM"'));
        $this->assertTrue(WhoisParser::isNotFound('Domain is available'));
        $this->assertTrue(WhoisParser::isNotFound('Status: free'));
        $this->assertFalse(WhoisParser::isNotFound('Domain Name: example.com'));
    }

    public function testStripBoilerplate(): void
    {
        $response = "Domain Name: example.com\nRegistrar: Test\n" .
            ">>> Last update of WHOIS database: 2026-03-16T14:58:50Z <<<\n\n" .
            "For more information on Whois status codes, please visit https://icann.org/epp\n\n" .
            "Terms of Use: If too many queries are received from a single IP address...\n";

        $stripped = WhoisParser::stripBoilerplate($response);
        $this->assertStringContainsString('Domain Name: example.com', $stripped);
        $this->assertStringContainsString('Registrar: Test', $stripped);
        $this->assertStringNotContainsString('too many queries', $stripped);
        $this->assertStringNotContainsString('Terms of Use', $stripped);
        $this->assertStringNotContainsString('>>>', $stripped);
    }

    public function testStripBoilerplateNoFalseRateLimit(): void
    {
        $response = "Domain Name: PJUDGE.AC\nRegistrar: NameSilo, LLC\n" .
            "Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\n" .
            ">>> Last update of WHOIS database: 2026-03-16T15:10:28Z <<<\n\n" .
            "For more information on Whois status codes, please visit https://icann.org/epp\n\n" .
            "Terms of Use: Access to WHOIS information is provided... " .
            "If too many queries are received from a single IP address within a specified time, " .
            "the service will begin to reject further queries...\n";

        $this->assertFalse(WhoisParser::isRateLimited($response));
        $this->assertFalse(WhoisParser::isNotFound($response));
    }

    public function testStripBoilerplateCommentLines(): void
    {
        $response = "% This is RIPE\n% Terms and Conditions\ninetnum: 1.2.3.0 - 1.2.3.255\nnetname: TEST\n";
        $stripped = WhoisParser::stripBoilerplate($response);
        $this->assertStringNotContainsString('RIPE', $stripped);
        $this->assertStringContainsString('inetnum:', $stripped);
    }

    public static function nxdomainFixtureProvider(): iterable
    {
        $dir = self::FIXTURE_DIR;
        if (!is_dir($dir)) {
            return;
        }

        foreach (glob("$dir/*/nxdomain.txt") as $fixtureFile) {
            $serverHostname = basename(dirname($fixtureFile));
            yield $serverHostname => [$fixtureFile];
        }
    }

    #[DataProvider('nxdomainFixtureProvider')]
    public function testIsNotFoundFixture(string $fixtureFile): void
    {
        $raw = file_get_contents($fixtureFile);
        $this->assertTrue(
            WhoisParser::isNotFound($raw),
            sprintf(
                "isNotFound() should return true for %s/nxdomain.txt:\n%s",
                basename(dirname($fixtureFile)),
                substr($raw, 0, 500),
            ),
        );
    }
}
