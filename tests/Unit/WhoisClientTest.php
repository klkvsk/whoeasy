<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Tests\Unit;

use Klkvsk\Whoeasy\Client\Whois\WhoisClient;
use PHPUnit\Framework\TestCase;

class WhoisClientTest extends TestCase
{
    public function testDetectReferralVerisign(): void
    {
        $response = <<<EOT
           Domain Name: EXAMPLE.COM
           Registrar: RESERVED-Internet Assigned Numbers Authority
           Registrar WHOIS Server: whois.iana.org
           Updated Date: 2024-08-14T07:01:38Z
        EOT;
        $this->assertSame('whois.iana.org', WhoisClient::detectReferral($response));
    }

    public function testDetectReferralWithProtocol(): void
    {
        $response = "ReferralServer: whois://whois.markmonitor.com\n";
        $this->assertSame('whois.markmonitor.com', WhoisClient::detectReferral($response));
    }

    public function testDetectReferralRefer(): void
    {
        $response = "refer:        whois.verisign-grs.com\n";
        $this->assertSame('whois.verisign-grs.com', WhoisClient::detectReferral($response));
    }

    public function testDetectReferralNone(): void
    {
        $response = "Domain Name: example.com\nRegistrar: Test\n";
        $this->assertNull(WhoisClient::detectReferral($response));
    }

    public function testIsRateLimited(): void
    {
        $this->assertTrue(WhoisClient::isRateLimited('You have exceeded your query limit'));
        $this->assertTrue(WhoisClient::isRateLimited('Too many requests'));
        $this->assertFalse(WhoisClient::isRateLimited('Domain Name: example.com'));
    }

    public function testIsNotFound(): void
    {
        $this->assertTrue(WhoisClient::isNotFound('No match for "NOTEXIST.COM"'));
        $this->assertTrue(WhoisClient::isNotFound('Domain is available'));
        $this->assertTrue(WhoisClient::isNotFound('Status: free'));
        $this->assertFalse(WhoisClient::isNotFound('Domain Name: example.com'));
    }

    public function testStripBoilerplate(): void
    {
        $response = "Domain Name: example.com\nRegistrar: Test\n" .
            ">>> Last update of WHOIS database: 2026-03-16T14:58:50Z <<<\n\n" .
            "For more information on Whois status codes, please visit https://icann.org/epp\n\n" .
            "Terms of Use: If too many queries are received from a single IP address...\n";

        $stripped = WhoisClient::stripBoilerplate($response);
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

        $stripped = WhoisClient::stripBoilerplate($response);
        $this->assertFalse(WhoisClient::isRateLimited($stripped));
        $this->assertFalse(WhoisClient::isNotFound($stripped));
    }

    public function testStripBoilerplateCommentLines(): void
    {
        $response = "% This is RIPE\n% Terms and Conditions\ninetnum: 1.2.3.0 - 1.2.3.255\nnetname: TEST\n";
        $stripped = WhoisClient::stripBoilerplate($response);
        $this->assertStringNotContainsString('RIPE', $stripped);
        $this->assertStringContainsString('inetnum:', $stripped);
    }
}
