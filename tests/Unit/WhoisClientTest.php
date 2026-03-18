<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Tests\Unit;

use Klkvsk\Whoeasy\Client\Whois\WhoisClient;
use PHPUnit\Framework\TestCase;

class WhoisClientTest extends TestCase
{
    // WhoisClient now only contains query() — no static methods to test.
    // detectReferral moved to WhoisParser::extractReferralServer
    // stripBoilerplate, is* moved to WhoisParser

    public function testClassExists(): void
    {
        $this->assertTrue(class_exists(WhoisClient::class));
    }
}
