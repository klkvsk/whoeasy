<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Tests\Unit;

use Klkvsk\Whoeasy\Enum\QueryType;
use Klkvsk\Whoeasy\Parser\Whois\WhoisParser;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class WhoisFixtureTest extends TestCase
{
    private const FIXTURE_DIR = __DIR__ . '/../Fixture/Whois';

    public static function fixtureProvider(): iterable
    {
        $dir = self::FIXTURE_DIR;
        if (!is_dir($dir)) {
            return;
        }

        foreach (glob("$dir/*/") as $serverDir) {
            $serverHostname = basename($serverDir);

            foreach (glob("$serverDir/*.txt") as $fixtureFile) {
                $basename = basename($fixtureFile, '.txt');
                if (in_array($basename, ['ratelimit', 'error', 'nxdomain'], true)) {
                    continue;
                }

                $expectedFile = "$serverDir/$basename.expected.json";
                if (!file_exists($expectedFile)) {
                    continue;
                }

                yield "$serverHostname/$basename" => [$fixtureFile, $expectedFile, $serverHostname];
            }
        }
    }

    #[DataProvider('fixtureProvider')]
    public function testFixture(string $fixtureFile, string $expectedFile, string $serverHostname): void
    {
        $raw = file_get_contents($fixtureFile);
        $expected = json_decode(file_get_contents($expectedFile), true, 512, JSON_THROW_ON_ERROR);

        if ($expected === []) {
            $this->markTestSkipped('Empty expected output');
        }

        $queryType = match ($expected['queryType'] ?? null) {
            'ipv4' => QueryType::Ipv4,
            'ipv6' => QueryType::Ipv6,
            'asn' => QueryType::Asn,
            default => QueryType::Domain,
        };

        $parser = new WhoisParser();
        $result = $parser->parse($raw, $serverHostname, $queryType);
        $actual = $result->info->toArray();

        // Remove queryType from expected — it's metadata, not part of toArray()
        $compare = $expected;
        unset($compare['queryType']);

        $this->assertSame($compare, $actual, sprintf(
            "Parsed output mismatch for %s/%s\nExpected: %s\nActual: %s",
            $serverHostname,
            basename($fixtureFile, '.txt'),
            json_encode($compare, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE),
            json_encode($actual, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE),
        ));
    }
}
