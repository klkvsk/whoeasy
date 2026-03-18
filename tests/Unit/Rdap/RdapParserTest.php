<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Tests\Unit\Rdap;

use Klkvsk\Whoeasy\Enum\QueryType;
use Klkvsk\Whoeasy\Parser\Rdap\RdapParser;
use Klkvsk\Whoeasy\Result\Info\AsnInfo;
use Klkvsk\Whoeasy\Result\Info\DomainInfo;
use Klkvsk\Whoeasy\Result\Info\IpInfo;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class RdapParserTest extends TestCase
{
    private const FIXTURE_DIR = __DIR__ . '/../../Fixture/Rdap';

    public static function fixtureProvider(): iterable
    {
        $dir = self::FIXTURE_DIR;
        if (!is_dir($dir)) {
            return;
        }

        foreach (glob("$dir/*/") as $serverDir) {
            $serverName = basename($serverDir);

            foreach (glob("$serverDir/*.json") as $fixtureFile) {
                $basename = basename($fixtureFile, '.json');
                if (in_array($basename, ['nxdomain', 'ratelimit'], true)) {
                    continue;
                }
                // Skip expected files themselves
                if (str_ends_with($basename, '.expected')) {
                    continue;
                }

                $expectedFile = "$serverDir/$basename.expected.json";
                if (!file_exists($expectedFile)) {
                    continue;
                }

                yield "$serverName/$basename" => [$fixtureFile, $expectedFile];
            }
        }
    }

    private static function detectQueryType(string $basename): QueryType
    {
        if (str_starts_with($basename, 'ip6-')) {
            return QueryType::Ipv6;
        }
        if (str_starts_with($basename, 'ip-')) {
            return QueryType::Ipv4;
        }
        if (str_starts_with($basename, 'asn-')) {
            return QueryType::Asn;
        }
        return QueryType::Domain;
    }

    #[DataProvider('fixtureProvider')]
    public function testFixture(string $fixtureFile, string $expectedFile): void
    {
        $json = json_decode(file_get_contents($fixtureFile), true, 512, JSON_THROW_ON_ERROR);
        $expected = json_decode(file_get_contents($expectedFile), true, 512, JSON_THROW_ON_ERROR);

        if ($expected === []) {
            $this->markTestSkipped('Empty expected output');
        }

        $parser = new RdapParser();
        $info = $parser->parse($json);
        $actual = $info->toArray();

        $this->sortArrayKeys($expected);
        $this->sortArrayKeys($actual);

        $this->assertSame($expected, $actual, sprintf(
            "Parsed output mismatch for %s/%s\nExpected: %s\nActual: %s",
            basename(dirname($fixtureFile)),
            basename($fixtureFile, '.json'),
            json_encode($expected, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE),
            json_encode($actual, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE),
        ));
    }

    private function sortArrayKeys(array &$array): void
    {
        ksort($array);
        foreach ($array as &$value) {
            if (is_array($value) && !array_is_list($value)) {
                $this->sortArrayKeys($value);
            } elseif (is_array($value)) {
                foreach ($value as &$item) {
                    if (is_array($item) && !array_is_list($item)) {
                        $this->sortArrayKeys($item);
                    }
                }
            }
        }
    }
}
