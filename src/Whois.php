<?php

namespace Klkvsk\Whoeasy;

use Klkvsk\Whoeasy\Client\Adapter\CurlTelnet;
use Klkvsk\Whoeasy\Client\Adapter\Socket;
use Klkvsk\Whoeasy\Client\Exception\ClientException;
use Klkvsk\Whoeasy\Client\Proxy\Provider\ProxyProvider;
use Klkvsk\Whoeasy\Client\Proxy\Provider\ProxyProviderInterface;
use Klkvsk\Whoeasy\Client\Registry\BuiltinRegistryRegistry;
use Klkvsk\Whoeasy\Client\Registry\ServerRegistry;
use Klkvsk\Whoeasy\Client\WhoisClient;
use Klkvsk\Whoeasy\Parser\Data\WhoisAnswer;
use Klkvsk\Whoeasy\Parser\Exception\ParserException;
use Klkvsk\Whoeasy\Parser\Process\CleanComments;
use Klkvsk\Whoeasy\Parser\Process\FormatDates;
use Klkvsk\Whoeasy\Parser\Process\GroupedFields;
use Klkvsk\Whoeasy\Parser\Process\NovutecTemplates;
use Klkvsk\Whoeasy\Parser\Process\SimpleFields;
use Klkvsk\Whoeasy\Parser\WhoisParser;

class Whois
{
    protected ProxyProviderInterface $proxyProvider;
    protected ServerRegistry $servers;
    protected array $adapters = [];

    protected static ?self $instance = null;

    public static function factory(): static
    {
        return self::$instance ??= new static();
    }

    public function __construct()
    {
        $this->proxyProvider = new ProxyProvider();
        $this->servers = new BuiltinRegistryRegistry();
        $this->adapters = [
            extension_loaded('curl')
                ? new CurlTelnet($this->adapters, $this->proxyProvider)
                : new Socket($this->proxyProvider),
        ];
    }

    public function createClient(): WhoisClient
    {
        return new WhoisClient($this->adapters, $this->servers);
    }

    public function createParser(): WhoisParser
    {
        return new WhoisParser([
            new CleanComments(),
            new SimpleFields(),
            new GroupedFields(),
            new FormatDates(),
            new NovutecTemplates(),
        ]);
    }

    /**
     * @throws ClientException
     */
    public static function getRaw($query): string
    {
        return static::factory()->createClient()->lookup($query);
    }

    /**
     * @throws ClientException
     * @throws ParserException
     */
    public static function getParsed($query): WhoisAnswer
    {
        $rawData = static::factory()->createClient()->lookup($query, $server, $queryType);

        $answer = new WhoisAnswer($rawData, $server->getName(), $query, $queryType);

        return static::factory()->createParser()->parse($answer);
    }
}