<?php

namespace Klkvsk\Whoeasy;

use Klkvsk\Whoeasy\Client\Adapter\CurlHttp;
use Klkvsk\Whoeasy\Client\Adapter\CurlTelnet;
use Klkvsk\Whoeasy\Client\Adapter\Socket;
use Klkvsk\Whoeasy\Client\Exception\ClientException;
use Klkvsk\Whoeasy\Client\Proxy\Provider\ProxyProvider;
use Klkvsk\Whoeasy\Client\Proxy\Provider\ProxyProviderInterface;
use Klkvsk\Whoeasy\Client\Proxy\ProxyInterface;
use Klkvsk\Whoeasy\Client\Registry\BuiltinServerRegistry;
use Klkvsk\Whoeasy\Client\Registry\ServerRegistryInterface;
use Klkvsk\Whoeasy\Client\ServerInfoInterface;
use Klkvsk\Whoeasy\Client\WhoisClient;
use Klkvsk\Whoeasy\Parser\Data\WhoisAnswer;
use Klkvsk\Whoeasy\Parser\Exception\ParserException;
use Klkvsk\Whoeasy\Parser\Process\BlockFields;
use Klkvsk\Whoeasy\Parser\Process\CleanComments;
use Klkvsk\Whoeasy\Parser\Process\CommonStructure;
use Klkvsk\Whoeasy\Parser\Process\FormatDates;
use Klkvsk\Whoeasy\Parser\Process\GroupedFields;
use Klkvsk\Whoeasy\Parser\Process\JsonToText;
use Klkvsk\Whoeasy\Parser\Process\NovutecTemplates;
use Klkvsk\Whoeasy\Parser\Process\SimpleFields;
use Klkvsk\Whoeasy\Parser\WhoisParser;

class Whois
{
    protected ProxyProviderInterface $proxyProvider;
    protected ServerRegistryInterface $servers;
    protected array $adapters = [];

    protected static ?self $instance = null;

    public static function factory(): static
    {
        return self::$instance ??= new static();
    }

    public function __construct()
    {
        $this->proxyProvider = new ProxyProvider();
        $this->servers = new BuiltinServerRegistry();
        $this->adapters = [
            extension_loaded('curl')
                ? new CurlTelnet([], $this->proxyProvider)
                : new Socket($this->proxyProvider),

            new CurlHttp([], $this->proxyProvider)
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
            new JsonToText(),
            new SimpleFields(),
            new GroupedFields(),
            new BlockFields(),
            new FormatDates(),
            new NovutecTemplates(),
            new CommonStructure(),
        ]);
    }

    /**
     * @throws ClientException
     */
    public static function getRaw(
        string $query,
        ServerInfoInterface|string $server = null,
        ProxyInterface|string $proxy = null,
    ): string
    {
        $client = self::factory()->createClient();
        $request = $client->createRequest($query, server: $server);
        $response = $client->handle($request);
        return $response->getAnswer();
    }

    /**
     * @param string|ServerInfoInterface|null $server
     * @throws ClientException
     * @throws ParserException
     */
    public static function getParsed(
        string $query,
        ServerInfoInterface|string $server = null,
        ProxyInterface|string $proxy = null
    ): WhoisAnswer
    {
        $client = self::factory()->createClient();
        $request = $client->createRequest($query, server: $server, proxy: $proxy);
        $response = $client->handle($request);

        $answer = new WhoisAnswer(
            $response->getAnswer(),
            $request->getQuery(),
            $request->getQueryType(),
            $request->getServer()->getName(),
        );

        return static::factory()->createParser()->parse($answer);
    }
}