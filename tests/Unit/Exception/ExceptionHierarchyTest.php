<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Tests\Unit\Exception;

use Klkvsk\Whoeasy\Client\Exception\ClientConnectException;
use Klkvsk\Whoeasy\Client\Exception\ClientException;
use Klkvsk\Whoeasy\Client\Exception\ClientNetworkException;
use Klkvsk\Whoeasy\Client\Exception\ClientRequestException;
use Klkvsk\Whoeasy\Client\Exception\ClientResponseException;
use Klkvsk\Whoeasy\Client\Exception\ClientTimeoutException;
use Klkvsk\Whoeasy\Exception\NotFoundException;
use Klkvsk\Whoeasy\Exception\RateLimitException;
use Klkvsk\Whoeasy\Exception\RetryableException;
use Klkvsk\Whoeasy\Exception\WhoeasyException;
use PHPUnit\Framework\TestCase;

class ExceptionHierarchyTest extends TestCase
{
    public function testClientExceptionIsRuntimeAndWhois(): void
    {
        $e = new ClientException('test');
        $this->assertInstanceOf(\RuntimeException::class, $e);
        $this->assertInstanceOf(WhoeasyException::class, $e);
    }

    public function testClientConnectExceptionIsRetryable(): void
    {
        $e = new ClientConnectException('connect failed');
        $this->assertInstanceOf(RetryableException::class, $e);
        $this->assertInstanceOf(ClientNetworkException::class, $e);
    }

    public function testClientTimeoutExceptionIsRetryable(): void
    {
        $e = new ClientTimeoutException('timed out');
        $this->assertInstanceOf(RetryableException::class, $e);
        $this->assertInstanceOf(ClientNetworkException::class, $e);
    }

    public function testRateLimitExceptionIsRetryable(): void
    {
        $e = new RateLimitException('rate limited');
        $this->assertInstanceOf(RetryableException::class, $e);
    }

    public function testNotFoundExceptionIsNotRetryable(): void
    {
        $e = new NotFoundException('not found');
        $this->assertNotInstanceOf(RetryableException::class, $e);
    }

    public function testClientRequestExceptionCarriesServerAndQuery(): void
    {
        $e = (new ClientRequestException('test'))
            ->withServer('whois.example.com')
            ->withQuery('example.com');

        $this->assertSame('whois.example.com', $e->getServer());
        $this->assertSame('example.com', $e->getQuery());
    }

    public function testClientResponseExceptionCarriesRawBodyAndHttpCode(): void
    {
        $e = (new ClientResponseException('test'))
            ->withHttpCode(429);

        $this->assertSame(429, $e->getHttpCode());
    }

    public function testClientRequestExceptionCarriesRawBody(): void
    {
        $e = (new ClientRequestException('test'))
            ->withRawBody('partial data');

        $this->assertSame('partial data', $e->getRawBody());
    }

    public function testGetServerFallsBackToRequest(): void
    {
        $e = new ClientRequestException('test');
        $this->assertNull($e->getServer());
        $this->assertNull($e->getQuery());
    }
}
