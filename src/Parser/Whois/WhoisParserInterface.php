<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Parser\Whois;

use Klkvsk\Whoeasy\Enum\QueryType;
use Klkvsk\Whoeasy\Parser\Exception\ParserException;
use Klkvsk\Whoeasy\Result\ParserResult;

/**
 * Common interface for WHOIS text parsers (universal and server-specific).
 */
interface WhoisParserInterface
{
    /**
     * Parse raw WHOIS response text into a ParserResult.
     *
     * @param string $rawResponse The raw WHOIS text response
     * @param string $serverHostname The WHOIS server that returned this response
     * @param QueryType $queryType The type of query that produced this response
     * @return ParserResult Parsed result with info + optional referral server
     * @throws ParserException If the response is completely unparseable
     */
    public function parse(string $rawResponse, string $serverHostname, QueryType $queryType): ParserResult;
}
