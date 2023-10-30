<?php

namespace Klkvsk\Whoeasy\Client;

interface RequestInterface
{
    public const QUERY_TYPE_DOMAIN = 'domain';
    public const QUERY_TYPE_NIC_HANDLE = 'handle';
    public const QUERY_TYPE_IPV4 = 'ipv4';
    public const QUERY_TYPE_IPV6 = 'ipv6';
    public const QUERY_TYPE_ASN = 'asn';

    public function getServer(): ServerInfoInterface;

    public function getQuery(): string;

    public function getQueryString(): string;

    public function getQueryType(): string;

    public function getTimeout(): ?float;
}