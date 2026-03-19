<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Registry;

enum QueryType: string
{
    case Domain = 'domain';
    case NicHandle = 'handle';
    case Ipv4 = 'ipv4';
    case Ipv6 = 'ipv6';
    case Asn = 'asn';

    /**
     * Guess query type from input string.
     */
    public static function guess(string $query): self
    {
        $query = trim($query);

        if (preg_match('/^(ASN?|autnum-?)\d+$/i', $query)) {
            return self::Asn;
        }
        if (filter_var($query, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return self::Ipv4;
        }
        if (filter_var($query, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return self::Ipv6;
        }
        // IPv4 CIDR notation
        if (preg_match('/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/', $query)) {
            return self::Ipv4;
        }
        // NIC handles
        if (preg_match('/-[a-z]$/i', $query)) {
            return self::NicHandle;
        }
        return self::Domain;
    }
}
