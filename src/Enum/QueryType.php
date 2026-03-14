<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Enum;

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
        if (preg_match('/-[a-z]$/i', $query)) {
            return self::NicHandle;
        }
        if (preg_match('/^asn?[0-9]+$/i', $query)) {
            return self::Asn;
        }
        if (filter_var($query, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return self::Ipv4;
        }
        if (filter_var($query, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return self::Ipv6;
        }
        return self::Domain;
    }
}
