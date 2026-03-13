<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Enum;

enum QueryType: string
{
    case Domain = 'domain';
    case Ipv4 = 'ipv4';
    case Ipv6 = 'ipv6';
    case Asn = 'asn';
}
