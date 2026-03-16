<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy;

enum QueryMode: string
{
    case PreferRdap = 'prefer-rdap';
    case PreferWhois = 'prefer-whois';
    case RdapOnly = 'rdap-only';
    case WhoisOnly = 'whois-only';
    case Both = 'both';
}
