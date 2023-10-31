<?php

namespace Klkvsk\Whoeasy;

function ip6prefix2long(string $ip): int|false
{
    if (!preg_match('/^([a-f0-9]{4}):([a-f0-9]{4})/i', $ip, $m)) {
        return false;
    }

    return hexdec($m[1] . $m[2]);
}