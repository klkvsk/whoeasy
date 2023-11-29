<?php

namespace Klkvsk\Whoeasy;

function ip6prefix2long(string $ip): int|false
{
    if (!preg_match('/^([a-f0-9]{4}):([a-f0-9]{4})/i', $ip, $m)) {
        return false;
    }

    return hexdec($m[1] . $m[2]);
}

function asn2long(string $asn): int|false
{
    if (!preg_match('/^(asn?[:-_. ]*)?([0-9.]+)/i', $asn, $m)) {
        return false;
    }
    $asParts = explode('.', $m[2]);
    $asNumber = 0;
    $n = 0;
    while ($asParts) {
        $part = array_pop($asParts);
        $asNumber += (int)$part * (2 ** (16 * $n));
        $n++;
    }
    return $asNumber;
}