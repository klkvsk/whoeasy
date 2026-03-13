<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Enum;

enum AuthLevel: string
{
    case NonAuth = 'non-auth';
    case Auth = 'auth';
}
