<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Enum;

enum ContactType: string
{
    case Registrant = 'registrant';
    case Admin = 'admin';
    case Tech = 'tech';
    case Abuse = 'abuse';
}
