<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Parser\Data;

class AsnResult extends AbstractResult
{
    public ?string $asn = null;
    public ?string $name = null;
    public ?string $range = null;

    public ?ContactResult $owner = null;
    public array $contacts = [];

    public ?\DateTimeInterface $created = null;
    public ?\DateTimeInterface $changed = null;

}