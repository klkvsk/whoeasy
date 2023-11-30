<?php

namespace Klkvsk\Whoeasy\Parser\Data;

class IpResult extends AbstractResult
{
    public ?string $name = null;
    public ?string $range = null;
    public ?string $asn = null;

    public ?ContactResult $owner = null;
    public array $contacts = [];

    public ?\DateTimeInterface $created = null;
    public ?\DateTimeInterface $changed = null;
}