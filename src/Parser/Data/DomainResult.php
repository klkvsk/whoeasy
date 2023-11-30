<?php

namespace Klkvsk\Whoeasy\Parser\Data;

class DomainResult extends AbstractResult
{
    public ?string $name = null;
    public ?string $status = null;

    public ?ContactResult $registrar = null;
    public array $contacts = [];

    public ?\DateTimeInterface $created = null;
    public ?\DateTimeInterface $changed = null;
    public ?\DateTimeInterface $expires = null;

    public ?array $nameservers = null;

}