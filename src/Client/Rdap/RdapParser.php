<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Client\Rdap;

use Klkvsk\Whoeasy\Parser\Data\AsnResult;
use Klkvsk\Whoeasy\Parser\Data\ContactResult;
use Klkvsk\Whoeasy\Parser\Data\DomainResult;
use Klkvsk\Whoeasy\Parser\Data\IpResult;

/**
 * Parses RDAP JSON responses (RFC 9083) into internal result objects.
 */
class RdapParser
{
    /**
     * Parse an RDAP response into the appropriate result object.
     */
    public function parse(RdapResponse $response): DomainResult|IpResult|AsnResult
    {
        $objectClass = $response->getObjectClassName();

        return match ($objectClass) {
            'domain' => $this->parseDomain($response->json),
            'ip network' => $this->parseIpNetwork($response->json),
            'autnum' => $this->parseAutnum($response->json),
            default => $this->parseDomain($response->json), // best-effort fallback
        };
    }

    private function parseDomain(array $data): DomainResult
    {
        $result = new DomainResult();
        $result->name = $data['ldhName'] ?? $data['unicodeName'] ?? null;

        // Status
        $statuses = $data['status'] ?? [];
        $result->status = $statuses ? implode(', ', $statuses) : null;

        // Dates from events
        $result->created = $this->extractEventDate($data, 'registration');
        $result->changed = $this->extractEventDate($data, 'last changed');
        $result->expires = $this->extractEventDate($data, 'expiration');

        // Nameservers
        $nameservers = [];
        foreach ($data['nameservers'] ?? [] as $ns) {
            $nsName = $ns['ldhName'] ?? $ns['unicodeName'] ?? null;
            if ($nsName !== null) {
                $nameservers[] = strtolower($nsName);
            }
        }
        $result->nameservers = $nameservers ?: null;

        // Entities (contacts)
        $this->parseEntities($data['entities'] ?? [], $result);

        return $result;
    }

    private function parseIpNetwork(array $data): IpResult
    {
        $result = new IpResult();
        $result->name = $data['name'] ?? null;

        // Build range from startAddress-endAddress or CIDR
        $start = $data['startAddress'] ?? null;
        $end = $data['endAddress'] ?? null;
        if ($start && $end) {
            $result->range = "$start - $end";
        } elseif (isset($data['cidr0_cidrs'][0])) {
            $cidr = $data['cidr0_cidrs'][0];
            $prefix = $cidr['v4prefix'] ?? $cidr['v6prefix'] ?? null;
            $length = $cidr['length'] ?? null;
            if ($prefix && $length !== null) {
                $result->range = "$prefix/$length";
            }
        }

        // Dates
        $result->created = $this->extractEventDate($data, 'registration');
        $result->changed = $this->extractEventDate($data, 'last changed');

        // Country from RDAP country field
        $country = $data['country'] ?? null;

        // Entities
        $this->parseEntities($data['entities'] ?? [], $result);

        // Set country on owner if available and not already set
        if ($country && $result->owner !== null && $result->owner->address === null) {
            $result->owner->address = $country;
        }

        return $result;
    }

    private function parseAutnum(array $data): AsnResult
    {
        $result = new AsnResult();

        $startAutnum = $data['startAutnum'] ?? null;
        $result->asn = $startAutnum !== null ? 'AS' . $startAutnum : null;
        $result->name = $data['name'] ?? null;

        // Range
        $endAutnum = $data['endAutnum'] ?? null;
        if ($startAutnum !== null && $endAutnum !== null && $startAutnum !== $endAutnum) {
            $result->range = "AS$startAutnum - AS$endAutnum";
        }

        // Dates
        $result->created = $this->extractEventDate($data, 'registration');
        $result->changed = $this->extractEventDate($data, 'last changed');

        // Entities
        $this->parseEntities($data['entities'] ?? [], $result);

        return $result;
    }

    /**
     * Parse RDAP entities into contact results and attach to the parent result.
     */
    private function parseEntities(array $entities, DomainResult|IpResult|AsnResult $result): void
    {
        foreach ($entities as $entity) {
            $roles = $entity['roles'] ?? [];
            $contact = $this->parseEntity($entity);

            if ($contact === null || $contact->isEmpty()) {
                continue;
            }

            foreach ($roles as $role) {
                $clone = clone $contact;
                $clone->type = $this->mapRole($role);

                if ($result instanceof DomainResult) {
                    if ($role === 'registrar') {
                        $result->registrar = $clone;
                    } else {
                        $result->contacts[] = $clone;
                    }
                } elseif ($result instanceof IpResult || $result instanceof AsnResult) {
                    if ($role === 'registrant' && $result->owner === null) {
                        $result->owner = $clone;
                    } else {
                        $result->contacts[] = $clone;
                    }
                }
            }
        }
    }

    /**
     * Parse a single RDAP entity into a ContactResult.
     */
    private function parseEntity(array $entity): ?ContactResult
    {
        $contact = new ContactResult();

        // Try to get name from vcardArray (jCard format per RFC 7095)
        $vcard = $entity['vcardArray'] ?? null;
        if (is_array($vcard) && isset($vcard[1]) && is_array($vcard[1])) {
            $this->parseVcard($vcard[1], $contact);
        }

        // Fallback: use handle as name if no name was found
        if ($contact->name === null && isset($entity['handle'])) {
            $contact->name = $entity['handle'];
        }

        // Recursively parse sub-entities (e.g., abuse contacts under registrar)
        // We don't recurse deeply, just note the pattern
        return $contact;
    }

    /**
     * Parse jCard (vCard-in-JSON, RFC 7095) properties into a ContactResult.
     */
    private function parseVcard(array $properties, ContactResult $contact): void
    {
        foreach ($properties as $prop) {
            if (!is_array($prop) || count($prop) < 4) {
                continue;
            }

            [$name, , , $value] = $prop;

            switch (strtolower($name)) {
                case 'fn':
                    $contact->name = is_string($value) ? $value : null;
                    break;

                case 'org':
                    // org value can be a string or array
                    if (is_string($value)) {
                        $contact->name ??= $value;
                    } elseif (is_array($value)) {
                        $contact->name ??= $value[0] ?? null;
                    }
                    break;

                case 'email':
                    $contact->email = is_string($value) ? $value : null;
                    break;

                case 'tel':
                    $phone = is_string($value) ? $value : null;
                    if ($phone !== null) {
                        $contact->phone ??= $phone;
                    }
                    break;

                case 'adr':
                    if (is_array($value)) {
                        // jCard ADR: [pobox, ext, street, locality, region, postal, country]
                        $parts = array_filter(
                            is_array($value) ? array_map(
                                fn($v) => is_array($v) ? implode(', ', $v) : $v,
                                $value
                            ) : [],
                            fn($v) => $v !== null && $v !== '',
                        );
                        $contact->address = implode(', ', $parts) ?: null;
                    }
                    break;
            }
        }
    }

    /**
     * Extract a date from RDAP events array.
     */
    private function extractEventDate(array $data, string $action): ?\DateTimeInterface
    {
        foreach ($data['events'] ?? [] as $event) {
            $eventAction = $event['eventAction'] ?? null;
            $eventDate = $event['eventDate'] ?? null;

            if ($eventAction === $action && $eventDate !== null) {
                try {
                    return new \DateTimeImmutable($eventDate);
                } catch (\Exception) {
                    return null;
                }
            }
        }

        return null;
    }

    /**
     * Map RDAP role to internal contact type string.
     */
    private function mapRole(string $role): string
    {
        return match (strtolower($role)) {
            'registrant' => 'registrant',
            'administrative' => 'admin',
            'technical' => 'tech',
            'abuse' => 'abuse',
            'registrar' => 'registrar',
            'billing' => 'registrant', // no billing type, map to registrant
            default => 'registrant',
        };
    }
}
