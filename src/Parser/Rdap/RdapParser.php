<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Parser\Rdap;

use Klkvsk\Whoeasy\Enum\QueryType;
use Klkvsk\Whoeasy\Result\ContactType;
use Klkvsk\Whoeasy\Result\AsnInfo;
use Klkvsk\Whoeasy\Result\Contact;
use Klkvsk\Whoeasy\Result\DomainInfo;
use Klkvsk\Whoeasy\Result\IpInfo;
use Klkvsk\Whoeasy\Result\Nameserver;
use Klkvsk\Whoeasy\Result\Registrar;
use Klkvsk\Whoeasy\Result\StructuredResult;

/**
 * Parses RDAP JSON responses (RFC 9083) into StructuredResult directly.
 */
class RdapParser
{
    /**
     * Parse an RDAP JSON array into a StructuredResult.
     */
    public function parse(array $json, QueryType $queryType): StructuredResult
    {
        $objectClass = $json['objectClassName'] ?? null;

        return match ($objectClass) {
            'domain' => $this->parseDomain($json, $queryType),
            'ip network' => $this->parseIpNetwork($json, $queryType),
            'autnum' => $this->parseAutnum($json, $queryType),
            default => $this->parseDomain($json, $queryType), // best-effort fallback
        };
    }

    private function parseDomain(array $data, QueryType $queryType): StructuredResult
    {
        $name = $data['ldhName'] ?? $data['unicodeName'] ?? null;

        // Status
        $statuses = $data['status'] ?? [];
        $status = $statuses ? array_map('trim', $statuses) : [];

        // Dates from events
        $created = $this->extractEventDate($data, 'registration');
        $changed = $this->extractEventDate($data, 'last changed');
        $expires = $this->extractEventDate($data, 'expiration');

        // Nameservers
        $nameservers = [];
        foreach ($data['nameservers'] ?? [] as $ns) {
            $nsName = $ns['ldhName'] ?? $ns['unicodeName'] ?? null;
            if ($nsName !== null) {
                $nameservers[] = new Nameserver(hostname: strtolower($nsName));
            }
        }

        // Entities (contacts + registrar)
        $contacts = [];
        $registrar = null;
        $this->parseEntities($data['entities'] ?? [], $contacts, $registrar);

        $domain = new DomainInfo(
            name: $name,
            registrar: $registrar,
            createdDate: $created?->format('Y-m-d H:i:s'),
            updatedDate: $changed?->format('Y-m-d H:i:s'),
            expiresDate: $expires?->format('Y-m-d H:i:s'),
            status: $status,
            nameservers: $nameservers,
            contacts: $contacts,
        );

        return new StructuredResult(
            queryType: $queryType,
            domain: $domain,
        );
    }

    private function parseIpNetwork(array $data, QueryType $queryType): StructuredResult
    {
        $networkName = $data['name'] ?? null;

        // Build range from startAddress-endAddress or CIDR
        $range = null;
        $start = $data['startAddress'] ?? null;
        $end = $data['endAddress'] ?? null;
        if ($start && $end) {
            $range = "$start - $end";
        } elseif (isset($data['cidr0_cidrs'][0])) {
            $cidr = $data['cidr0_cidrs'][0];
            $prefix = $cidr['v4prefix'] ?? $cidr['v6prefix'] ?? null;
            $length = $cidr['length'] ?? null;
            if ($prefix && $length !== null) {
                $range = "$prefix/$length";
            }
        }

        // Dates
        $created = $this->extractEventDate($data, 'registration');
        $changed = $this->extractEventDate($data, 'last changed');

        // Country from RDAP country field
        $country = $data['country'] ?? null;

        // Entities — for IP we collect owner + other contacts
        $ownerContact = null;
        $otherContacts = [];
        $this->parseIpAsnEntities($data['entities'] ?? [], $ownerContact, $otherContacts);

        // Try to extract country from owner address if not set from top-level
        if ($country === null && $ownerContact !== null && $ownerContact->address !== null) {
            $country = $this->extractCountry($ownerContact->address);
        }

        // If country is set at top level and owner has no address, try to extract from that
        if ($country === null && $ownerContact !== null) {
            // no country available
        }

        // Build contacts array: owner first (as registrant), then others
        $contacts = [];
        if ($ownerContact !== null) {
            $contacts[] = $ownerContact;
        }
        array_push($contacts, ...$otherContacts);

        $ip = new IpInfo(
            range: $range,
            networkName: $networkName,
            country: $country,
            createdDate: $created?->format('Y-m-d H:i:s'),
            updatedDate: $changed?->format('Y-m-d H:i:s'),
            contacts: $contacts,
        );

        return new StructuredResult(
            queryType: $queryType,
            ip: $ip,
        );
    }

    private function parseAutnum(array $data, QueryType $queryType): StructuredResult
    {
        $startAutnum = $data['startAutnum'] ?? null;
        $asnNumber = $startAutnum !== null ? (int)$startAutnum : null;
        $name = $data['name'] ?? null;

        // Dates
        $created = $this->extractEventDate($data, 'registration');
        $changed = $this->extractEventDate($data, 'last changed');

        // Entities — for ASN we collect owner + other contacts
        $ownerContact = null;
        $otherContacts = [];
        $this->parseIpAsnEntities($data['entities'] ?? [], $ownerContact, $otherContacts);

        // Build contacts array: owner first (as registrant), then others
        $contacts = [];
        if ($ownerContact !== null) {
            $contacts[] = $ownerContact;
        }
        array_push($contacts, ...$otherContacts);

        $asn = new AsnInfo(
            asn: $asnNumber,
            name: $name,
            createdDate: $created?->format('Y-m-d H:i:s'),
            updatedDate: $changed?->format('Y-m-d H:i:s'),
            contacts: $contacts,
        );

        return new StructuredResult(
            queryType: $queryType,
            asn: $asn,
        );
    }

    /**
     * Parse RDAP entities for domain results (contacts + registrar).
     *
     * @param Contact[] $contacts Collected contacts (by reference)
     * @param Registrar|null $registrar Registrar if found (by reference)
     */
    private function parseEntities(array $entities, array &$contacts, ?Registrar &$registrar): void
    {
        foreach ($entities as $entity) {
            $roles = $entity['roles'] ?? [];
            $parsed = $this->parseEntityFields($entity);

            if ($parsed === null) {
                continue;
            }

            [$name, $email, $phone, $address] = $parsed;

            foreach ($roles as $role) {
                if ($role === 'registrar') {
                    $registrar = new Registrar(
                        name: $name,
                        abuseEmail: $email,
                        abusePhone: $phone,
                    );
                } else {
                    $contacts[] = new Contact(
                        type: $this->mapContactType($role),
                        name: $name,
                        email: $email,
                        phone: $phone,
                        address: $address,
                    );
                }
            }
        }
    }

    /**
     * Parse RDAP entities for IP/ASN results (owner + other contacts).
     *
     * @param Contact|null $ownerContact Owner/registrant contact (by reference)
     * @param Contact[] $otherContacts Other contacts (by reference)
     */
    private function parseIpAsnEntities(array $entities, ?Contact &$ownerContact, array &$otherContacts): void
    {
        foreach ($entities as $entity) {
            $roles = $entity['roles'] ?? [];
            $parsed = $this->parseEntityFields($entity);

            if ($parsed === null) {
                continue;
            }

            [$name, $email, $phone, $address] = $parsed;

            foreach ($roles as $role) {
                $contact = new Contact(
                    type: $this->mapContactType($role),
                    name: $name,
                    email: $email,
                    phone: $phone,
                    address: $address,
                );

                if ($role === 'registrant' && $ownerContact === null) {
                    $ownerContact = $contact;
                } else {
                    $otherContacts[] = $contact;
                }
            }
        }
    }

    /**
     * Parse a single RDAP entity's fields. Returns [name, email, phone, address] or null if empty.
     *
     * @return array{string|null, string|null, string|null, string|null}|null
     */
    private function parseEntityFields(array $entity): ?array
    {
        $name = null;
        $email = null;
        $phone = null;
        $address = null;

        // Try to get fields from vcardArray (jCard format per RFC 7095)
        $vcard = $entity['vcardArray'] ?? null;
        if (is_array($vcard) && isset($vcard[1]) && is_array($vcard[1])) {
            foreach ($vcard[1] as $prop) {
                if (!is_array($prop) || count($prop) < 4) {
                    continue;
                }

                [$propName, , , $value] = $prop;

                switch (strtolower($propName)) {
                    case 'fn':
                        $name = is_string($value) ? $value : null;
                        break;

                    case 'org':
                        if (is_string($value)) {
                            $name ??= $value;
                        } elseif (is_array($value)) {
                            $name ??= $value[0] ?? null;
                        }
                        break;

                    case 'email':
                        $email = is_string($value) ? $value : null;
                        break;

                    case 'tel':
                        $telValue = is_string($value) ? $value : null;
                        if ($telValue !== null) {
                            $phone ??= $telValue;
                        }
                        break;

                    case 'adr':
                        if (is_array($value)) {
                            $parts = array_filter(
                                array_map(
                                    fn($v) => is_array($v) ? implode(', ', $v) : $v,
                                    $value
                                ),
                                fn($v) => $v !== null && $v !== '',
                            );
                            $address = implode(', ', $parts) ?: null;
                        }
                        break;
                }
            }
        }

        // Fallback: use handle as name if no name was found
        if ($name === null && isset($entity['handle'])) {
            $name = $entity['handle'];
        }

        // Check if empty (all fields null)
        if ($name === null && $email === null && $phone === null && $address === null) {
            return null;
        }

        return [$name, $email, $phone, $address];
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
     * Map RDAP role to ContactType enum.
     */
    private function mapContactType(string $role): ContactType
    {
        return match (strtolower($role)) {
            'administrative' => ContactType::Admin,
            'technical' => ContactType::Tech,
            'abuse' => ContactType::Abuse,
            default => ContactType::Registrant,
        };
    }

    /**
     * Extract a 2-letter country code from an address string.
     */
    private function extractCountry(?string $address): ?string
    {
        if ($address === null) {
            return null;
        }
        $parts = array_map('trim', explode(',', $address));
        foreach ($parts as $part) {
            if (preg_match('/^[A-Z]{2}$/', $part)) {
                return $part;
            }
        }
        return null;
    }
}
