<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Parser\Rdap;

use Klkvsk\Whoeasy\Exception\NotFoundException;
use Klkvsk\Whoeasy\Exception\RateLimitException;
use Klkvsk\Whoeasy\Parser\Exception\ParserException;
use Klkvsk\Whoeasy\Result\Info\AbstractInfo;
use Klkvsk\Whoeasy\Result\Info\AsnInfo;
use Klkvsk\Whoeasy\Result\Info\DomainInfo;
use Klkvsk\Whoeasy\Result\Info\Field\Contact;
use Klkvsk\Whoeasy\Result\Info\Field\ContactType;
use Klkvsk\Whoeasy\Result\Info\Field\Nameserver;
use Klkvsk\Whoeasy\Result\Info\Field\Registrar;
use Klkvsk\Whoeasy\Result\Info\IpInfo;

/**
 * Parses RDAP JSON responses (RFC 9083) into structured info.
 */
class RdapParser
{
    /**
     * Parse an RDAP JSON array into structured info.
     */
    public function parse(array $json): AbstractInfo
    {
        if (static::isNotFound($json)) {
            throw new NotFoundException("RDAP: nothing found");
        }
        if (static::isRateLimited($json)) {
            throw new RateLimitException("RDAP: rate limit exceeded");
        }
        if (isset($json['errorCode'])) {
            throw new ParserException("RDAP: unknown error: {$json['errorCode']}");
        }

        $objectClass = $json['objectClassName'] ?? null;

        return match ($objectClass) {
            'domain' => $this->parseDomain($json),
            'ip network' => $this->parseIpNetwork($json),
            'autnum' => $this->parseAutnum($json),
            default => $this->parseDomain($json), // best-effort fallback
        };
    }

    public static function isRateLimited(array $json): bool
    {
        return (isset($json['errorCode']) && (int)$json['errorCode'] === 429);
    }

    public static function isNotFound(array $json): bool
    {
        return (isset($json['errorCode']) && (int)$json['errorCode'] === 404);
    }

    private function parseDomain(array $data): DomainInfo
    {
        $name = $data['ldhName'] ?? $data['unicodeName'] ?? null;
        // Strip trailing dot from domain name
        if ($name !== null) {
            $name = rtrim($name, '.');
        }

        // Status (sorted for deterministic output)
        $statuses = $data['status'] ?? [];
        $status = $statuses ? array_map('trim', $statuses) : [];
        sort($status);

        // Dates from events
        $created = $this->extractEventDate($data, 'registration');
        $changed = $this->extractEventDate($data, 'last changed');
        $expires = $this->extractEventDate($data, 'expiration');

        // Nameservers (sorted by hostname)
        $nameservers = [];
        foreach ($data['nameservers'] ?? [] as $ns) {
            $nsName = $ns['ldhName'] ?? $ns['unicodeName'] ?? null;
            if ($nsName !== null) {
                $nameservers[] = new Nameserver(hostname: strtolower($nsName));
            }
        }
        usort($nameservers, fn(Nameserver $a, Nameserver $b) => strcmp($a->hostname, $b->hostname));

        // DNSSEC
        $dnssec = null;
        if (isset($data['secureDNS']['delegationSigned'])) {
            $dnssec = $data['secureDNS']['delegationSigned'] ? 'signedDelegation' : false;
        }

        // Entities (contacts + registrar)
        $contacts = [];
        $registrar = null;
        $this->parseEntities($data['entities'] ?? [], $contacts, $registrar);

        return new DomainInfo(
            name: $name,
            registrar: $registrar,
            createdDate: $created?->format('Y-m-d H:i:s'),
            updatedDate: $changed?->format('Y-m-d H:i:s'),
            expiresDate: $expires?->format('Y-m-d H:i:s'),
            status: $status,
            nameservers: $nameservers,
            contacts: $contacts,
            dnssec: $dnssec,
        );
    }

    private function parseIpNetwork(array $data): IpInfo
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

        // Extract origin AS number from non-standard RIR fields (last value if multiple)
        $asNumber = static::extractOriginAsn($data);

        return new IpInfo(
            range: $range,
            networkName: $networkName,
            description: null,
            asNumber: $asNumber,
            country: $country,
            createdDate: $created?->format('Y-m-d H:i:s'),
            updatedDate: $changed?->format('Y-m-d H:i:s'),
            contacts: $contacts,
        );
    }

    private function parseAutnum(array $data): AsnInfo
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

        return new AsnInfo(
            asn: $asnNumber,
            name: $name,
            createdDate: $created?->format('Y-m-d H:i:s'),
            updatedDate: $changed?->format('Y-m-d H:i:s'),
            contacts: $contacts,
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

            foreach ($roles as $role) {
                if ($role === 'registrar') {
                    $name = $parsed ? $parsed[0] : null;

                    // Extract IANA registrar ID from publicIds
                    $ianaId = null;
                    foreach ($entity['publicIds'] ?? [] as $pid) {
                        if (($pid['type'] ?? '') === 'IANA Registrar ID') {
                            $ianaId = $pid['identifier'] ?? null;
                        }
                    }

                    // Extract abuse email/phone from nested abuse entity
                    $abuseEmail = null;
                    $abusePhone = null;
                    foreach ($entity['entities'] ?? [] as $subEntity) {
                        $subRoles = $subEntity['roles'] ?? [];
                        if (in_array('abuse', $subRoles, true)) {
                            $abuseParsed = $this->parseEntityFields($subEntity);
                            if ($abuseParsed !== null) {
                                $abuseEmail = $abuseParsed[1];
                                $abusePhone = $abuseParsed[2];
                            }
                        }
                    }

                    // Fall back to registrar entity's own email/phone if no nested abuse
                    if ($parsed !== null) {
                        $abuseEmail ??= $parsed[1];
                        $abusePhone ??= $parsed[2];
                    }

                    $registrar = new Registrar(
                        name: $name,
                        ianaId: $ianaId,
                        abuseEmail: $abuseEmail,
                        abusePhone: $abusePhone,
                    );
                } else {
                    if ($parsed === null) {
                        continue;
                    }
                    [$name, $email, $phone, $address] = $parsed;
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
                        $name = is_string($value) && trim($value) !== '' ? $value : null;
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
                        // Strip "tel:" URI prefix
                        if ($telValue !== null) {
                            $telValue = preg_replace('/^tel:/i', '', $telValue);
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
                            // Append country code from params if not already in address parts
                            $params = $prop[1] ?? [];
                            $cc = $params['cc'] ?? null;
                            if ($cc !== null && $cc !== '') {
                                $parts[] = $cc;
                            }
                            $address = implode(', ', $parts) ?: null;
                        }
                        break;
                }
            }
        }

        // Check if empty (all fields null — don't use handle as fallback name)
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
     * Extract referral URL from RFC 9083 links array (rel=related, type=rdap+json).
     */
    public static function extractReferralUrl(array $data): ?string
    {
        foreach ($data['links'] ?? [] as $link) {
            if (($link['rel'] ?? null) === 'related'
                && isset($link['href'])
                && str_contains($link['type'] ?? '', 'rdap+json')
            ) {
                return $link['href'];
            }
        }
        return null;
    }

    /**
     * Extract origin AS number from non-standard RIR extension fields.
     * ARIN: arin_originas0_originautnums (array of ints)
     * LACNIC: lacnic_originAutnum (array of "AS28001" strings)
     * Uses last value if multiple.
     */
    public static function extractOriginAsn(array $data): ?int
    {
        // ARIN: arin_originas0_originautnums => [15169]
        $arinOrigins = $data['arin_originas0_originautnums'] ?? [];
        if (is_array($arinOrigins) && $arinOrigins !== []) {
            $last = end($arinOrigins);
            $asn = (int)preg_replace('/^AS/i', '', (string)$last);
            if ($asn > 0) return $asn;
        }

        // LACNIC: lacnic_originAutnum => ["AS28001"]
        $lacnicOrigins = $data['lacnic_originAutnum'] ?? [];
        if (is_array($lacnicOrigins) && $lacnicOrigins !== []) {
            $last = end($lacnicOrigins);
            $asn = (int)preg_replace('/^AS/i', '', (string)$last);
            if ($asn > 0) return $asn;
        }

        return null;
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
