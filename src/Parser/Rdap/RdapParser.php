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
     *
     * @param array<string, mixed> $json
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
            $errorCode = $json['errorCode'];
            $errorCodeStr = is_scalar($errorCode) ? (string)$errorCode : 'unknown';
            throw new ParserException("RDAP: unknown error: {$errorCodeStr}");
        }

        $objectClass = $json['objectClassName'] ?? null;

        return match ($objectClass) {
            'domain' => $this->parseDomain($json),
            'ip network' => $this->parseIpNetwork($json),
            'autnum' => $this->parseAutnum($json),
            default => $this->parseDomain($json), // best-effort fallback
        };
    }

    /**
     * @param array<string, mixed> $json
     */
    public static function isRateLimited(array $json): bool
    {
        if (!isset($json['errorCode'])) {
            return false;
        }
        $code = $json['errorCode'];
        return (is_int($code) || is_string($code)) && intval($code) === 429;
    }

    /**
     * @param array<string, mixed> $json
     */
    public static function isNotFound(array $json): bool
    {
        if (!isset($json['errorCode'])) {
            return false;
        }
        $code = $json['errorCode'];
        return (is_int($code) || is_string($code)) && intval($code) === 404;
    }

    /**
     * @param array<string, mixed> $data
     */
    private function parseDomain(array $data): DomainInfo
    {
        $name = $data['ldhName'] ?? $data['unicodeName'] ?? null;
        // Strip trailing dot from domain name
        if (is_string($name)) {
            $name = rtrim($name, '.');
        } else {
            $name = null;
        }

        // Status (sorted for deterministic output)
        $statuses = $data['status'] ?? [];
        $status = [];
        if (is_array($statuses) && $statuses !== []) {
            /** @var list<string> $status */
            $status = array_map(
                static fn(mixed $s): string => is_string($s) ? trim($s) : '',
                $statuses
            );
        }
        sort($status);

        // Dates from events
        $created = $this->extractEventDate($data, 'registration');
        $changed = $this->extractEventDate($data, 'last changed');
        $expires = $this->extractEventDate($data, 'expiration');

        // Nameservers (sorted by hostname)
        $nameservers = [];
        $nsArray = $data['nameservers'] ?? [];
        if (is_array($nsArray)) {
            foreach ($nsArray as $ns) {
                if (!is_array($ns)) {
                    continue;
                }
                $nsName = $ns['ldhName'] ?? $ns['unicodeName'] ?? null;
                if (is_string($nsName)) {
                    $nameservers[] = new Nameserver(hostname: strtolower($nsName));
                }
            }
        }
        usort($nameservers, fn(Nameserver $a, Nameserver $b) => strcmp($a->hostname, $b->hostname));

        // DNSSEC
        $dnssec = null;
        if (isset($data['secureDNS']) && is_array($data['secureDNS']) && isset($data['secureDNS']['delegationSigned'])) {
            $dnssec = $data['secureDNS']['delegationSigned'] ? 'signedDelegation' : false;
        }

        // Entities (contacts + registrar)
        $contacts = [];
        $registrar = null;
        $entitiesArray = $data['entities'] ?? [];
        if (is_array($entitiesArray)) {
            $this->parseEntities($entitiesArray, $contacts, $registrar);
        }

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

    /**
     * @param array<string, mixed> $data
     */
    private function parseIpNetwork(array $data): IpInfo
    {
        $networkName = $data['name'] ?? null;
        if (!is_string($networkName)) {
            $networkName = null;
        }

        // Build range from startAddress-endAddress or CIDR
        $range = null;
        $start = $data['startAddress'] ?? null;
        $end = $data['endAddress'] ?? null;
        if (is_string($start) && is_string($end) && $start !== '' && $end !== '') {
            $range = "{$start} - {$end}";
        } elseif (isset($data['cidr0_cidrs']) && is_array($data['cidr0_cidrs']) && isset($data['cidr0_cidrs'][0])) {
            $cidr = $data['cidr0_cidrs'][0];
            if (is_array($cidr)) {
                $prefix = $cidr['v4prefix'] ?? $cidr['v6prefix'] ?? null;
                $length = $cidr['length'] ?? null;
                if (is_string($prefix) && $prefix !== '' && $length !== null) {
                    $lengthStr = is_int($length) || is_string($length) ? (string)$length : '';
                    $range = "{$prefix}/{$lengthStr}";
                }
            }
        }

        // Dates
        $created = $this->extractEventDate($data, 'registration');
        $changed = $this->extractEventDate($data, 'last changed');

        // Country from RDAP country field
        $country = $data['country'] ?? null;
        if (!is_string($country)) {
            $country = null;
        }

        // Entities — for IP we collect owner + other contacts
        $ownerContact = null;
        $otherContacts = [];
        $entitiesArray = $data['entities'] ?? [];
        if (is_array($entitiesArray)) {
            $this->parseIpAsnEntities($entitiesArray, $ownerContact, $otherContacts);
        }

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

    /**
     * @param array<string, mixed> $data
     */
    private function parseAutnum(array $data): AsnInfo
    {
        $startAutnum = $data['startAutnum'] ?? null;
        $asnNumber = null;
        if (is_int($startAutnum)) {
            $asnNumber = $startAutnum;
        } elseif (is_string($startAutnum) && is_numeric($startAutnum)) {
            $asnNumber = intval($startAutnum);
        }
        $name = $data['name'] ?? null;
        if (!is_string($name)) {
            $name = null;
        }

        // Dates
        $created = $this->extractEventDate($data, 'registration');
        $changed = $this->extractEventDate($data, 'last changed');

        // Entities — for ASN we collect owner + other contacts
        $ownerContact = null;
        $otherContacts = [];
        $entitiesArray = $data['entities'] ?? [];
        if (is_array($entitiesArray)) {
            $this->parseIpAsnEntities($entitiesArray, $ownerContact, $otherContacts);
        }

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
     * @param array<mixed> $entities
     * @param Contact[] $contacts Collected contacts (by reference)
     * @param Registrar|null $registrar Registrar if found (by reference)
     */
    private function parseEntities(array $entities, array &$contacts, ?Registrar &$registrar): void
    {
        foreach ($entities as $entity) {
            if (!is_array($entity)) {
                continue;
            }
            $roles = $entity['roles'] ?? [];
            if (!is_array($roles)) {
                continue;
            }
            $parsed = $this->parseEntityFields($entity);

            foreach ($roles as $role) {
                if (!is_string($role)) {
                    continue;
                }
                if ($role === 'registrar') {
                    $name = $parsed ? $parsed[0] : null;

                    // Extract IANA registrar ID from publicIds
                    $ianaId = null;
                    $publicIds = $entity['publicIds'] ?? [];
                    if (is_array($publicIds)) {
                        foreach ($publicIds as $pid) {
                            if (!is_array($pid)) {
                                continue;
                            }
                            if (($pid['type'] ?? '') === 'IANA Registrar ID') {
                                $identifier = $pid['identifier'] ?? null;
                                $ianaId = is_string($identifier) ? $identifier : null;
                            }
                        }
                    }

                    // Extract abuse email/phone from nested abuse entity
                    $abuseEmail = null;
                    $abusePhone = null;
                    $subEntities = $entity['entities'] ?? [];
                    if (is_array($subEntities)) {
                        foreach ($subEntities as $subEntity) {
                            if (!is_array($subEntity)) {
                                continue;
                            }
                            $subRoles = $subEntity['roles'] ?? [];
                            if (!is_array($subRoles)) {
                                continue;
                            }
                            if (in_array('abuse', $subRoles, true)) {
                                $abuseParsed = $this->parseEntityFields($subEntity);
                                if ($abuseParsed !== null) {
                                    $abuseEmail = $abuseParsed[1];
                                    $abusePhone = $abuseParsed[2];
                                }
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
     * @param array<mixed> $entities
     * @param Contact|null $ownerContact Owner/registrant contact (by reference)
     * @param Contact[] $otherContacts Other contacts (by reference)
     */
    private function parseIpAsnEntities(array $entities, ?Contact &$ownerContact, array &$otherContacts): void
    {
        foreach ($entities as $entity) {
            if (!is_array($entity)) {
                continue;
            }
            $roles = $entity['roles'] ?? [];
            if (!is_array($roles)) {
                continue;
            }
            $parsed = $this->parseEntityFields($entity);

            if ($parsed === null) {
                continue;
            }

            [$name, $email, $phone, $address] = $parsed;

            foreach ($roles as $role) {
                if (!is_string($role)) {
                    continue;
                }
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
     * @param array<mixed> $entity
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

                $propName = $prop[0] ?? null;
                $value = $prop[3] ?? null;

                if (!is_string($propName)) {
                    continue;
                }

                switch (strtolower($propName)) {
                    case 'fn':
                        $name = is_string($value) && trim($value) !== '' ? $value : null;
                        break;

                    case 'org':
                        if (is_string($value)) {
                            $name ??= $value;
                        } elseif (is_array($value)) {
                            $orgFirst = $value[0] ?? null;
                            $name ??= is_string($orgFirst) ? $orgFirst : null;
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
                                    static fn(mixed $v): string => is_array($v) ? implode(', ', array_map(
                                        static fn(mixed $item): string => is_string($item) ? $item : '',
                                        $v
                                    )) : (is_string($v) ? $v : ''),
                                    $value
                                ),
                                static fn(string $v): bool => $v !== '',
                            );
                            // Append country code from params if not already in address parts
                            $params = $prop[1] ?? [];
                            if (is_array($params)) {
                                $cc = $params['cc'] ?? null;
                                if (is_string($cc) && $cc !== '') {
                                    $parts[] = $cc;
                                }
                            }
                            $joined = implode(', ', $parts);
                            $address = $joined !== '' ? $joined : null;
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
     *
     * @param array<string, mixed> $data
     */
    private function extractEventDate(array $data, string $action): ?\DateTimeInterface
    {
        $events = $data['events'] ?? [];
        if (!is_array($events)) {
            return null;
        }
        foreach ($events as $event) {
            if (!is_array($event)) {
                continue;
            }
            $eventAction = $event['eventAction'] ?? null;
            $eventDate = $event['eventDate'] ?? null;

            if ($eventAction === $action && is_string($eventDate)) {
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
     *
     * @param array<string, mixed> $data
     */
    public static function extractReferralUrl(array $data): ?string
    {
        $links = $data['links'] ?? [];
        if (!is_array($links)) {
            return null;
        }
        foreach ($links as $link) {
            if (!is_array($link)) {
                continue;
            }
            $rel = $link['rel'] ?? null;
            $href = $link['href'] ?? null;
            $type = $link['type'] ?? '';
            if ($rel === 'related'
                && is_string($href)
                && is_string($type)
                && str_contains($type, 'rdap+json')
            ) {
                return $href;
            }
        }
        return null;
    }

    /**
     * Extract origin AS number from non-standard RIR extension fields.
     * ARIN: arin_originas0_originautnums (array of ints)
     * LACNIC: lacnic_originAutnum (array of "AS28001" strings)
     * Uses last value if multiple.
     *
     * @param array<string, mixed> $data
     */
    public static function extractOriginAsn(array $data): ?int
    {
        // ARIN: arin_originas0_originautnums => [15169]
        $arinOrigins = $data['arin_originas0_originautnums'] ?? [];
        if (is_array($arinOrigins) && $arinOrigins !== []) {
            $last = end($arinOrigins);
            if (is_int($last) || is_string($last)) {
                $lastStr = (string)$last;
                $cleaned = preg_replace('/^AS/i', '', $lastStr);
                $asn = is_string($cleaned) ? intval($cleaned) : 0;
                if ($asn > 0) {
                    return $asn;
                }
            }
        }

        // LACNIC: lacnic_originAutnum => ["AS28001"]
        $lacnicOrigins = $data['lacnic_originAutnum'] ?? [];
        if (is_array($lacnicOrigins) && $lacnicOrigins !== []) {
            $last = end($lacnicOrigins);
            if (is_int($last) || is_string($last)) {
                $lastStr = (string)$last;
                $cleaned = preg_replace('/^AS/i', '', $lastStr);
                $asn = is_string($cleaned) ? intval($cleaned) : 0;
                if ($asn > 0) {
                    return $asn;
                }
            }
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
