<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Parser\Whois;

use Klkvsk\Whoeasy\Enum\ContactType;
use Klkvsk\Whoeasy\Enum\QueryType;
use Klkvsk\Whoeasy\Result\AsnInfo;
use Klkvsk\Whoeasy\Result\Contact;
use Klkvsk\Whoeasy\Result\DomainInfo;
use Klkvsk\Whoeasy\Result\IpInfo;
use Klkvsk\Whoeasy\Result\Nameserver;
use Klkvsk\Whoeasy\Result\Registrar;
use Klkvsk\Whoeasy\Result\StructuredResult;

/**
 * Universal WHOIS text parser that handles key:value formats across servers.
 *
 * Replaces 143 Novutec templates with a single parser that normalizes
 * field names and extracts structured data from any WHOIS response.
 */
final class WhoisParser implements WhoisParserInterface
{
    public function parse(string $rawResponse, string $serverHostname, QueryType $queryType): StructuredResult
    {
        // Strip comment lines and legal notices
        $text = $this->cleanResponse($rawResponse);

        // Extract all key:value pairs
        $fields = $this->extractFields($text);

        return match ($queryType) {
            QueryType::Domain => $this->parseDomain($fields, $text),
            QueryType::Ipv4, QueryType::Ipv6 => $this->parseIp($fields, $text),
            QueryType::Asn => $this->parseAsn($fields, $text),
        };
    }

    /**
     * Remove comment lines, legal notices, and normalize whitespace.
     */
    private function cleanResponse(string $text): string
    {
        // Normalize line endings
        $text = str_replace("\r\n", "\n", $text);
        $text = str_replace("\r", "\n", $text);

        // Remove lines that are purely comments (%, #, ;)
        $lines = explode("\n", $text);
        $cleaned = [];
        foreach ($lines as $line) {
            $trimmed = ltrim($line);
            if (str_starts_with($trimmed, '%') || str_starts_with($trimmed, '#') || str_starts_with($trimmed, ';')) {
                continue;
            }
            // Skip >>> markers
            if (str_starts_with($trimmed, '>>>')) {
                continue;
            }
            $cleaned[] = $line;
        }

        return implode("\n", $cleaned);
    }

    /**
     * Extract key:value pairs from WHOIS text.
     * Handles multiple values for the same key (e.g., multiple Name Servers).
     *
     * @return array<string, string[]> Normalized key => array of values
     */
    private function extractFields(string $text): array
    {
        $fields = [];
        $lines = explode("\n", $text);

        foreach ($lines as $line) {
            // Match "Key: Value" or "Key:Value" patterns
            if (preg_match('/^([A-Za-z][A-Za-z0-9 \/_-]*?)\s*:\s*(.+)$/', $line, $m)) {
                $key = $this->normalizeKey($m[1]);
                $value = trim($m[2]);
                if ($value !== '') {
                    $fields[$key][] = $value;
                }
            }
            // Match indented continuation values (UK Nominet style)
            // "    Key:\n        value"
            if (preg_match('/^\s{4,}([A-Za-z][A-Za-z0-9 ]*?)\s*:\s*$/', $line, $m)) {
                // This is a label line, value is on the next indented line
                $key = $this->normalizeKey($m[1]);
                // Look ahead for indented value (handled by subsequent iterations)
            }
        }

        // Handle UK Nominet format: "    Label:\n        value"
        $this->parseIndentedSections($text, $fields);

        return $fields;
    }

    /**
     * Parse indented section format used by Nominet (.uk) and others.
     * Format: "    Section header:\n        key: value" or "    Section:\n        value"
     */
    private function parseIndentedSections(string $text, array &$fields): void
    {
        // Match sections like "    Domain name:\n        google.co.uk"
        if (preg_match('/^\s+Domain name:\s*\n\s+(\S.+)$/m', $text, $m)) {
            $fields['domain_name'][] = trim($m[1]);
        }

        // Nominet dates: "    Registered on: 14-Feb-1999"
        if (preg_match('/Registered on:\s*(.+)/m', $text, $m)) {
            $fields['creation_date'][] = trim($m[1]);
        }
        if (preg_match('/Expiry date:\s*(.+)/m', $text, $m)) {
            $fields['expiry_date'][] = trim($m[1]);
        }
        if (preg_match('/Last updated:\s*(.+)/m', $text, $m)) {
            $fields['updated_date'][] = trim($m[1]);
        }

        // Nominet registrar: "    Registrar:\n        Markmonitor Inc. [Tag = MARKMONITOR]"
        if (preg_match('/^\s+Registrar:\s*\n\s+(\S.+?)(?:\s*\[Tag\s*=.*\])?\s*$/m', $text, $m)) {
            $fields['registrar'][] = trim($m[1]);
        }

        // Nominet name servers section
        if (preg_match('/Name servers:\s*\n((?:\s+\S+\n?)+)/m', $text, $m)) {
            $nsBlock = trim($m[1]);
            foreach (explode("\n", $nsBlock) as $ns) {
                $ns = trim($ns);
                if ($ns !== '' && !str_contains($ns, ':') && preg_match('/^[a-z0-9.-]+$/i', $ns)) {
                    $fields['name_server'][] = $ns;
                }
            }
        }
    }

    /**
     * Normalize field key to a canonical form.
     */
    private function normalizeKey(string $key): string
    {
        $key = strtolower(trim($key));
        $key = preg_replace('/\s+/', '_', $key);
        $key = preg_replace('/[^a-z0-9_]/', '', $key);

        // Map common variations to canonical keys
        return match ($key) {
            'domain', 'domain_name', 'domainname' => 'domain_name',
            'registrar', 'sponsoring_registrar', 'registrar_name' => 'registrar',
            'registrar_whois_server', 'whois_server', 'refer' => 'whois_server',
            'registrar_url', 'registrar_homepage' => 'registrar_url',
            'registrar_abuse_contact_email', 'abuse_contact_email', 'abuse_email' => 'abuse_email',
            'registrar_abuse_contact_phone', 'abuse_contact_phone', 'abuse_phone' => 'abuse_phone',
            'registrar_iana_id' => 'registrar_iana_id',
            'creation_date', 'created', 'created_date', 'created_on',
            'registration_date', 'registered_on', 'domain_registered',
            'reg_created_date', 'registration_time', 'registered' => 'creation_date',
            'updated_date', 'last_modified', 'lastmodified', 'changed',
            'last_updated', 'modification_date', 'modified', 'domain_last_updated' => 'updated_date',
            'registry_expiry_date', 'expiry_date', 'expiration_date', 'expires',
            'expire_date', 'paid_till', 'renewal_date', 'domain_expiration_date',
            'registrar_registration_expiration_date' => 'expiry_date',
            'domain_status', 'status' => 'status',
            'name_server', 'nameserver', 'nserver', 'nameservers', 'name_servers',
            'dns', 'hostname' => 'name_server',
            'dnssec' => 'dnssec',
            'registrant_name' => 'registrant_name',
            'registrant_organization', 'registrant_organisation' => 'registrant_organization',
            'registrant_email' => 'registrant_email',
            'registrant_phone', 'registrant_phone_number' => 'registrant_phone',
            'registrant_country', 'registrant_countrycode' => 'registrant_country',
            'registrant_address', 'registrant_street' => 'registrant_address',
            'admin_name', 'admin_contact_name' => 'admin_name',
            'admin_email', 'admin_contact_email' => 'admin_email',
            'admin_phone', 'admin_contact_phone' => 'admin_phone',
            'admin_organization', 'admin_organisation' => 'admin_organization',
            'tech_name', 'tech_contact_name', 'technical_contact_name' => 'tech_name',
            'tech_email', 'tech_contact_email', 'technical_contact_email' => 'tech_email',
            'tech_phone', 'tech_contact_phone' => 'tech_phone',
            'tech_organization', 'tech_organisation' => 'tech_organization',
            // IP-specific
            'inetnum', 'netrange', 'inet6num' => 'ip_range',
            'netname', 'network_name' => 'net_name',
            'descr', 'description', 'orgname', 'org_name', 'organization' => 'description',
            'country' => 'country',
            'origin', 'originas', 'origin_as' => 'origin_as',
            // ASN-specific
            'aut_num', 'ashandle', 'as_handle', 'asnumber' => 'asn',
            'as_name', 'asname' => 'as_name',
            default => $key,
        };
    }

    private function parseDomain(array $fields, string $text): StructuredResult
    {
        $domainName = $this->firstValue($fields, 'domain_name');

        // Extract registrar info
        $registrarName = $this->firstValue($fields, 'registrar');
        $registrar = null;
        if ($registrarName !== null) {
            $registrar = new Registrar(
                name: $registrarName,
                url: $this->firstValue($fields, 'registrar_url'),
                abuseEmail: $this->firstValue($fields, 'abuse_email'),
                abusePhone: $this->firstValue($fields, 'abuse_phone'),
            );
        }

        // Extract dates
        $createdDate = $this->parseDate($this->firstValue($fields, 'creation_date'));
        $updatedDate = $this->parseDate($this->firstValue($fields, 'updated_date'));
        $expiresDate = $this->parseDate($this->firstValue($fields, 'expiry_date'));

        // Extract status codes
        $statuses = [];
        foreach ($fields['status'] ?? [] as $status) {
            // Strip EPP URL suffix: "clientTransferProhibited (https://...)"
            $status = preg_replace('/\s*\(https?:\/\/[^)]+\)/', '', $status);
            $statuses[] = trim($status);
        }

        // Extract nameservers
        $nameservers = [];
        foreach ($fields['name_server'] ?? [] as $ns) {
            $ns = strtolower(trim($ns));
            // Some servers include IP after hostname
            $parts = preg_split('/\s+/', $ns, 2);
            $hostname = $parts[0];
            if (preg_match('/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$/i', $hostname)) {
                $nameservers[] = new Nameserver(hostname: $hostname);
            }
        }

        // Extract contacts
        $contacts = $this->extractContacts($fields);

        // DNSSEC
        $dnssec = $this->firstValue($fields, 'dnssec');

        return new StructuredResult(
            queryType: QueryType::Domain,
            domain: new DomainInfo(
                name: $domainName,
                registrar: $registrarName,
                registrarInfo: $registrar,
                createdDate: $createdDate,
                updatedDate: $updatedDate,
                expiresDate: $expiresDate,
                status: $statuses,
                nameservers: $nameservers,
                contacts: $contacts,
                dnssec: $dnssec,
            ),
        );
    }

    private function parseIp(array $fields, string $text): StructuredResult
    {
        $range = $this->firstValue($fields, 'ip_range');
        $netName = $this->firstValue($fields, 'net_name');
        $description = $this->firstValue($fields, 'description');
        $country = $this->firstValue($fields, 'country');
        $createdDate = $this->parseDate($this->firstValue($fields, 'creation_date')
            ?? $this->firstValue($fields, 'created'));
        $updatedDate = $this->parseDate($this->firstValue($fields, 'updated_date')
            ?? $this->firstValue($fields, 'last_modified'));

        $contacts = $this->extractIpContacts($fields, $text);

        return new StructuredResult(
            queryType: QueryType::Ipv4,
            ip: new IpInfo(
                range: $range,
                networkName: $netName,
                description: $description,
                country: $country,
                createdDate: $createdDate,
                updatedDate: $updatedDate,
                contacts: $contacts,
            ),
        );
    }

    private function parseAsn(array $fields, string $text): StructuredResult
    {
        $asnStr = $this->firstValue($fields, 'asn');
        $asn = null;
        if ($asnStr !== null) {
            $asn = (int)preg_replace('/^AS/i', '', $asnStr);
        }

        $name = $this->firstValue($fields, 'as_name');
        $description = $this->firstValue($fields, 'description');
        $country = $this->firstValue($fields, 'country');

        return new StructuredResult(
            queryType: QueryType::Asn,
            asn: new AsnInfo(
                asn: $asn,
                name: $name,
                description: $description,
                country: $country,
            ),
        );
    }

    /**
     * Extract contact information from field names with contact type prefixes.
     * E.g., "Registrant Name", "Admin Email", "Tech Phone"
     *
     * @return Contact[]
     */
    private function extractContacts(array $fields): array
    {
        $contacts = [];
        $typeMap = [
            'registrant' => ContactType::Registrant,
            'admin' => ContactType::Admin,
            'tech' => ContactType::Tech,
            'abuse' => ContactType::Abuse,
        ];

        foreach ($typeMap as $prefix => $type) {
            $name = $this->firstValue($fields, "{$prefix}_name");
            $org = $this->firstValue($fields, "{$prefix}_organization");
            $email = $this->firstValue($fields, "{$prefix}_email");
            $phone = $this->firstValue($fields, "{$prefix}_phone");

            // For registrant, also check Registrant Country as address
            $address = null;
            if ($prefix === 'registrant') {
                $country = $this->firstValue($fields, 'registrant_country');
                if ($country !== null) {
                    $address = $country;
                }
            }

            if ($name !== null || $org !== null || $email !== null || $phone !== null) {
                $contacts[] = new Contact(
                    type: $type,
                    name: $name,
                    organization: $org,
                    email: $email,
                    phone: $phone,
                    address: $address,
                );
            }
        }

        return $contacts;
    }

    /**
     * Extract contacts from IP WHOIS responses (RIPE/ARIN format).
     *
     * @return Contact[]
     */
    private function extractIpContacts(array $fields, string $text): array
    {
        $contacts = [];

        // Check for abuse email in text
        if (preg_match('/Abuse contact.*?is \'([^\']+)\'/i', $text, $m)) {
            $contacts[] = new Contact(
                type: ContactType::Abuse,
                email: $m[1],
            );
        }

        // ARIN format: OrgName, OrgAbuseEmail, etc.
        $orgName = $this->firstValue($fields, 'orgname')
            ?? $this->firstValue($fields, 'description');

        if ($orgName !== null) {
            $contacts[] = new Contact(
                type: ContactType::Registrant,
                organization: $orgName,
            );
        }

        return $contacts;
    }

    /**
     * Parse a date string into Y-m-d H:i:s format (best-effort).
     */
    private function parseDate(?string $dateStr): ?string
    {
        if ($dateStr === null || $dateStr === '') {
            return null;
        }

        // Try common formats
        $formats = [
            'Y-m-d\TH:i:sP',      // ISO 8601 with timezone: 2024-08-02T02:17:33+0000
            'Y-m-d\TH:i:s.uP',    // ISO 8601 with microseconds
            'Y-m-d H:i:s',        // Standard: 2024-08-02 02:17:33
            'Y-m-d',              // Date only: 2024-08-02
            'd-M-Y',              // UK format: 14-Feb-1999
            'd/m/Y',              // European: 14/02/1999
            'm/d/Y',              // US: 02/14/1999
            'Y/m/d',              // Japanese: 1999/02/14
            'd.m.Y',              // German: 14.02.1999
            'D M d H:i:s T Y',   // ctime format
        ];

        foreach ($formats as $format) {
            $dt = \DateTimeImmutable::createFromFormat($format, $dateStr);
            if ($dt !== false) {
                return $dt->format('Y-m-d H:i:s');
            }
        }

        // Try PHP's general date parser as fallback
        try {
            $dt = new \DateTimeImmutable($dateStr);
            return $dt->format('Y-m-d H:i:s');
        } catch (\Exception) {
            return null;
        }
    }

    /**
     * Get the first value for a key, or null.
     */
    private function firstValue(array $fields, string $key): ?string
    {
        return $fields[$key][0] ?? null;
    }
}
