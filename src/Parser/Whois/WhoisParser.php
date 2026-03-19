<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Parser\Whois;

use Klkvsk\Whoeasy\Exception\NotFoundException;
use Klkvsk\Whoeasy\Exception\NotSupportedException;
use Klkvsk\Whoeasy\Exception\RateLimitException;
use Klkvsk\Whoeasy\Registry\QueryType;
use Klkvsk\Whoeasy\Result\Info\AbstractInfo;
use Klkvsk\Whoeasy\Result\Info\AsnInfo;
use Klkvsk\Whoeasy\Result\Info\DomainInfo;
use Klkvsk\Whoeasy\Result\Info\Field\Contact;
use Klkvsk\Whoeasy\Result\Info\Field\ContactType;
use Klkvsk\Whoeasy\Result\Info\Field\Nameserver;
use Klkvsk\Whoeasy\Result\Info\Field\Registrar;
use Klkvsk\Whoeasy\Result\Info\IpInfo;

class WhoisParser implements WhoisParserInterface
{
    /**
     * Strip legal boilerplate, comment lines, and informational banners from raw WHOIS text.
     * Returns only the data-bearing portion of the response.
     */
    public static function stripBoilerplate(string $response): string
    {
        // Normalize line endings
        $response = str_replace("\r\n", "\n", $response);
        $response = str_replace("\r", "\n", $response);

        // Remove >>> marker lines (VeriSign/Identity Digital/Afilias boundary)
        // Don't truncate everything after it, as some servers (e.g., .st) include
        // detailed data in a second section after the marker
        $response = preg_replace('/^>>>.*<<<\s*$/m', '', $response);

        // Strip trailing legal blocks that appear without >>> marker
        $boilerplateStarts = [
            '/^NOTICE:\s/m',
            '/^Terms of Use:\s/m',
            '/^URL of the ICANN\b/m',
            '/^For more information on Whois status codes/m',
            '/^TERMS OF USE:\s/m',
        ];
        foreach ($boilerplateStarts as $pattern) {
            if (preg_match($pattern, $response, $m, \PREG_OFFSET_CAPTURE)) {
                $response = substr($response, 0, $m[0][1]);
            }
        }

        // Remove comment-prefixed lines (%, #, ;)
        $lines = explode("\n", $response);
        $cleaned = [];
        foreach ($lines as $line) {
            $trimmed = ltrim($line);
            if ($trimmed === '') {
                $cleaned[] = $line;
                continue;
            }
            if ($trimmed[0] === '%' || $trimmed[0] === ';') {
                continue;
            }
            // Strip #-prefixed comment lines, but preserve Korean WHOIS section headers
            if ($trimmed[0] === '#' && !preg_match('/^#\s*(ENGLISH|KOREAN)/i', $trimmed)) {
                continue;
            }
            $cleaned[] = $line;
        }

        return implode("\n", $cleaned);
    }

    /**
     * Detect if the response indicates rate limiting.
     * Takes the original (non-stripped) raw WHOIS response.
     */
    public static function isRateLimited(string $response): bool
    {
        $response = static::stripBoilerplate($response);

        $patterns = [
            '/(reached|exceeded) the maximum allowable/i',
            '/(reached|exceeded) your (query|request) limit/i',
            '/(rate limit|quota) (exceeded|reached)/i',
            '/try again (later|after)/i',
            '/(request|rate|query|connection) limit (exceeded|reached)/i',
            '/too many (requests|queries|lookups)/i',
            '/server is busy/i',
            '/(?<!for )excessive querying/i',
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $response)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Detect if the response indicates the TLD/protocol is not supported by this server.
     * Takes the original (non-stripped) raw WHOIS response.
     */
    public static function isNotSupported(string $response): bool
    {
        $response = static::stripBoilerplate($response);

        $patterns = [
            '/^TLD is not supported\b/im',
            '/^This TLD has no whois server/im',
            '/^No whois service is available/im',
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $response)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Detect if the response indicates "not found".
     * Takes the original (non-stripped) raw WHOIS response.
     */
    public static function isNotFound(string $response): bool
    {
        $patterns = [
            '/^[\W\s]*(no match|not found|no data found|nothing found|no domain|no information)/im',
            '/is available for registration/i',
            '/queried (object|domain|record) does not exist/i',
            '/domain is available/i',
            '/domain( name)? not found/i',
            '/^status: (free|available)/mi',
            '/no matching objects found/i',
            '/(objects?|domains?|records?|entry|entries) (was )?not found/im',
            '/(object|domain|key) does not exist/i',
            '/no (object|entries|records) found/i',
            '/no such (domain|entry|record)/i',
            '/is available for purchase$/im',
            '/^No record found for /im',
            '/domain (has not been|is not) registered/i',
            '/ is not available for registration/i',
            '/domain "[a-z-.0-9]+" not found/i',
            '/domain (name )?you requested (is not known|was not found)/i',
            '/^>>> Domain name violates registry policy/m', // whois.dmdomains.dm
            '/^(Registration |Domain )?Status:\s+AVAILABLE/im', // whois.nic.be
            '/ - No Match/m', // whois.dns.pt
            '/query returned 0 objects/m', // whois.iana.org
            '/registration status: invalid/m', // whois.imena.bg
            '/No data was found/', // whois.isoc.org.il
            '/Object_Not_Found/', // whois.mx
            '/[a-z-.0-9]+.[a-z]+ (is free|(was ?)not found)/i', // whois.nic.aw
            '/Nincs talalat \/ No match/i', // whois.nic.hu
            '/Domain Cannot Be Registered/i', // whois.nic.net.bw - when 2nd level
            '/<pre>\nAvailable/i', // whois.nic.za
            '/status: not registered/i', // whois.pknic.net.pk
            '/^Domain unknown$/mi', // whois.registry.pf
            '/Reserved by QDR/mi', // whois.registry.qa
            '/^No found$/i', // whois.twnic.net.tw
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $response)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Extract referral server hostname from raw WHOIS response text.
     *
     * Looks for patterns like:
     * - "Registrar WHOIS Server: whois.example.com"
     * - "refer: whois.example.com"
     * - "ReferralServer: whois://whois.example.com"
     */
    public static function extractReferralServer(string $response): ?string
    {
        $patterns = [
            '/^\s*Registrar WHOIS Server:\s*(.+)/mi',
            '/^\s*Whois Server:\s*(.+)/mi',
            '/^\s*refer:\s*(.+)/mi',
            '/^\s*ReferralServer:\s*(.+)/mi',
            '/^\s*Registrar Whois:\s*(.+)/mi',
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $response, $m)) {
                $referral = trim($m[1]);

                // Strip protocol prefix if present
                $referral = preg_replace('#^(whois|rwhois)://#i', '', $referral);

                // Strip port suffix and path
                $referral = preg_replace('#[:/].*$#', '', $referral);

                // Validate it looks like a hostname
                if (preg_match('/^[a-z0-9]([a-z0-9\-.]+[a-z0-9])?$/i', $referral)) {
                    return $referral;
                }
            }
        }

        return null;
    }

    public function parse(string $rawResponse, string $serverHostname, QueryType $queryType): AbstractInfo
    {
        // Detect rate limiting / not found / not supported
        if (static::isRateLimited($rawResponse)) {
            throw new RateLimitException("WHOIS rate limit on $serverHostname");
        }
        if (static::isNotSupported($rawResponse)) {
            throw new NotSupportedException("WHOIS: not supported on $serverHostname");
        }
        if (static::isNotFound($rawResponse)) {
            throw new NotFoundException("WHOIS: not found on $serverHostname");
        }


        // Extract data from comments/boilerplate before stripping
        $preStrip = $this->extractFromBoilerplate($rawResponse, $serverHostname);

        $text = $this->cleanResponse($rawResponse);

        $fields = $this->extractFields($text, $serverHostname);

        // Merge pre-strip data (lower priority than parsed fields)
        foreach ($preStrip as $k => $v) {
            if (!isset($fields[$k])) {
                $fields[$k] = $v;
            }
        }

        return match ($queryType) {
            QueryType::Domain => $this->parseDomain($fields, $text, $serverHostname),
            QueryType::Ipv4, QueryType::Ipv6 => $this->parseIp($fields, $text, $rawResponse),
            QueryType::Asn => $this->parseAsn($fields, $text, $rawResponse),
        };
    }

    private function cleanResponse(string $text): string
    {
        $text = static::stripBoilerplate($text);
        // Normalize line endings
        $text = str_replace("\r\n", "\n", $text);
        $text = str_replace("\r", "\n", $text);
        return $text;
    }

    /**
     * Extract useful data from comment/boilerplate lines before they are stripped.
     * @return array<string, string[]>
     */
    private function extractFromBoilerplate(string $rawResponse, string $serverHostname): array
    {
        $fields = [];

        // NIC Chile: domain name from "Whois.do?d=domain.cl" URL in comments
        if ($serverHostname === 'whois.nic.cl'
            && preg_match('/[?&]d=([a-z0-9.-]+\.cl)\b/i', $rawResponse, $m)
        ) {
            $fields['domain_name'][] = strtolower($m[1]);
        }

        // Registry Abuse Contact Email from comments (e.g. NIC Chile)
        if (preg_match('/Registry Abuse Contact Email:\s*(\S+@\S+)/i', $rawResponse, $m)) {
            $fields['registry_abuse_email'][] = trim($m[1]);
        }

        return $fields;
    }

    /**
     * @return array<string, string[]>
     */
    private function extractFields(string $text, string $serverHostname): array
    {
        $fields = [];
        $lines = explode("\n", $text);

        // Detect if this is a dot-padded sectioned format (.ax, .tn, .kz)
        $hasDotPadded = preg_match('/\.\.\.\.*:\s/', $text);
        $currentSection = null;

        foreach ($lines as $line) {
            $trimmed = trim($line);

            // Detect section headers (standalone word lines)
            if ($hasDotPadded && preg_match('/^(Holder|Owner|Registrant|Registrar|Nameservers|Administrative|Technical|Admin|Tech|DNS servers|Owner Contact|Administrativ contact|Technical contact)$/i', $trimmed, $sm)) {
                $sectionLower = strtolower($sm[1]);
                $currentSection = match(true) {
                    str_contains($sectionLower, 'holder'), str_contains($sectionLower, 'owner'), str_contains($sectionLower, 'registrant') => 'registrant',
                    str_contains($sectionLower, 'registrar') => 'registrar',
                    str_contains($sectionLower, 'admin') => 'admin',
                    str_contains($sectionLower, 'tech') => 'tech',
                    default => null,
                };
                continue;
            }

            // Reset section on blank line
            if ($trimmed === '' && $hasDotPadded) {
                // Don't reset section on blank lines within sections
            }

            // Match "Key: Value" with dots padding: "key...........: value"
            if (preg_match('/^([A-Za-z][A-Za-z0-9 \/_-]*?)\.{2,}\s*:\s*(.+)$/u', $trimmed, $m)) {
                $rawKey = trim($m[1]);
                $key = $this->normalizeKey($rawKey);
                $value = trim($m[2]);
                if ($value !== '') {
                    // Apply section prefix for contact fields
                    $key = $this->applySectionPrefix($key, $currentSection);
                    $fields[$key][] = $value;
                }
                continue;
            }

            // Match bracket-key format: [Key Name]    VALUE
            if (preg_match('/^\[([^\]]+)\]\s+(.+)$/u', $trimmed, $m)) {
                $key = $this->normalizeKey($m[1]);
                $value = trim($m[2]);
                if ($value !== '' && !str_starts_with($value, '(Not displayed')) {
                    $fields[$key][] = $value;
                }
                continue;
            }

            // Standard "Key: Value" or "Key:Value"
            if (preg_match('/^([A-Za-z\x{0080}-\x{FFFF}][A-Za-z0-9 \/_\-.*()#\'\x{0080}-\x{FFFF}]*?)\s*:\s*(.+)$/u', $trimmed, $m)) {
                $rawKey = trim($m[1]);
                if (preg_match('/^https?$/i', $rawKey) || preg_match('/^[a-z]{20,}$/i', $rawKey)) {
                    continue;
                }
                $key = $this->normalizeKey($rawKey);
                $value = trim($m[2]);
                if ($value !== '') {
                    $fields[$key][] = $value;
                }
                continue;
            }
        }

        // Handle section-based formats
        $this->parseIndentedSections($text, $fields, $serverHostname);

        return $fields;
    }

    private function applySectionPrefix(string $key, ?string $section): string
    {
        if ($section === null) {
            return $key;
        }

        if ($section === 'registrar') {
            return match($key) {
                'name', 'registrant_name' => 'registrar',
                'registrar_url', 'registrar_homepage' => 'registrar_url',
                default => $key,
            };
        }

        // Map generic/bare keys to section-prefixed contact keys
        // After normalizeKey, bare 'name' stays as 'name' (unmapped), 'holder_email' => 'registrant_email', etc.
        return match($key) {
            'name', 'registrant_name', 'person' => $section . '_name',
            'email', 'registrant_email' => $section . '_email',
            'phone', 'registrant_phone' => $section . '_phone',
            'fax' => $section . '_fax',
            'organization', 'registrant_organization' => $section . '_organization',
            'address', 'registrant_address' => $section . '_address',
            'country', 'registrant_country' => $section . '_country',
            'city', 'registrant_city' => $section . '_city',
            'state', 'registrant_state' => $section . '_state',
            'postal_code', 'registrant_postal_code' => $section . '_postal_code',
            default => $key,
        };
    }

    private function parseIndentedSections(string $text, array &$fields, string $serverHostname): void
    {
        // --- Nominet UK / .ac.uk / .gg / .je format ---
        $this->parseNominetFormat($text, $fields, $serverHostname);

        // --- IANA format: contact blocks ---
        $this->parseIanaFormat($text, $fields);

        // --- Italian .it format ---
        $this->parseItalianFormat($text, $fields);

        // --- .edu format ---
        $this->parseEduFormat($text, $fields);

        // --- Armenian .am format ---
        $this->parseArmenianFormat($text, $fields);

        // --- Belgian .be format ---
        $this->parseBelgianFormat($text, $fields);

        // --- .eu EURid format ---
        $this->parseEuFormat($text, $fields);

        // --- .sm format ---
        $this->parseSanMarinoFormat($text, $fields);

        // --- .mx format ---
        $this->parseMexicoFormat($text, $fields);

        // --- .ae format (aeda) ---
        $this->parseAeFormat($text, $fields);

        // --- .gov.za format ---
        $this->parseGovZaFormat($text, $fields);

        // --- Latvian .lv bracket sections ---
        $this->parseLatvianFormat($text, $fields);

        // --- .hk format ---
        $this->parseHkFormat($text, $fields);

        // --- Korean .kr format ---
        $this->parseKoreanFormat($text, $fields);

        // --- Czech/Malawi/MK FRED format: contact blocks ---
        $this->parseFredFormat($text, $fields);

        // --- .at / .priv.at RIPE-like format ---
        $this->parseAtFormat($text, $fields);

        // --- Tunisian .tn dot-padded sections ---
        $this->parseTunisianFormat($text, $fields);

        // --- .pf format ---
        $this->parsePfFormat($text, $fields);

        // --- .aw format ---
        $this->parseAwFormat($text, $fields);

        // --- .kz format ---
        $this->parseKzFormat($text, $fields);

        // --- Israeli .il format ---
        $this->parseIsraeliFormat($text, $fields);

        // --- .dk Punktum format ---
        $this->parseDkFormat($text, $fields);

        // --- .im format ---
        $this->parseImFormat($text, $fields);

        // --- .mo format ---
        $this->parseMoFormat($text, $fields);

        // --- .nc format ---
        $this->parseNcFormat($text, $fields);

        // --- Japanese .jp bracket format contact ---
        $this->parseJpContactSection($text, $fields);

        // --- Estonian .ee format ---
        $this->parseEstonianFormat($text, $fields);

        // --- Togo .tg format (JWhoisServer dot-padded) ---
        $this->parseTgFormat($text, $fields);

        // --- JWhoisServer bracket-section format (.gf/.gp/.mq) ---
        $this->parseJWhoisBracketFormat($text, $fields);

        // --- Slovak .sk format ---
        $this->parseSkFormat($text, $fields);

        // --- Serbian .rs RNIDS format ---
        $this->parseSerbianFormat($text, $fields);

        // --- Turkish .tr format ---
        $this->parseTurkishFormat($text, $fields);

        // --- Taiwanese .tw format ---
        $this->parseTaiwaneseFormat($text, $fields);

        // --- Generic nameserver blocks ---
        $this->parseNameserverBlocks($text, $fields);
    }

    private function parseNominetFormat(string $text, array &$fields, string $server): void
    {
        // Nominet-style: indented domain name
        if (preg_match('/^Domain:\s*\n\s+(\S.+)$/m', $text, $m)) {
            $fields['domain_name'][] = strtolower(trim($m[1]));
        }

        // "Registered on 01st April 2018 at 04:14:07.826" (.gg/.je)
        if (preg_match('/Registered on\s+(\d{1,2}(?:st|nd|rd|th)\s+\w+\s+\d{4}(?:\s+at\s+[\d:.]+)?)/i', $text, $m)) {
            $dateStr = preg_replace('/(\d)(st|nd|rd|th)/i', '$1', $m[1]);
            $dateStr = preg_replace('/\s+at\s+/', ' ', $dateStr);
            $parsed = $this->parseDate($dateStr);
            if ($parsed !== null) {
                $fields['creation_date'][] = $parsed;
            }
        }

        // Registrar with URL in parens: "NameCheap, Inc (https://www.namecheap.com)"
        // But NOT tab-indented (Belgian format) or key:value indented
        if (preg_match('/^Registrar:\s*\n\s+(.+)/m', $text, $m) && !preg_match('/^Registrar:\s*\n[ \t]+\w+:/m', $text)) {
            $regLine = trim($m[1]);
            if (preg_match('/^(.+?)\s*\(([^)]+)\)\s*$/', $regLine, $rm)) {
                if (!isset($fields['registrar']) || empty($fields['registrar'])) {
                    $fields['registrar'][] = trim($rm[1]);
                }
                if (preg_match('#https?://#', $rm[2]) && !isset($fields['registrar_url'])) {
                    $fields['registrar_url'][] = trim($rm[2]);
                }
            } elseif (preg_match('/^(.+?)(?:\s*\[Tag\s*=.*\])?\s*$/', $regLine, $rm)) {
                if (!isset($fields['registrar']) || empty($fields['registrar'])) {
                    $fields['registrar'][] = trim($rm[1]);
                }
            }
        }

        // Registrant as indented block (.gg/.je): "Registrant:\n     Name"
        // But NOT when the indented line is a key:value pair (like "Name: value")
        if (preg_match('/^Registrant:\s*\n\s{2,}(.+)$/m', $text, $m)) {
            $val = trim($m[1]);
            if ($val !== '' && !str_contains($val, ':') && !preg_match('/^NOT DISCLOSED/i', $val) && !preg_match('/^Not shown/i', $val)) {
                if (!isset($fields['registrant_organization']) || empty($fields['registrant_organization'])) {
                    $fields['registrant_organization'][] = $val;
                }
            }
        }

        // Nominet name servers indented
        if (preg_match('/^(?:Name servers|Name Servers):\s*\n((?:[ \t]+\S+.*\n?)+)/m', $text, $m)) {
            $nsBlock = trim($m[1]);
            foreach (explode("\n", $nsBlock) as $ns) {
                $ns = trim($ns);
                if ($ns !== '' && preg_match('/^[a-z0-9.-]+$/i', explode("\t", $ns)[0] ?? '')) {
                    $fields['name_server'][] = explode("\t", $ns)[0];
                }
            }
        }

        // Nominet dates
        if (preg_match('/Registered on:\s*(.+)/m', $text, $m)) {
            $fields['creation_date'][] = trim($m[1]);
        }
        if (preg_match('/Expiry date:\s*(.+)/m', $text, $m)) {
            $fields['expiry_date'][] = trim($m[1]);
        }
        if (preg_match('/Last updated:\s*(.+)/m', $text, $m)) {
            if (!isset($fields['updated_date']) || empty($fields['updated_date'])) {
                $fields['updated_date'][] = trim($m[1]);
            }
        }

        // .ac.uk format
        $this->parseAcUkFormat($text, $fields);
    }

    private function parseAcUkFormat(string $text, array &$fields): void
    {
        // Registered By: / Registered For: / Domain Owner:
        if (preg_match('/^Registered By:\s*\n\s+(.+)/m', $text, $m)) {
            $fields['registrar'][] = trim($m[1]);
        }
        if (preg_match('/^Domain Owner:\s*\n\s+(.+)/m', $text, $m)) {
            $fields['registrant_organization'][] = trim($m[1]);
        }
        if (preg_match('/^Registered For:\s*\n\s+(.+)/m', $text, $m)) {
            // "Registered For" = description/org
        }

        // Registrant Contact: / Registrant Address: blocks
        if (preg_match('/^Registrant Contact:\s*\n\s+(.+)/m', $text, $m)) {
            $fields['registrant_name'][] = trim($m[1]);
        }

        // Registrant Address block with phone/fax/email
        if (preg_match('/Registrant Address:\s*\n((?:[ \t]+.+\n)+)/m', $text, $m)) {
            $addrLines = [];
            $phone = null;
            $fax = null;
            $email = null;
            foreach (explode("\n", trim($m[1])) as $line) {
                $line = trim($line);
                if ($line === '') continue;
                if (preg_match('/^([\+\d][\d .()-]+)\s*\(Phone\)/i', $line, $pm)) {
                    $phone = trim($pm[1]);
                } elseif (preg_match('/^([\+\d][\d .()-]+)\s*\(FAX\)/i', $line, $pm)) {
                    $fax = trim($pm[1]);
                } elseif (preg_match('/^[\w.+-]+@[\w.-]+$/i', $line)) {
                    $email = $line;
                } else {
                    $addrLines[] = $line;
                }
            }
            if ($addrLines) {
                // Use newlines if any line contains a comma, otherwise commas
                $hasComma = false;
                foreach ($addrLines as $al) {
                    if (str_contains($al, ',')) { $hasComma = true; break; }
                }
                $sep = $hasComma ? "\n" : ", ";
                $fields['registrant_address'][] = implode($sep, $addrLines);
            }
            if ($phone) $fields['registrant_phone'][] = $phone;
            if ($fax) $fields['registrant_fax'][] = $fax;
            if ($email) $fields['registrant_email'][] = $email;
        }

        // Servers block with hostname + IP
        if (preg_match('/^Servers:\s*\n((?:[ \t]+.+\n)+)/m', $text, $m)) {
            $nsData = [];
            foreach (explode("\n", trim($m[1])) as $line) {
                $line = trim($line);
                if ($line === '') continue;
                $parts = preg_split('/\s+/', $line);
                $hostname = strtolower($parts[0]);
                $ip = $parts[1] ?? null;
                if (!isset($nsData[$hostname])) {
                    $nsData[$hostname] = ['ipv4' => null, 'ipv6' => null];
                }
                if ($ip !== null) {
                    if (str_contains($ip, ':')) {
                        if ($nsData[$hostname]['ipv6'] === null) {
                            $nsData[$hostname]['ipv6'] = $ip;
                        }
                    } else {
                        if ($nsData[$hostname]['ipv4'] === null) {
                            $nsData[$hostname]['ipv4'] = $ip;
                        }
                    }
                }
            }
            foreach ($nsData as $host => $ips) {
                $fields['name_server_detail'][] = json_encode([
                    'hostname' => $host,
                    'ipv4' => $ips['ipv4'],
                    'ipv6' => $ips['ipv6'],
                ]);
            }
        }

        // UK-style dates: "Thursday 23rd Mar 2028"
        if (preg_match('/^Renewal date:\s*\n\s+(.+)/m', $text, $m)) {
            $fields['expiry_date'][] = trim($m[1]);
        }
        if (preg_match('/^Entry updated:\s*\n\s+(.+)/m', $text, $m)) {
            $fields['updated_date'][] = trim($m[1]);
        }
        if (preg_match('/^Entry created:\s*\n\s+(.+)/m', $text, $m)) {
            $fields['creation_date'][] = trim($m[1]);
        }
    }

    private function parseIanaFormat(string $text, array &$fields): void
    {
        if (!str_contains($text, 'IANA')) {
            return;
        }

        // Only process as IANA if it's actually an IANA WHOIS response (has "source: IANA")
        $isIanaResponse = (bool) preg_match('/^source:\s+IANA$/m', $text);

        if ($isIanaResponse) {
            // Clear "changed:" dates that were mapped to updated_date by standard parser
            // IANA "changed:" is not an update date for the domain
            unset($fields['updated_date']);
        }

        // IANA nserver with IPs: "nserver:      A.IN-ADDR-SERVERS.ARPA 199.180.182.53 2620:37:e000::53"
        if (preg_match_all('/^nserver:[ \t]+(\S+)(?:[ \t]+(.+))?$/m', $text, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $m) {
                $hostname = strtolower(rtrim($m[1], '.'));
                $rest = isset($m[2]) ? trim($m[2]) : '';
                $ipv4 = null;
                $ipv6 = null;
                if ($rest !== '') {
                    foreach (preg_split('/\s+/', $rest) as $ip) {
                        $ip = trim($ip);
                        if (str_contains($ip, ':')) {
                            // Normalize IPv6 to shortened form
                            $packed = @inet_pton($ip);
                            $ipv6 = ($packed !== false) ? inet_ntop($packed) : $ip;
                        } elseif (preg_match('/^\d+\.\d+\.\d+\.\d+$/', $ip)) {
                            $ipv4 = $ip;
                        }
                    }
                }
                $fields['name_server_detail'][] = json_encode([
                    'hostname' => $hostname,
                    'ipv4' => $ipv4,
                    'ipv6' => $ipv6,
                ]);
            }
        }

        // ds-rdata means signedDelegation
        if (preg_match('/^ds-rdata:/m', $text)) {
            $fields['dnssec'][] = 'signedDelegation';
        }

        // IANA contact blocks
        $contactPattern = '/^contact:\s+(administrative|technical)\s*\n((?:(?:name|organisation|address|phone|fax-no|e-mail):\s+.+\n?)+)/m';
        if (preg_match_all($contactPattern, $text, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $cm) {
                $type = $cm[1] === 'administrative' ? 'admin' : 'tech';
                $block = $cm[2];
                $cFields = $this->parseKeyValueBlock($block);
                $fields["{$type}_name"][] = $cFields['name'] ?? '';
                if (isset($cFields['organisation'])) {
                    $fields["{$type}_organization"][] = $cFields['organisation'];
                }
                if (isset($cFields['e-mail'])) {
                    $fields["{$type}_email"][] = $cFields['e-mail'];
                }
                if (isset($cFields['phone'])) {
                    $fields["{$type}_phone"][] = $cFields['phone'];
                }
                if (isset($cFields['fax-no'])) {
                    $fields["{$type}_fax"][] = $cFields['fax-no'];
                }
                // Address: multiple lines
                $addrLines = [];
                if (preg_match_all('/^address:\s+(.+)$/m', $block, $am)) {
                    $addrLines = $am[1];
                }
                if ($addrLines) {
                    $fields["{$type}_address"][] = implode(', ', $addrLines);
                }
            }
        }

        // Organisation as registrant
        if (preg_match('/^organisation:\s+(.+)$/m', $text, $m)) {
            $org = trim($m[1]);
            if (!isset($fields['registrant_organization']) || empty($fields['registrant_organization'])) {
                $fields['registrant_organization'][] = $org;
            }
        }

        // IANA registrant address (top-level, before contact blocks)
        $orgAddrLines = [];
        if (preg_match('/^organisation:\s+.+\n((?:address:\s+.+\n)+)/m', $text, $m)) {
            if (preg_match_all('/^address:\s+(.+)$/m', $m[1], $am)) {
                $orgAddrLines = $am[1];
            }
        }
        if ($orgAddrLines) {
            $fields['registrant_address'][] = implode(', ', $orgAddrLines);
        }
    }

    private function parseKeyValueBlock(string $block): array
    {
        $result = [];
        foreach (explode("\n", $block) as $line) {
            if (preg_match('/^(\S+):\s+(.+)$/', trim($line), $m)) {
                $key = $m[1];
                if (!isset($result[$key])) {
                    $result[$key] = trim($m[2]);
                }
            }
        }
        return $result;
    }

    private function parseItalianFormat(string $text, array &$fields): void
    {
        // .it format: sections with 2-space indented key: value
        // Check for the distinctive .it pattern
        if (!preg_match('/^Domain:\s+\S+\.it$/m', $text) &&
            !preg_match('/^Registrant\s*$/m', $text)) {
            return;
        }

        // Registrant section
        if (preg_match('/^Registrant\s*\n((?:\s{2}.+\n)+)/m', $text, $m)) {
            $block = $m[1];
            $this->parseItContactBlock($block, 'registrant', $fields);
        }

        // Admin Contact
        if (preg_match('/^Admin Contact\s*\n((?:\s{2}.+\n)+)/m', $text, $m)) {
            $this->parseItContactBlock($m[1], 'admin', $fields);
        }

        // Technical Contacts
        if (preg_match('/^Technical Contacts?\s*\n((?:\s{2}.+\n)+)/m', $text, $m)) {
            $this->parseItContactBlock($m[1], 'tech', $fields);
        }

        // Registrar section
        if (preg_match('/^Registrar\s*\n((?:\s{2}.+\n)+)/m', $text, $m)) {
            $block = $m[1];
            if (preg_match('/Organization:\s+(.+)/m', $block, $rm)) {
                $fields['registrar'][] = trim($rm[1]);
            }
            if (preg_match('/Web:\s+(.+)/m', $block, $rm)) {
                $fields['registrar_url'][] = trim($rm[1]);
            }
            if (preg_match('/DNSSEC:\s+(.+)/m', $block, $rm)) {
                $val = strtolower(trim($rm[1]));
                if ($val === 'yes') {
                    $fields['dnssec'][] = 'signedDelegation';
                } elseif ($val === 'no') {
                    $fields['dnssec'][] = 'unsigned';
                }
            }
        }

        // Nameservers section (bare hostnames)
        if (preg_match('/^Nameservers\s*\n((?:\s{2}\S+.*\n)+)/m', $text, $m)) {
            foreach (explode("\n", trim($m[1])) as $ns) {
                $ns = strtolower(trim($ns));
                if ($ns !== '' && preg_match('/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$/i', $ns)) {
                    $fields['name_server'][] = $ns;
                }
            }
        }

        // Signed field (top-level)
        if (preg_match('/^Signed:\s+(.+)$/m', $text, $m)) {
            $val = strtolower(trim($m[1]));
            if ($val === 'yes') {
                $fields['dnssec'][] = 'signedDelegation';
            } elseif ($val === 'no' && !isset($fields['dnssec'])) {
                // Will be overridden by Registrar DNSSEC if present
            }
        }
    }

    private function parseItContactBlock(string $block, string $prefix, array &$fields): void
    {
        if (preg_match('/Name:\s+(.+)/m', $block, $m)) {
            $fields["{$prefix}_name"][] = trim($m[1]);
        }
        if (preg_match('/Organization:\s+(.+)/m', $block, $m)) {
            $fields["{$prefix}_organization"][] = trim($m[1]);
        }

        // Multi-line address with continuation lines (20+ spaces indent)
        if (preg_match('/Address:\s+(.+(?:\n\s{16,}.+)*)/m', $block, $m)) {
            $addrText = $m[1];
            $addrLines = [];
            foreach (explode("\n", $addrText) as $line) {
                $line = trim($line);
                if ($line !== '') {
                    $addrLines[] = $line;
                }
            }
            if ($addrLines) {
                $fields["{$prefix}_address"][] = implode("\n", $addrLines);
            }
        }
    }

    private function parseEduFormat(string $text, array &$fields): void
    {
        if (!preg_match('/Domain Name:\s+\S+\.EDU/i', $text)) {
            return;
        }

        // Registrant block (tab-indented, no "key: value", just lines)
        if (preg_match('/^Registrant:\s*\n((?:\t.+\n)+)/m', $text, $m)) {
            $lines = array_map('trim', explode("\n", trim($m[1])));
            if (count($lines) >= 1) {
                $fields['registrant_organization'][] = $lines[0];
                $addrLines = array_slice($lines, 1);
                if ($addrLines) {
                    $fields['registrant_address'][] = implode(', ', $addrLines);
                }
            }
        }

        // Admin/Tech contact blocks
        foreach (['Administrative' => 'admin', 'Technical' => 'tech'] as $label => $prefix) {
            if (preg_match('/^' . $label . ' Contact:\s*\n((?:\t.+\n)+)/m', $text, $m)) {
                $lines = array_map('trim', explode("\n", trim($m[1])));
                $name = null;
                $org = null;
                $addrLines = [];
                $phone = null;
                $email = null;

                // First line is name
                if (isset($lines[0])) $name = $lines[0];
                // Second line might be org if different from name
                $idx = 1;
                if (isset($lines[$idx]) && !preg_match('/^\d/', $lines[$idx]) && !preg_match('/^[\+]/', $lines[$idx])) {
                    $org = $lines[$idx];
                    $idx++;
                }

                for ($i = $idx; $i < count($lines); $i++) {
                    $line = $lines[$i];
                    if (preg_match('/^[\+\d][\d .()-]+$/', $line)) {
                        $phone = $line;
                    } elseif (preg_match('/^[\w.+-]+@[\w.-]+$/', $line)) {
                        $email = $line;
                    } else {
                        $addrLines[] = $line;
                    }
                }

                if ($name) $fields["{$prefix}_name"][] = $name;
                if ($org) $fields["{$prefix}_organization"][] = $org;
                if ($phone) $fields["{$prefix}_phone"][] = $phone;
                if ($email) $fields["{$prefix}_email"][] = $email;
                if ($addrLines) $fields["{$prefix}_address"][] = implode(', ', $addrLines);
            }
        }

        // Name Servers block (tab-indented)
        if (preg_match('/^Name Servers:\s*\n((?:\t.+\n?)+)/m', $text, $m)) {
            foreach (explode("\n", trim($m[1])) as $ns) {
                $ns = strtolower(trim($ns));
                if ($ns !== '' && preg_match('/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$/i', $ns)) {
                    $fields['name_server'][] = $ns;
                }
            }
        }

        // Edu-specific date fields
        if (preg_match('/Domain record activated:\s+(.+)/m', $text, $m)) {
            $fields['creation_date'][] = trim($m[1]);
        }
        if (preg_match('/Domain record last updated:\s+(.+)/m', $text, $m)) {
            $fields['updated_date'][] = trim($m[1]);
        }
        if (preg_match('/Domain expires:\s+(.+)/m', $text, $m)) {
            $fields['expiry_date'][] = trim($m[1]);
        }
    }

    private function parseArmenianFormat(string $text, array &$fields): void
    {
        if (!preg_match('/AM TLD|\.am$/m', $text)) {
            return;
        }

        // Contact blocks: "   Registrant:\n      Name\n      Address lines"
        foreach (['Registrant' => 'registrant', 'Administrative contact' => 'admin', 'Technical contact' => 'tech'] as $label => $prefix) {
            $pattern = '/^\s+' . preg_quote($label, '/') . ':\s*\n((?:\s{6,}.+\n)+)/m';
            if (preg_match($pattern, $text, $m)) {
                $lines = array_map('trim', array_filter(explode("\n", $m[1]), fn($l) => trim($l) !== ''));
                if (empty($lines)) continue;

                $name = $lines[0];
                $addrLines = [];
                $email = null;
                $phone = null;

                for ($i = 1; $i < count($lines); $i++) {
                    $line = $lines[$i];
                    if (preg_match('/^[\w.+-]+@[\w.-]+$/', $line)) {
                        $email = $line;
                    } elseif (preg_match('/^\+?\d[\d ()-]+$/', $line)) {
                        $phone = $line;
                    } else {
                        $addrLines[] = $line;
                    }
                }

                $fields["{$prefix}_name"][] = $name;
                if ($email) $fields["{$prefix}_email"][] = $email;
                if ($phone) $fields["{$prefix}_phone"][] = $phone;
                if ($addrLines) {
                    $addr = implode(', ', $addrLines);
                    // Normalize multiple spaces (e.g., "Kyiv,  02095" -> "Kyiv, 02095")
                    $addr = preg_replace('/,\s{2,}/', ', ', $addr);
                    $fields["{$prefix}_address"][] = $addr;
                }
            }
        }

        // DNS servers: "   DNS servers:\n      hostname"
        if (preg_match('/^\s+DNS servers:\s*\n((?:\s{6,}\S+.*\n)+)/m', $text, $m)) {
            foreach (explode("\n", trim($m[1])) as $ns) {
                $ns = strtolower(trim($ns));
                if ($ns !== '' && preg_match('/^[a-z0-9.-]+$/i', $ns)) {
                    $fields['name_server'][] = $ns;
                }
            }
        }
    }

    private function parseBelgianFormat(string $text, array &$fields): void
    {
        // Belgian format: tab-indented sections with Registrar/Nameservers/Registrant
        if (!preg_match('/^Registrar:\s*\n\t/m', $text)) {
            return;
        }

        // Registrar section (tab-indented)
        if (preg_match('/^Registrar:\s*\n((?:\t.+\n)+)/m', $text, $m)) {
            $block = $m[1];
            if (preg_match('/Name:\s+(.+)/m', $block, $rm)) {
                $fields['registrar'][] = trim($rm[1]);
            }
            if (preg_match('/Website:\s+(.+)/m', $block, $rm)) {
                $fields['registrar_url'][] = trim($rm[1]);
            }
        }

        // Nameservers section (tab-indented)
        if (preg_match('/^Nameservers:\s*\n((?:\t\S+.*\n?)+)/m', $text, $m)) {
            foreach (explode("\n", trim($m[1])) as $ns) {
                $ns = strtolower(trim($ns));
                if ($ns !== '' && preg_match('/^[a-z0-9.-]+$/i', $ns)) {
                    $fields['name_server'][] = $ns;
                }
            }
        }
    }

    private function parseEuFormat(string $text, array &$fields): void
    {
        if (!preg_match('/EURid|eurid\.eu|WHOIS \S+\.eu$/m', $text)) {
            return;
        }

        // Technical contact block
        if (preg_match('/^Technical:\s*\n((?:[ \t]+.+\n)+)/m', $text, $m)) {
            $block = $m[1];
            if (preg_match('/Organisation:\s+(.+)/m', $block, $rm)) {
                $fields['tech_organization'][] = trim($rm[1]);
            }
            if (preg_match('/Email:\s+(.+)/m', $block, $rm)) {
                $fields['tech_email'][] = trim($rm[1]);
            }
        }

        // Registrar block - override any previously extracted registrar
        if (preg_match('/^Registrar:\s*\n((?:[ \t]+.+\n)+)/m', $text, $m)) {
            $block = $m[1];
            if (preg_match('/Name:\s+(.+)/m', $block, $rm)) {
                $fields['registrar'] = [trim($rm[1])];
            }
            if (preg_match('/Website:\s+(.+)/m', $block, $rm)) {
                $fields['registrar_url'] = [trim($rm[1])];
            }
        }

        // Name servers
        if (preg_match('/^Name servers:\s*\n((?:[ \t]+\S+.*\n)+)/m', $text, $m)) {
            foreach (explode("\n", trim($m[1])) as $ns) {
                $ns = strtolower(trim($ns));
                if ($ns !== '' && preg_match('/^[a-z0-9.-]+$/i', $ns)) {
                    $fields['name_server'][] = $ns;
                }
            }
        }
    }

    private function parseSanMarinoFormat(string $text, array &$fields): void
    {
        if (!preg_match('/\.sm$/m', $text)) {
            return;
        }

        // Owner block
        if (preg_match('/^Owner:\s*\n((?:(?!\n(?:Technical|DNS|Administrative|Billing)\b).+\n)+)/m', $text, $m)) {
            $lines = array_map('trim', array_filter(explode("\n", trim($m[1])), fn($l) => trim($l) !== ''));
            if (empty($lines)) return;

            $org = $lines[0];
            $addrLines = [];
            $phone = null;
            $email = null;

            for ($i = 1; $i < count($lines); $i++) {
                $line = $lines[$i];
                if (preg_match('/^Phone:\s+(.+)/i', $line, $pm)) {
                    $phone = trim($pm[1]);
                } elseif (preg_match('/^Email:\s+(.+)/i', $line, $pm)) {
                    $email = trim($pm[1]);
                } else {
                    $addrLines[] = $line;
                }
            }

            $fields['registrant_organization'][] = $org;
            if ($phone) $fields['registrant_phone'][] = $phone;
            if ($email) $fields['registrant_email'][] = $email;
            if ($addrLines) $fields['registrant_address'][] = implode(', ', $addrLines);
        }

        // Technical Contact block
        if (preg_match('/^Technical Contact:\s*\n((?:(?!\n(?:Owner|DNS|Administrative|Billing)\b).+\n)+)/m', $text, $m)) {
            $lines = array_map('trim', array_filter(explode("\n", trim($m[1])), fn($l) => trim($l) !== ''));
            if (empty($lines)) return;

            $name = $lines[0];
            $org = null;
            $addrLines = [];
            $phone = null;
            $email = null;

            $idx = 1;
            // Check if second line is org (not an address pattern)
            if (isset($lines[$idx]) && !preg_match('/^\d/', $lines[$idx]) && !preg_match('/^Phone:/i', $lines[$idx]) && !preg_match('/^Email:/i', $lines[$idx])) {
                // Could be org or address - check if it's a company name
                if (preg_match('/\b(srl|ltd|llc|spa|gmbh|inc|corp)\b/i', $lines[$idx])) {
                    $org = $lines[$idx];
                    $idx++;
                }
            }

            for ($i = $idx; $i < count($lines); $i++) {
                $line = $lines[$i];
                if (preg_match('/^Phone:\s+(.+)/i', $line, $pm)) {
                    $phone = trim($pm[1]);
                } elseif (preg_match('/^Email:\s+(.+)/i', $line, $pm)) {
                    $email = trim($pm[1]);
                } else {
                    $addrLines[] = $line;
                }
            }

            $fields['tech_name'][] = $name;
            if ($org) $fields['tech_organization'][] = $org;
            if ($phone) $fields['tech_phone'][] = $phone;
            if ($email) $fields['tech_email'][] = $email;
            if ($addrLines) $fields['tech_address'][] = implode(', ', $addrLines);
        }

        // DNS Servers block
        if (preg_match('/^DNS Servers:\s*\n((?:\S+.*\n)+)/m', $text, $m)) {
            foreach (explode("\n", trim($m[1])) as $ns) {
                $ns = strtolower(trim($ns));
                if ($ns !== '' && preg_match('/^[a-z0-9.-]+$/i', $ns)) {
                    $fields['name_server'][] = $ns;
                }
            }
        }
    }

    private function parseMexicoFormat(string $text, array &$fields): void
    {
        // .mx format has indented contact sections
        if (!preg_match('/\.com\.mx$|\.mx$/m', $text)) {
            return;
        }

        foreach (['Registrant' => 'registrant', 'Administrative Contact' => 'admin', 'Technical Contact' => 'tech', 'Billing Contact' => 'billing'] as $label => $prefix) {
            $pattern = '/^' . preg_quote($label, '/') . ':\s*\n((?:\s{3,}.+\n)+)/m';
            if (preg_match($pattern, $text, $m)) {
                $block = $m[1];
                $name = null;
                $city = null;
                $state = null;
                $country = null;

                if (preg_match('/Name:\s+(.+)/m', $block, $rm)) $name = trim($rm[1]);
                if (preg_match('/City:\s+(.+)/m', $block, $rm)) $city = trim($rm[1]);
                if (preg_match('/State:\s+(.+)/m', $block, $rm)) $state = trim($rm[1]);
                if (preg_match('/Country:\s+(.+)/m', $block, $rm)) $country = trim($rm[1]);

                if ($name) $fields["{$prefix}_name"][] = $name;

                $addrParts = array_filter([$city, $state, $country]);
                if ($addrParts) {
                    $fields["{$prefix}_address"][] = implode(', ', $addrParts);
                }
            }
        }

        // DNS entries
        if (preg_match('/^Name Servers:\s*\n((?:[ \t]+DNS:\s+\S+.*\n)+)/m', $text, $m)) {
            foreach (explode("\n", trim($m[1])) as $line) {
                if (preg_match('/DNS:\s+(\S+)/i', trim($line), $nm)) {
                    $fields['name_server'][] = strtolower(trim($nm[1]));
                }
            }
        }
    }

    private function parseAeFormat(string $text, array &$fields): void
    {
        // Already handled by standard key:value parsing
    }

    private function parseGovZaFormat(string $text, array &$fields): void
    {
        // .gov.za format: "1a.  Domain Name : xxx"
        if (!preg_match('/^\d+[a-z]\.\s/m', $text)) {
            return;
        }

        if (preg_match('/Domain Name\s*:\s*(.+)/m', $text, $m)) {
            $fields['domain_name'][] = strtolower(trim($m[1]));
        }
        if (preg_match('/Department Name\s*:\s*(.+)/m', $text, $m)) {
            $fields['registrant_organization'][] = trim($m[1]);
        }

        // 2b postal address
        if (preg_match('/2b\.\s+Postal Address\s*:\s*(.+)/m', $text, $m)) {
            $fields['registrant_address'][] = trim($m[1]);
        }

        // Admin contact
        if (preg_match('/Admin Contact Name\s*:\s*(.+)/m', $text, $m)) {
            $fields['admin_name'][] = trim($m[1]);
        }
        if (preg_match('/3d\.\s+Email\s*:\s*(.+)/m', $text, $m)) {
            $fields['admin_email'][] = trim($m[1]);
        }
        if (preg_match('/3e\.\s+Postal Address\s*:\s*(.+)/m', $text, $m)) {
            $fields['admin_address'][] = trim($m[1]);
        }

        // Tech contact
        if (preg_match('/Tech Contact Name\s*:\s*(.+)/m', $text, $m)) {
            $fields['tech_name'][] = trim($m[1]);
        }
        if (preg_match('/4d\.\s+Email\s*:\s*(.+)/m', $text, $m)) {
            $fields['tech_email'][] = trim($m[1]);
        }
        if (preg_match('/4e\.\s+Postal Address\s*:\s*(.+)/m', $text, $m)) {
            $fields['tech_address'][] = trim($m[1]);
        }

        // Nameservers
        if (preg_match('/Primary NS\s*:\s*(.+)/m', $text, $m)) {
            $hostname = strtolower(trim($m[1]));
            $ipv4 = null;
            if (preg_match('/Primary NS IP\s*:\s*(\S+)/m', $text, $ipm)) {
                $ipv4 = trim($ipm[1]);
            }
            $fields['name_server_detail'][] = json_encode(['hostname' => $hostname, 'ipv4' => $ipv4, 'ipv6' => null]);
        }
        if (preg_match('/1st Secondary NS\s*:\s*(.+)/m', $text, $m)) {
            $hostname = strtolower(trim($m[1]));
            $ipv4 = null;
            if (preg_match('/1st Secondary NS IP\s*:\s*(\S+)/m', $text, $ipm)) {
                $ipv4 = trim($ipm[1]);
            }
            $fields['name_server_detail'][] = json_encode(['hostname' => $hostname, 'ipv4' => $ipv4, 'ipv6' => null]);
        }

        // Date
        if (preg_match('/6b\.\s+Date\s*:\s*(.+)/m', $text, $m)) {
            $fields['creation_date'][] = trim($m[1]);
        }
    }

    private function parseLatvianFormat(string $text, array &$fields): void
    {
        if (!preg_match('/^\[Domain\]/m', $text)) {
            return;
        }

        // [Holder] section
        if (preg_match('/^\[Holder\]\s*\n((?:(?!\[).+\n)+)/m', $text, $m)) {
            $block = $m[1];
            if (preg_match('/^Name:\s+(.+)/m', $block, $rm)) {
                $fields['registrant_name'][] = trim($rm[1]);
            }
            if (preg_match('/^Address:\s+(.+)/m', $block, $rm)) {
                $fields['registrant_address'][] = trim($rm[1]);
            }
            if (preg_match('/^Country:\s+(.+)/m', $block, $rm)) {
                if (!isset($fields['registrant_address'])) {
                    $fields['registrant_address'][] = trim($rm[1]);
                }
            }
        }

        // Clear "Updated" from [Whois] section - it's the database update time, not domain update
        unset($fields['updated_date']);

        // [Nservers] section
        if (preg_match('/^\[Nservers\]\s*\n((?:(?!\[).+\n)+)/m', $text, $m)) {
            foreach (explode("\n", trim($m[1])) as $line) {
                if (preg_match('/^Nserver:\s+(.+)/i', trim($line), $nm)) {
                    $fields['name_server'][] = strtolower(trim($nm[1]));
                }
            }
        }
    }

    private function parseHkFormat(string $text, array &$fields): void
    {
        if (!preg_match('/HKIRC|\.hk/i', $text)) {
            return;
        }

        // Domain Name Commencement Date / Expiry Date
        if (preg_match('/Domain Name Commencement Date:\s+(.+)/m', $text, $m)) {
            $fields['creation_date'][] = trim($m[1]);
        }
        if (preg_match('/Expiry Date:\s+(.+)/m', $text, $m)) {
            $fields['expiry_date'][] = trim($m[1]);
        }

        // Registrant info from "Company English Name" block
        if (preg_match('/Registrant Contact Information:\s*\n\n.*?Company English Name[^:]*:\s*([^\n]+)/ms', $text, $m)) {
            $org = trim($m[1]);
            if ($org !== '') {
                $fields['registrant_organization'][] = $org;
            }
        }
        if (preg_match('/Registrant Contact Information:.*?Address:\s*([^\n]+?)(?:\n.*?Country:\s*([^\n]+?))?(?:\n.*?Email:\s*([^\n]+?))?(?:\n)/ms', $text, $m)) {
            $addr = trim($m[1] ?? '');
            $country = isset($m[2]) ? trim($m[2]) : '';
            $email = isset($m[3]) ? trim($m[3]) : '';

            // Extract country from "Hong Kong (HK)" or "United States (US)"
            $countryName = preg_replace('/\s*\([A-Z]+\)\s*$/', '', $country);

            if ($addr !== '' && $countryName !== '') {
                $fields['registrant_address'][] = $addr . ', ' . $countryName;
            }
            if ($email !== '') {
                $fields['registrant_email'][] = $email;
            }
        }

        // Admin/Tech contact blocks
        foreach (['Administrative' => 'admin', 'Technical' => 'tech'] as $label => $prefix) {
            $pattern = '/^' . $label . ' Contact Information:\s*\n\n((?:.*?\n)+?)(?:\n(?:Account|Status|\s*$)|\z)/m';
            if (preg_match($pattern, $text, $m)) {
                $block = $m[1];
                $given = '';
                $family = '';
                $company = '';
                $addr = '';
                $country = '';
                $phone = '';
                $fax = '';
                $email = '';

                if (preg_match('/Given name:\s*(.+)/m', $block, $rm)) $given = trim($rm[1]);
                if (preg_match('/Family name:\s*(.+)/m', $block, $rm)) $family = trim($rm[1]);
                if (preg_match('/Company name:\s*(.+)/m', $block, $rm)) $company = trim($rm[1]);
                if (preg_match('/Address:\s*(.+)/m', $block, $rm)) $addr = trim($rm[1]);
                if (preg_match('/Country:\s*(.+)/m', $block, $rm)) $country = preg_replace('/\s*\([A-Z]+\)\s*$/', '', trim($rm[1]));
                if (preg_match('/Phone:\s*(.+)/m', $block, $rm)) $phone = trim($rm[1]);
                if (preg_match('/Fax:\s*(.+)/m', $block, $rm)) $fax = trim($rm[1]);
                if (preg_match('/Email:\s*(.+)/m', $block, $rm)) $email = trim($rm[1]);

                $name = trim("$given $family");
                if ($name !== '') $fields["{$prefix}_name"][] = $name;
                if ($company !== '') $fields["{$prefix}_organization"][] = $company;
                if ($phone !== '') $fields["{$prefix}_phone"][] = $phone;
                if ($fax !== '') $fields["{$prefix}_fax"][] = $fax;
                if ($email !== '') $fields["{$prefix}_email"][] = $email;
                if ($addr !== '' && $country !== '') {
                    $fields["{$prefix}_address"][] = $addr . ', ' . $country;
                }
            }
        }

        // Name Servers
        if (preg_match('/^Name Servers Information:\s*\n\n((?:\S+.*\n)+)/m', $text, $m)) {
            foreach (explode("\n", trim($m[1])) as $ns) {
                $ns = strtolower(trim($ns));
                if ($ns !== '' && preg_match('/^[a-z0-9.-]+$/i', $ns)) {
                    $fields['name_server'][] = $ns;
                }
            }
        }
    }

    private function parseKoreanFormat(string $text, array &$fields): void
    {
        if (!str_contains($text, '# ENGLISH')) {
            return;
        }

        // Use only the ENGLISH section
        $englishPart = '';
        if (preg_match('/# ENGLISH\s*\n(.+?)(?:\n\n-|$)/s', $text, $m)) {
            $englishPart = $m[1];
        }
        if ($englishPart === '') return;

        // Parse key: value from English section
        $engFields = [];
        foreach (explode("\n", $englishPart) as $line) {
            if (preg_match('/^([A-Za-z][A-Za-z0-9 ()-]*?)\s*:\s*(.+)$/u', trim($line), $m)) {
                $engFields[trim($m[1])][] = trim($m[2]);
            }
        }

        // Clear fields that may have been set by standard parser from Korean section
        $fields['domain_name'] = [];
        $fields['registrant_name'] = [];
        $fields['registrant_organization'] = [];
        $fields['registrant_address'] = [];
        $fields['admin_name'] = [];
        $fields['admin_email'] = [];
        $fields['admin_phone'] = [];
        $fields['creation_date'] = [];
        $fields['updated_date'] = [];
        $fields['expiry_date'] = [];

        if (isset($engFields['Domain Name'])) $fields['domain_name'][] = strtolower($engFields['Domain Name'][0]);
        if (isset($engFields['Registrant'])) $fields['registrant_organization'][] = $engFields['Registrant'][0];
        if (isset($engFields['Registrant Address'])) $fields['registrant_address'][] = $engFields['Registrant Address'][0];
        if (isset($engFields['Administrative Contact(AC)'])) $fields['admin_name'][] = $engFields['Administrative Contact(AC)'][0];
        if (isset($engFields['AC E-Mail'])) $fields['admin_email'][] = $engFields['AC E-Mail'][0];
        if (isset($engFields['AC Phone Number'])) $fields['admin_phone'][] = $engFields['AC Phone Number'][0];

        // Parse Korean date format: "2004. 10. 07."
        $parseKrDate = function(string $s): string {
            $s = trim($s);
            $s = preg_replace('/\.\s*$/', '', $s); // remove trailing dot
            $s = preg_replace('/\.\s+/', '-', $s); // "2004. 10. 07" -> "2004-10-07"
            return $s;
        };
        if (isset($engFields['Registered Date'])) $fields['creation_date'][] = $parseKrDate($engFields['Registered Date'][0]);
        if (isset($engFields['Last Updated Date'])) $fields['updated_date'][] = $parseKrDate($engFields['Last Updated Date'][0]);
        if (isset($engFields['Expiration Date'])) $fields['expiry_date'][] = $parseKrDate($engFields['Expiration Date'][0]);
        if (isset($engFields['Authorized Agency'])) {
            $val = $engFields['Authorized Agency'][0];
            // "Gabia, Inc.(http://www.gabia.co.kr)"
            if (preg_match('/^(.+?)\(([^)]+)\)$/', $val, $rm)) {
                $fields['registrar'][] = trim($rm[1]);
                $fields['registrar_url'][] = trim($rm[2]);
            } else {
                $fields['registrar'][] = $val;
            }
        }

        // Nameservers with IP
        if (preg_match_all('/Host Name\s*:\s*(\S+)\s*\n\s*IP Address\s*:\s*(\S+)/m', $englishPart, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $m) {
                $hostname = strtolower(trim($m[1]));
                $ip = trim($m[2]);
                $fields['name_server_detail'][] = json_encode([
                    'hostname' => $hostname,
                    'ipv4' => $ip,
                    'ipv6' => null,
                ]);
            }
        }
    }

    private function parseFredFormat(string $text, array &$fields): void
    {
        // FRED format used by .mw, .mk, etc: contact blocks with "contact: ID"
        if (!preg_match('/^contact:\s+\S+/m', $text)) {
            return;
        }

        // Get the domain's registrant/admin-c/tech-c references
        $registrantRef = null;
        $adminRef = null;
        $techRef = null;

        if (preg_match('/^registrant:\s+(\S+)/m', $text, $m)) $registrantRef = $m[1];
        if (preg_match('/^admin-c:\s+(\S+)/m', $text, $m)) $adminRef = $m[1];

        // Find nsset block to get nservers and tech-c
        $nssetRef = null;
        if (preg_match('/^nsset:\s+(\S+)/m', $text, $m)) $nssetRef = $m[1];

        // Parse nsset DEFINITION block for nservers (find the block that contains nserver: lines)
        if ($nssetRef && preg_match_all('/^nsset:\s+' . preg_quote($nssetRef, '/') . '\s*\n((?:(?:nserver|tech-c|registrar|created):\s+.+\n)*)/m', $text, $allNssets, PREG_SET_ORDER)) {
            // Find the block that has nserver: lines (the definition, not the reference)
            $m = null;
            foreach ($allNssets as $candidate) {
                if (preg_match('/^nserver:/m', $candidate[1])) {
                    $m = $candidate;
                    break;
                }
            }
        }
        if ($nssetRef && isset($m)) {
            $nsBlock = $m[1];
            if (preg_match_all('/^nserver:\s+(\S+)(?:\s+\(([^)]+)\))?/m', $nsBlock, $nsm, PREG_SET_ORDER)) {
                foreach ($nsm as $ns) {
                    $hostname = strtolower(rtrim(trim($ns[1]), '.'));
                    $ip = isset($ns[2]) ? trim($ns[2]) : null;
                    if ($ip) {
                        $fields['name_server_detail'][] = json_encode([
                            'hostname' => $hostname,
                            'ipv4' => $ip,
                            'ipv6' => null,
                        ]);
                    } else {
                        $fields['name_server'][] = $hostname;
                    }
                }
            }
            if (preg_match('/^tech-c:\s+(\S+)/m', $nsBlock, $m)) $techRef = $m[1];
        }

        // Parse contact blocks
        $contacts = [];
        if (preg_match_all('/^contact:\s+(\S+)\s*\n((?:(?:org|name|address|phone|fax-no|e-mail|registrar|created|changed):\s+.+\n)*)/m', $text, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $cm) {
                $contactId = $cm[1];
                $block = $cm[2];

                $cData = [];
                if (preg_match('/^org:\s+(.+)/m', $block, $rm)) $cData['org'] = trim($rm[1]);
                if (preg_match('/^name:\s+(.+)/m', $block, $rm)) $cData['name'] = trim($rm[1]);
                if (preg_match('/^phone:\s+(.+)/m', $block, $rm)) $cData['phone'] = trim($rm[1]);
                if (preg_match('/^fax-no:\s+(.+)/m', $block, $rm)) $cData['fax'] = trim($rm[1]);
                if (preg_match('/^e-mail:\s+(.+)/m', $block, $rm)) $cData['email'] = trim($rm[1]);

                // Multiple address lines
                $addrLines = [];
                if (preg_match_all('/^address:\s+(.+)/m', $block, $am)) {
                    foreach ($am[1] as $addr) {
                        $addr = trim($addr);
                        if ($addr !== '' && $addr !== '-') {
                            $addrLines[] = $addr;
                        }
                    }
                }
                if ($addrLines) $cData['address'] = implode(', ', $addrLines);

                $contacts[$contactId] = $cData;
            }
        }

        // Map contacts to types
        $typeMap = [
            $registrantRef => 'registrant',
            $adminRef => 'admin',
            $techRef => 'tech',
        ];

        foreach ($typeMap as $ref => $prefix) {
            if ($ref === null || !isset($contacts[$ref])) continue;
            $c = $contacts[$ref];

            // Override any values set by the standard parser (e.g., contact ID as name)
            if (isset($c['name'])) $fields["{$prefix}_name"] = [$c['name']];
            if (isset($c['org'])) $fields["{$prefix}_organization"] = [$c['org']];
            if (isset($c['email'])) $fields["{$prefix}_email"] = [$c['email']];
            if (isset($c['phone'])) $fields["{$prefix}_phone"] = [$c['phone']];
            if (isset($c['fax'])) $fields["{$prefix}_fax"] = [$c['fax']];
            if (isset($c['address'])) $fields["{$prefix}_address"] = [$c['address']];
        }
    }

    private function parseAtFormat(string $text, array &$fields): void
    {
        // .at format: RIPE-like with personname, organization blocks after domain
        if (!preg_match('/^source:\s+(AT-DOM|PRIVAT)/m', $text, $sourceMatch)) {
            return;
        }
        $isPrivat = ($sourceMatch[1] === 'PRIVAT');

        // nserver with remarks for IPs (AT-DOM only - PRIVAT remarks are not nserver IPs)
        $nservers = [];
        $currentNs = null;
        foreach (explode("\n", $text) as $line) {
            if (preg_match('/^nserver:\s+(\S+)/i', $line, $m)) {
                $currentNs = strtolower(trim($m[1]));
                $nservers[$currentNs] = ['ipv4' => null];
            } elseif (!$isPrivat && preg_match('/^remarks:\s+(\d+\.\d+\.\d+\.\d+)/i', $line, $m) && $currentNs !== null) {
                $nservers[$currentNs]['ipv4'] = $m[1];
            } elseif (!preg_match('/^remarks:/i', $line)) {
                $currentNs = null;
            }
        }
        // Add all nameservers as details to preserve order
        // (plain ones go first, then IP ones would otherwise jump ahead)
        if (!empty($nservers)) {
            // Clear any previously extracted nameservers
            unset($fields['name_server'], $fields['name_server_detail']);
            foreach ($nservers as $host => $data) {
                $fields['name_server_detail'][] = json_encode([
                    'hostname' => $host,
                    'ipv4' => $data['ipv4'],
                    'ipv6' => null,
                ]);
            }
        }

        // changed field as updated date
        // AT-DOM format: "changed: 20250307 14:32:33"
        // PRIVAT format: "changed: email 20170323" (in domain block)
        if (preg_match('/^changed:\s+(\d{8}\s+\d{2}:\d{2}:\d{2})/m', $text, $m)) {
            $fields['updated_date'][] = trim($m[1]);
        } elseif ($isPrivat) {
            // Extract dates from "changed:" lines in domain block (before first person: block)
            $domainBlock = $text;
            $personPos = strpos($text, "\nperson:");
            if ($personPos !== false) {
                $domainBlock = substr($text, 0, $personPos);
            }
            if (preg_match_all('/^changed:\s+\S+\s+(\d{8})/m', $domainBlock, $cm)) {
                // Use the last changed date
                $lastDate = end($cm[1]);
                $fields['updated_date'][] = $lastDate;
            }
        }

        // Person blocks - first one is registrant, match by registrant nic-hdl
        $registrantRef = null;
        $techRef = null;
        if (preg_match('/^registrant:\s+(\S+)/m', $text, $m)) $registrantRef = $m[1];
        if (preg_match('/^tech-c:\s+(\S+)/m', $text, $m)) $techRef = $m[1];

        // Parse person blocks
        if (preg_match_all('/^(?:personname:[ \t]*(.*)\n)((?:(?:organization|street address|postal code|city|country|phone|fax-no|e-mail|nic-hdl|changed|source):\s+.+\n)*)/m', $text, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $pm) {
                $personName = trim($pm[1]);
                $block = $pm[2];
                $nicHdl = '';
                if (preg_match('/^nic-hdl:\s+(\S+)/m', $block, $rm)) $nicHdl = $rm[1];

                $prefix = null;
                if ($registrantRef && $nicHdl === $registrantRef) $prefix = 'registrant';
                elseif ($techRef && $nicHdl === $techRef) $prefix = 'tech';

                if ($prefix === null) continue;

                if ($personName !== '') $fields["{$prefix}_name"][] = $personName;

                if (preg_match('/^organization:\s+(.+)/m', $block, $rm)) {
                    $fields["{$prefix}_organization"][] = trim($rm[1]);
                }
                if (preg_match('/^e-mail:\s+(.+)/m', $block, $rm)) {
                    $fields["{$prefix}_email"][] = trim($rm[1]);
                }
                if (preg_match('/^phone:\s+(.+)/m', $block, $rm)) {
                    $fields["{$prefix}_phone"][] = trim($rm[1]);
                }
                if (preg_match('/^fax-no:\s+(.+)/m', $block, $rm)) {
                    $fields["{$prefix}_fax"][] = trim($rm[1]);
                }

                $addrParts = [];
                if (preg_match('/^street address:\s+(.+)/m', $block, $rm)) $addrParts[] = trim($rm[1]);
                if (preg_match('/^postal code:\s+(.+)/m', $block, $rm)) $addrParts[] = trim($rm[1]);
                if (preg_match('/^city:\s+(.+)/m', $block, $rm)) $addrParts[] = trim($rm[1]);
                if (preg_match('/^country:\s+(.+)/m', $block, $rm)) $addrParts[] = trim($rm[1]);
                if ($addrParts) $fields["{$prefix}_address"][] = implode(', ', $addrParts);
            }
        }

        // Handle .priv.at: person blocks using "person:" instead of "personname:"
        if (preg_match_all('/^person:\s+(.+)\n((?:(?:address|phone|fax-no|e-mail|nic-hdl|changed|source):\s+.+\n)*)/m', $text, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $pm) {
                $personName = trim($pm[1]);
                $block = $pm[2];
                $nicHdl = '';
                if (preg_match('/^nic-hdl:\s+(\S+)/m', $block, $rm)) $nicHdl = $rm[1];

                // For .priv.at, first person block is registrant
                $prefix = 'registrant';
                if (isset($fields['registrant_name']) && !empty($fields['registrant_name'])) {
                    continue; // Already have registrant
                }

                if ($personName !== '') $fields["{$prefix}_name"][] = $personName;
                if (preg_match('/^e-mail:\s+(.+)/m', $block, $rm)) {
                    $fields["{$prefix}_email"][] = trim($rm[1]);
                }
                if (preg_match('/^phone:\s+(.+)/m', $block, $rm)) {
                    $fields["{$prefix}_phone"][] = trim($rm[1]);
                }
                if (preg_match('/^fax-no:\s+(.+)/m', $block, $rm)) {
                    $fields["{$prefix}_fax"][] = trim($rm[1]);
                }

                $addrLines = [];
                if (preg_match_all('/^address:\s+(.+)/m', $block, $am)) {
                    $addrLines = array_map('trim', $am[1]);
                }
                // Also include descr lines from domain block as address for .priv.at
                if (empty($addrLines) && preg_match_all('/^descr:\s+(.+)/m', $text, $dm)) {
                    // Skip first descr (it's the name), rest is address
                    $descrLines = array_map('trim', $dm[1]);
                    if (count($descrLines) > 1) {
                        $addrLines = array_slice($descrLines, 1);
                    }
                }
                if ($addrLines) $fields["{$prefix}_address"][] = implode("\n", $addrLines);
            }
        }
    }

    private function parseTunisianFormat(string $text, array &$fields): void
    {
        if (!preg_match('/NIC Whois server.*\.tn/i', $text)) {
            return;
        }

        // Clear fields that may have been set by the standard dot-padded parser
        // Tunisian format needs special handling for firstName + name combination
        foreach (['registrant', 'admin', 'tech'] as $p) {
            unset($fields["{$p}_name"], $fields["{$p}_email"], $fields["{$p}_phone"],
                  $fields["{$p}_address"]);
        }

        // Parse contact sections with dot-padded keys
        foreach (['Owner Contact' => 'registrant', 'Administrativ contact' => 'admin', 'Technical contact' => 'tech'] as $label => $prefix) {
            $pattern = '/^' . preg_quote($label, '/') . '\s*\n((?:.+\n)*?)(?=\n(?:Owner|Admin|Technical|DNS|$))/mi';
            if (preg_match($pattern, $text, $m)) {
                $block = $m[1];
                $name = null;
                $firstName = null;
                $email = null;
                $phone = null;
                $addrLines = [];

                foreach (explode("\n", $block) as $line) {
                    if (preg_match('/^Name\.+:\s*(.+)/i', $line, $rm)) $name = trim($rm[1]);
                    if (preg_match('/^First name\.+:\s*(.+)/i', $line, $rm)) $firstName = trim($rm[1]);
                    if (preg_match('/^Email\.+:\s*(.+)/i', $line, $rm)) $email = trim($rm[1]);
                    if (preg_match('/^Phone\.+:\s*(.+)/i', $line, $rm)) $phone = trim($rm[1]);
                    if (preg_match('/^Address\.+:\s*(.+)/i', $line, $rm)) {
                        $val = trim($rm[1]);
                        if ($val !== '') $addrLines[] = $val;
                    }
                    // Continuation lines (not key-padded, just values)
                    if (preg_match('/^(\d{4,5})$/', trim($line), $rm)) {
                        $addrLines[] = $rm[1];
                    }
                    if (preg_match('/^([A-Z]{2,}(?:\s+[A-Z]+)*)$/', trim($line), $rm) && !preg_match('/^(Name|First|Email|Phone|Fax|Address|City|Zip|Country)/i', trim($line))) {
                        $val = $rm[1];
                        if (strlen($val) > 2) $addrLines[] = $val;
                    }
                }

                $fullName = trim(($firstName ? $firstName . ' ' : '') . ($name ?? ''));
                if ($fullName !== '') $fields["{$prefix}_name"][] = $fullName;
                if ($email && $email !== '') $fields["{$prefix}_email"][] = $email;
                if ($phone && $phone !== '') $fields["{$prefix}_phone"][] = $phone;
                if ($addrLines) $fields["{$prefix}_address"][] = implode(', ', $addrLines);
            }
        }

        // DNS servers section
        if (preg_match('/^DNS servers\s*\n((?:.+\n)*?)(?=\n|$)/mi', $text, $m)) {
            foreach (explode("\n", trim($m[1])) as $line) {
                if (preg_match('/^Name\.+:\s*(\S+)/i', trim($line), $nm)) {
                    $ns = strtolower(rtrim(trim($nm[1]), '.'));
                    if (preg_match('/^[a-z0-9.-]+$/i', $ns)) {
                        $fields['name_server'][] = $ns;
                    }
                }
            }
        }
    }

    private function parsePfFormat(string $text, array &$fields): void
    {
        if (!preg_match('/\.pf top level domain/i', $text) && !preg_match('/\.pf$/m', $text)) {
            return;
        }

        // Extract dates: "Created (JJ/MM/AAAA) : 27/02/2020"
        if (preg_match('/Created\s*\(JJ\/MM\/AAAA\)\s*:\s*(\d{2}\/\d{2}\/\d{4})/m', $text, $m)) {
            $fields['creation_date'][] = trim($m[1]);
        }
        if (preg_match('/Expire\s*\(JJ\/MM\/AAAA\)\s*:\s*(\d{2}\/\d{2}\/\d{4})/m', $text, $m)) {
            $fields['expiry_date'][] = trim($m[1]);
        }

        // Extract nameservers: "Name server 1 : ns1.vini.pf"
        if (preg_match_all('/Name server \d+\s*:\s*(\S+)/m', $text, $nsm)) {
            foreach ($nsm[1] as $ns) {
                $ns = strtolower(rtrim(trim($ns), '.'));
                if (preg_match('/^[a-z0-9.-]+$/i', $ns)) {
                    $fields['name_server'][] = $ns;
                }
            }
        }

        // Extract domain name
        if (preg_match('/Informations about \'([^\']+)\'/', $text, $m)) {
            $fields['domain_name'][] = strtolower(trim($m[1]));
        }

        // Clear fields that may have been set by the standard parser
        // (PF format has special address composition)
        unset($fields['registrant_address'], $fields['registrant_city'],
              $fields['registrant_postal_code'], $fields['registrant_country'],
              $fields['tech_address'], $fields['tech_city'],
              $fields['tech_postal_code'], $fields['tech_country'],
              $fields['status']);

        // "Registrant Compagnie Name" and "Tech 1 Compagnie Name"
        if (preg_match('/Registrant Compagnie Name\s*:\s*(.+)/m', $text, $m)) {
            $fields['registrant_organization'][] = trim($m[1]);
        }
        if (preg_match('/Registrant Name\s*:\s*(.+)/m', $text, $m)) {
            $val = trim($m[1]);
            if ($val !== '' && !isset($fields['registrant_name'])) {
                $fields['registrant_name'][] = $val;
            }
        }

        // Build registrant address from components
        $addrParts = [];
        if (preg_match('/Registrant Address\s*:\s*(.+)/m', $text, $m)) {
            $val = trim($m[1]);
            if ($val !== '') $addrParts[] = $val;
        }
        if (preg_match('/Registrant Postal Code\s*:\s*(.+)/m', $text, $m)) {
            $pc = trim($m[1]);
            $city = '';
            if (preg_match('/Registrant City\s*:\s*(.+)/m', $text, $m2)) $city = trim($m2[1]);
            if ($pc !== '' || $city !== '') {
                $addrParts[] = trim("$pc $city");
            }
        }
        if (preg_match('/Registrant Country\s*:\s*(.+)/m', $text, $m)) {
            $val = trim($m[1]);
            if ($val !== '') $addrParts[] = $val;
        }
        if ($addrParts) {
            $fields['registrant_address'][] = implode(', ', $addrParts);
        }

        // Tech contact
        if (preg_match('/Tech 1 Compagnie Name\s*:\s*(.+)/m', $text, $m)) {
            $fields['tech_organization'][] = trim($m[1]);
        }
        if (preg_match('/Tech 1 Name\s*:\s*(.+)/m', $text, $m)) {
            $fields['tech_name'][] = trim($m[1]);
        }
        $techAddrParts = [];
        if (preg_match('/Tech 1 Address\s*:\s*(.+)/m', $text, $m)) {
            $val = trim($m[1]);
            if ($val !== '') $techAddrParts[] = $val;
        }
        if (preg_match('/Tech 1 Postal Code\s*:\s*(.+)/m', $text, $m)) {
            $pc = trim($m[1]);
            $city = '';
            if (preg_match('/Tech 1 City\s*:\s*(.+)/m', $text, $m2)) $city = trim($m2[1]);
            if ($pc !== '' || $city !== '') {
                $techAddrParts[] = trim("$pc $city");
            }
        }
        if (preg_match('/Tech 1 Country\s*:\s*(.+)/m', $text, $m)) {
            $val = trim($m[1]);
            if ($val !== '') $techAddrParts[] = $val;
        }
        if ($techAddrParts) {
            $fields['tech_address'][] = implode(', ', $techAddrParts);
        }
    }

    private function parseAwFormat(string $text, array &$fields): void
    {
        if (!preg_match('/\.aw$/m', $text)) {
            return;
        }

        // Domain nameservers block
        if (preg_match('/^Domain nameservers:\s*\n((?:[ \t]+\S+.*\n)+)/m', $text, $m)) {
            foreach (explode("\n", trim($m[1])) as $ns) {
                $ns = strtolower(trim($ns));
                if ($ns !== '' && preg_match('/^[a-z0-9.-]+$/i', $ns)) {
                    $fields['name_server'][] = $ns;
                }
            }
        }

        // Registrar block
        if (preg_match('/^Registrar:\s*\n((?:[ \t]+.+\n)+)/m', $text, $m)) {
            $lines = array_map('trim', array_filter(explode("\n", trim($m[1])), fn($l) => trim($l) !== ''));
            if (!empty($lines)) {
                $fields['registrar'][] = $lines[0];
            }
        }
    }

    private function parseKzFormat(string $text, array &$fields): void
    {
        if (!preg_match('/KZ top level domain/i', $text)) {
            return;
        }

        // Organization section
        if (preg_match('/^Name\.+:\s*(.+)/m', $text, $m)) {
            $fields['registrant_name'][] = trim($m[1]);
        }
        if (preg_match('/^Organization Name\.+:\s*(.+)/m', $text, $m)) {
            $fields['registrant_organization'][] = trim($m[1]);
        }

        // Address from dot-padded fields
        $addrParts = [];
        if (preg_match('/^Street Address\.+:\s*(.+)/m', $text, $m)) $addrParts[] = trim($m[1]);
        if (preg_match('/^City\.+:\s*(.+)/m', $text, $m)) $addrParts[] = trim($m[1]);
        if (preg_match('/^State\.+:\s*(.+)/m', $text, $m)) $addrParts[] = trim($m[1]);
        if (preg_match('/^Postal Code\.+:\s*(.+)/m', $text, $m)) $addrParts[] = trim($m[1]);
        if (preg_match('/^Country\.+:\s*(.+)/m', $text, $m)) $addrParts[] = trim($m[1]);
        if ($addrParts) $fields['registrant_address'][] = implode("\n", $addrParts);

        // Admin contact
        if (preg_match('/Administrative Contact.*\n(?:NIC Handle\.+:\s*.+\n)?Name\.+:\s*(.+)/m', $text, $m)) {
            $fields['admin_name'][] = trim($m[1]);
        }
        if (preg_match('/Administrative Contact.*\n(?:.*\n)*?Phone Number\.+:\s*(.+)/m', $text, $m)) {
            $fields['admin_phone'][] = trim($m[1]);
        }
        if (preg_match('/Administrative Contact.*\n(?:.*\n)*?Fax Number\.+:\s*(.+)/m', $text, $m)) {
            $fields['admin_fax'][] = trim($m[1]);
        }
        if (preg_match('/Administrative Contact.*\n(?:.*\n)*?Email Address\.+:\s*(.+)/m', $text, $m)) {
            $fields['admin_email'][] = trim($m[1]);
        }

        // Nameservers with IPs
        if (preg_match_all('/(?:Primary|Secondary) server\.+:\s*(\S+)\s*\n(?:Primary|Secondary) ip address\.+:\s*(\S+)/m', $text, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $m) {
                $fields['name_server_detail'][] = json_encode([
                    'hostname' => strtolower(trim($m[1])),
                    'ipv4' => trim($m[2]),
                    'ipv6' => null,
                ]);
            }
        }

        // Domain dates
        if (preg_match('/Domain created:\s+(.+?)(?:\s+\(|$)/m', $text, $m)) {
            $fields['creation_date'][] = trim($m[1]);
        }
        if (preg_match('/Last modified\s*:\s+(.+?)(?:\s+\(|$)/m', $text, $m)) {
            $fields['updated_date'][] = trim($m[1]);
        }

        // Clear status that was incorrectly extracted from "State:" geographic field
        unset($fields['status']);

        // Status - may have multi-line with hyphens
        if (preg_match('/Domain status\s*:\s*(.+?)(?:\s+-\s*)?$/m', $text, $m)) {
            $statusLine = trim($m[1]);
            if ($statusLine !== '') {
                $fields['status'][] = $statusLine;
            }
        }
        // Additional status lines
        if (preg_match_all('/^\s{16,}(\S+)\s+-\s*$/m', $text, $sm)) {
            foreach ($sm[1] as $s) {
                $fields['status'][] = trim($s);
            }
        }

        // Registrar
        if (preg_match('/Current Registar:\s*(.+)/m', $text, $m)) {
            // Use this if no registrar yet
        }
    }

    private function parseIsraeliFormat(string $text, array &$fields): void
    {
        if (!preg_match('/ISOC-IL|\.il$/m', $text)) {
            return;
        }

        // "descr:" lines as registrant info
        $descrLines = [];
        if (preg_match_all('/^descr:\s+(.+)/m', $text, $m)) {
            $descrLines = array_map('trim', $m[1]);
        }
        if (!empty($descrLines)) {
            $fields['registrant_name'][] = $descrLines[0];
            if (count($descrLines) > 1) {
                $fields['registrant_address'][] = implode(', ', array_slice($descrLines, 1));
            }
        }

        // e-mail with "AT" -> "@" conversion
        if (preg_match('/^e-mail:\s+(.+)/m', $text, $m)) {
            $email = str_replace(' AT ', '@', trim($m[1]));
            $fields['registrant_email'][] = $email;
        }

        // phone
        if (preg_match('/^phone:\s+(.+)/m', $text, $m)) {
            $fields['registrant_phone'][] = trim($m[1]);
        }

        // "assigned:" as creation date, "validity:" as expiry
        if (preg_match('/^assigned:\s+(.+)/m', $text, $m)) {
            $fields['creation_date'][] = trim($m[1]);
        }
        if (preg_match('/^validity:\s+(.+)/m', $text, $m)) {
            $fields['expiry_date'][] = trim($m[1]);
        }

        // registrar at bottom
        if (preg_match('/^registrar name:\s+(.+)/m', $text, $m)) {
            $fields['registrar'][] = trim($m[1]);
        }
        if (preg_match('/^registrar info:\s+(.+)/m', $text, $m)) {
            $fields['registrar_url'][] = trim($m[1]);
        }

        // Admin/tech contacts from person blocks referenced by admin-c/tech-c
        $adminRef = null;
        $techRef = null;
        if (preg_match('/^admin-c:\s+(\S+)/m', $text, $m)) $adminRef = $m[1];
        if (preg_match('/^tech-c:\s+(\S+)/m', $text, $m)) $techRef = $m[1];

        // Parse person blocks
        if (preg_match_all('/^person:\s+(.+)\n((?:(?:address|phone|e-mail|nic-hdl|changed)\s*.+\n)*)/m', $text, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $pm) {
                $name = trim($pm[1]);
                $block = $pm[2];
                $nicHdl = '';
                if (preg_match('/nic-hdl:\s+(\S+)/m', $block, $rm)) $nicHdl = $rm[1];

                $prefix = null;
                if ($adminRef && $nicHdl === $adminRef) $prefix = 'admin';
                if ($techRef && $nicHdl === $techRef) $prefix = 'tech';
                if ($prefix === null) continue;

                $fields["{$prefix}_name"][] = $name;

                if (preg_match('/e-mail:\s+(.+)/m', $block, $rm)) {
                    $fields["{$prefix}_email"][] = str_replace(' AT ', '@', trim($rm[1]));
                }
                if (preg_match('/phone:\s+(.+)/m', $block, $rm)) {
                    $fields["{$prefix}_phone"][] = trim($rm[1]);
                }

                // address lines (without colon, just "address     xxx")
                $addrLines = [];
                if (preg_match_all('/address\s+(.+)/m', $block, $am)) {
                    foreach ($am[1] as $addr) {
                        $addr = trim($addr);
                        if ($addr !== '' && $addr !== '-') {
                            $addrLines[] = $addr;
                        }
                    }
                }
                if ($addrLines) $fields["{$prefix}_address"][] = implode(', ', $addrLines);
            }
        }
    }

    private function parseJpContactSection(string $text, array &$fields): void
    {
        // JP WHOIS: "Contact Information:\n[Name]  value\n[Email]  value"
        if (preg_match('/Contact Information:\s*\n((?:\[.+\].*\n)+)/m', $text, $m)) {
            $block = $m[1];
            foreach (explode("\n", $block) as $line) {
                if (preg_match('/^\[([^\]]+)\]\s+(.+)$/u', trim($line), $bm)) {
                    $key = strtolower(trim($bm[1]));
                    $val = trim($bm[2]);
                    if ($key === 'name' && $val !== '') {
                        // This is the registrant contact, but name might be privacy service
                        // Check if it looks like a privacy service
                    }
                    if ($key === 'email' && $val !== '') {
                        $fields['registrant_email'][] = $val;
                    }
                    // Don't extract phone from JP Contact Info - it's the privacy service phone
                }
            }
        }
    }

    private function parseEstonianFormat(string $text, array &$fields): void
    {
        if (!preg_match('/Estonia.*\.ee/i', $text)) {
            return;
        }

        // Clear fields that were erroneously extracted by standard parser
        // (since Estonian format uses section-scoped key:value)
        unset($fields['status'], $fields['registrar'], $fields['registrar_url']);

        // Parse section-based format: "Section:\nkey: value"
        $sections = preg_split('/^(\w[\w ]*?):\s*$/m', $text, -1, PREG_SPLIT_DELIM_CAPTURE);

        for ($i = 1; $i < count($sections) - 1; $i += 2) {
            $sectionName = strtolower(trim($sections[$i]));
            $sectionBody = $sections[$i + 1];

            $sectionFields = [];
            foreach (explode("\n", $sectionBody) as $line) {
                if (preg_match('/^(\w[\w ]*?):\s+(.+)$/u', trim($line), $m)) {
                    $sectionFields[strtolower(trim($m[1]))][] = trim($m[2]);
                }
            }

            if ($sectionName === 'domain') {
                if (isset($sectionFields['name'])) $fields['domain_name'][] = strtolower($sectionFields['name'][0]);
                if (isset($sectionFields['status'])) {
                    $status = preg_replace('/\s*\(.*\)/', '', $sectionFields['status'][0]);
                    $fields['status'][] = trim($status);
                }
                if (isset($sectionFields['registered'])) $fields['creation_date'][] = $sectionFields['registered'][0];
                if (isset($sectionFields['changed'])) $fields['updated_date'][] = $sectionFields['changed'][0];
                if (isset($sectionFields['expire'])) $fields['expiry_date'][] = $sectionFields['expire'][0];
            } elseif ($sectionName === 'registrant') {
                if (isset($sectionFields['name'])) {
                    $val = $this->filterRedacted($sectionFields['name'][0]);
                    if ($val) $fields['registrant_name'][] = $val;
                }
                if (isset($sectionFields['country'])) {
                    $val = $this->filterRedacted($sectionFields['country'][0]);
                    if ($val) $fields['registrant_country'][] = $val;
                }
            } elseif ($sectionName === 'registrar') {
                if (isset($sectionFields['name'])) $fields['registrar'][] = $sectionFields['name'][0];
                if (isset($sectionFields['url'])) $fields['registrar_url'][] = $sectionFields['url'][0];
            } elseif ($sectionName === 'name servers') {
                foreach ($sectionFields['nserver'] ?? [] as $ns) {
                    $fields['name_server'][] = strtolower(trim($ns));
                }
            }
        }
    }

    private function parseDkFormat(string $text, array &$fields): void
    {
        if (!preg_match('/Punktum dk/i', $text) && !preg_match('/^Nameservers\nHostname:/m', $text)) {
            return;
        }

        // Remove "DNS:" field that was incorrectly parsed as nameserver (it's the domain zone name)
        if (isset($fields['name_server'])) {
            $domainName = strtolower($this->firstValue($fields, 'domain_name') ?? '');
            $fields['name_server'] = array_values(array_filter(
                $fields['name_server'],
                fn($ns) => strtolower($ns) !== $domainName
            ));
            if (empty($fields['name_server'])) unset($fields['name_server']);
        }

        // Nameservers section with "Hostname:" entries
        if (preg_match('/^Nameservers\s*\n((?:Hostname:\s+\S+\n)+)/m', $text, $m)) {
            foreach (explode("\n", trim($m[1])) as $line) {
                if (preg_match('/Hostname:\s+(\S+)/i', $line, $nm)) {
                    $fields['name_server'][] = strtolower(trim($nm[1]));
                }
            }
        }
    }

    private function parseImFormat(string $text, array &$fields): void
    {
        if (!preg_match('/\.im$/m', $text)) {
            return;
        }

        // "Name Server:hostname." format (no space)
        if (preg_match_all('/Name Server:\s*(\S+)/m', $text, $matches)) {
            foreach ($matches[1] as $ns) {
                $ns = strtolower(rtrim(trim($ns), '.'));
                if (preg_match('/^[a-z0-9.-]+$/i', $ns)) {
                    $fields['name_server'][] = $ns;
                }
            }
        }

        // "Expiry Date: 12/02/2027 00:59:52"
        if (preg_match('/Expiry Date:\s*(.+)/m', $text, $m)) {
            $fields['expiry_date'][] = trim($m[1]);
        }
    }

    private function parseMoFormat(string $text, array &$fields): void
    {
        if (!preg_match('/Record created on|Record expires on/m', $text)) {
            return;
        }

        // "Record created on DATE"
        if (preg_match('/Record created on\s+(.+)/m', $text, $m)) {
            $fields['creation_date'][] = trim($m[1]);
        }
        if (preg_match('/Record expires on\s+(.+)/m', $text, $m)) {
            $fields['expiry_date'][] = trim($m[1]);
        }

        // Nameservers after dashes line
        if (preg_match('/Domain name servers:\s*\n\s*-+\s*\n((?:\S+.*\n?)+)/m', $text, $m)) {
            foreach (explode("\n", trim($m[1])) as $ns) {
                $ns = strtolower(trim($ns));
                if ($ns !== '' && preg_match('/^[a-z0-9.-]+$/i', $ns)) {
                    $fields['name_server'][] = $ns;
                }
            }
        }
    }

    private function parseNcFormat(string $text, array &$fields): void
    {
        if (!preg_match('/OPT Whois/i', $text)) {
            return;
        }

        // "Domain server 1" etc
        if (preg_match_all('/Domain server \d+\s*:\s*(\S+)/m', $text, $matches)) {
            foreach ($matches[1] as $ns) {
                $fields['name_server'][] = strtolower(trim($ns));
            }
        }
    }

    private function parseTgFormat(string $text, array &$fields): void
    {
        // JWhoisServer .tg format: "Key:...........Value" with contact blocks separated by "---"
        // Must have dot-padded fields to distinguish from bracket-section JWhoisServer (.gf/.gp/.mq)
        if (!preg_match('/JWhoisServer|ccTLD tg/i', $text) || !preg_match('/^[A-Za-z].*?:\.{2,}/m', $text)) {
            return;
        }

        // Clear fields that standard parser may have polluted with dot-prefixed values
        unset($fields['domain_name'], $fields['registrar'], $fields['status'],
              $fields['creation_date'], $fields['expiry_date'], $fields['name_server']);

        // Parse dot-colon format: "Key:...value" or "Key:..........value"
        $parseField = function(string $line): ?array {
            if (preg_match('/^([A-Za-z][A-Za-z0-9 ()-]*?):\.{2,}(.*)$/', trim($line), $m)) {
                return [trim($m[1]), trim($m[2])];
            }
            return null;
        };

        // Split into blocks by "---"
        $blocks = preg_split('/^-{3,}\s*$/m', $text);
        $seenContactTypes = [];

        foreach ($blocks as $block) {
            $blockFields = [];
            foreach (explode("\n", $block) as $line) {
                $parsed = $parseField($line);
                if ($parsed !== null) {
                    [$key, $value] = $parsed;
                    $blockFields[strtolower($key)][] = $value;
                }
            }

            if (empty($blockFields)) continue;

            // Extract domain info from first block only
            if (!isset($fields['domain_name']) && isset($blockFields['domain'])) {
                $fields['domain_name'][] = strtolower($blockFields['domain'][0]);
            }
            if (!isset($fields['registrar']) && isset($blockFields['registrar'])) {
                $fields['registrar'][] = $blockFields['registrar'][0];
            }
            if (!isset($fields['creation_date']) && isset($blockFields['activation'])) {
                $fields['creation_date'][] = $blockFields['activation'][0];
            }
            if (!isset($fields['expiry_date']) && isset($blockFields['expiration'])) {
                $fields['expiry_date'][] = $blockFields['expiration'][0];
            }

            // Nameservers
            foreach ($blockFields['name server (db)'] ?? [] as $ns) {
                $ns = strtolower(trim($ns));
                if ($ns !== '' && !in_array($ns, $fields['name_server'] ?? [], true)) {
                    $fields['name_server'][] = $ns;
                }
            }

            // Contact
            $contactType = strtolower($blockFields['contact type'][0] ?? '');
            if ($contactType === '') continue;

            $prefix = match($contactType) {
                'owner' => 'registrant',
                'administrative' => 'admin',
                'technical' => 'tech',
                default => null,
            };

            if ($prefix === null || isset($seenContactTypes[$prefix])) continue;
            $seenContactTypes[$prefix] = true;

            $lastName = $blockFields['last name'][0] ?? '';
            $firstName = $blockFields['first name'][0] ?? '';
            $name = trim(($firstName ? $firstName . ' ' : '') . $lastName);
            if ($name === '') $name = $lastName;

            $email = $blockFields['e-mail'][0] ?? '';
            $phone = $blockFields['tel'][0] ?? '';
            $address = $blockFields['address'][0] ?? '';

            if ($name !== '') $fields["{$prefix}_name"][] = $name;
            if ($email !== '') $fields["{$prefix}_email"][] = $email;
            if ($phone !== '') $fields["{$prefix}_phone"][] = $phone;
            if ($address !== '') $fields["{$prefix}_address"][] = $address;
        }
    }

    private function parseJWhoisBracketFormat(string $text, array &$fields): void
    {
        // JWhoisServer bracket-section format: [holder], [admin_c], [tech_c], [zone_c]
        // Used by .gf, .gp, .mq (ccTLD tld;mq;gf;gp)
        if (!preg_match('/JWhoisServer/i', $text) || !preg_match('/^\[holder\]/m', $text)) {
            return;
        }

        // Split into sections by [bracket_header]
        $sections = preg_split('/^\[(\w+)\]\s*$/m', $text, -1, PREG_SPLIT_DELIM_CAPTURE);

        // First section is the domain header (before any bracket)
        // Already parsed by extractFields(), but ensure domain name is set
        $headerBlock = $sections[0] ?? '';
        foreach (explode("\n", $headerBlock) as $line) {
            if (preg_match('/^domain:\s+(.+)/i', trim($line), $m)) {
                $fields['domain_name'] = [strtolower(trim($m[1]))];
            }
            if (preg_match('/^nameserver:\s+(.+)/i', trim($line), $m)) {
                $ns = strtolower(trim($m[1]));
                if (!in_array($ns, $fields['name_server'] ?? [], true)) {
                    $fields['name_server'][] = $ns;
                }
            }
        }

        // Process bracket sections in pairs: [1]=section_name, [2]=section_body, ...
        for ($i = 1; $i + 1 < count($sections); $i += 2) {
            $sectionName = strtolower($sections[$i]);
            $sectionBody = $sections[$i + 1];

            $prefix = match ($sectionName) {
                'holder' => 'registrant',
                'admin_c' => 'admin',
                'tech_c' => 'tech',
                default => null,
            };
            if ($prefix === null) {
                continue;
            }

            // Parse key: value lines within section
            $sectionFields = [];
            $addressLines = [];
            $inAddress = false;
            foreach (explode("\n", $sectionBody) as $line) {
                $trimmed = trim($line);
                if ($trimmed === '') {
                    $inAddress = false;
                    continue;
                }
                if (preg_match('/^([a-z][a-z0-9_]*?):\s*(.*)/i', $trimmed, $m)) {
                    $key = strtolower($m[1]);
                    $val = trim($m[2]);
                    $sectionFields[$key] = $val;
                    $inAddress = ($key === 'address');
                    if ($inAddress && $val !== '') {
                        $addressLines = [$val];
                    }
                } elseif ($inAddress) {
                    // Continuation line for address
                    $addressLines[] = $trimmed;
                }
            }

            $name = $sectionFields['name'] ?? '';
            $email = $sectionFields['email'] ?? '';
            $phone = $sectionFields['phone'] ?? '';
            $fax = $sectionFields['fax'] ?? '';
            $pcode = trim($sectionFields['pcode'] ?? '');
            $country = $sectionFields['country'] ?? '';

            // Build address from address lines + pcode + country
            $addrParts = $addressLines;
            if ($pcode !== '') {
                $addrParts[] = $pcode;
            }
            if ($country !== '') {
                $addrParts[] = $country;
            }
            $address = implode(', ', $addrParts);

            if ($name !== '') $fields["{$prefix}_name"][] = $name;
            if ($email !== '') $fields["{$prefix}_email"][] = $email;
            if ($phone !== '') $fields["{$prefix}_phone"][] = $phone;
            if ($fax !== '') $fields["{$prefix}_fax"][] = $fax;
            if ($address !== '') $fields["{$prefix}_address"][] = $address;
        }
    }

    private function parseSkFormat(string $text, array &$fields): void
    {
        // SK-NIC format: section-based with "Domain registrant:", "Registrar:", "Administrative Contact:", "Technical Contact:"
        if (!preg_match('/^Domain registrant:/m', $text) && !preg_match('/^Authorised Registrar:/m', $text)) {
            return;
        }

        // Clear fields that standard parser may have mixed up
        unset($fields['registrant_name'], $fields['registrant_organization'], $fields['registrant_email'],
              $fields['registrant_phone'], $fields['registrant_address'], $fields['registrant_city'],
              $fields['registrant_postal_code'], $fields['registrant_country'],
              $fields['admin_name'], $fields['admin_organization'], $fields['admin_email'],
              $fields['admin_phone'], $fields['admin_address'],
              $fields['tech_name'], $fields['tech_organization'], $fields['tech_email'],
              $fields['tech_phone'], $fields['tech_address'],
              $fields['registrar']);

        // Split into blocks by blank lines
        $blocks = preg_split('/\n\n+/', $text);

        foreach ($blocks as $block) {
            $blockFields = [];
            foreach (explode("\n", $block) as $line) {
                if (preg_match('/^([A-Za-z][A-Za-z0-9 ]*?):\s+(.+)$/u', trim($line), $m)) {
                    $blockFields[strtolower(trim($m[1]))][] = trim($m[2]);
                }
            }

            if (empty($blockFields)) continue;

            // Detect block type
            $prefix = null;
            if (isset($blockFields['domain registrant'])) {
                $prefix = 'registrant';
            } elseif (isset($blockFields['administrative contact'])) {
                $prefix = 'admin';
            } elseif (isset($blockFields['technical contact'])) {
                $prefix = 'tech';
            } elseif (isset($blockFields['registrar'])) {
                // Registrar block
                if (isset($blockFields['name'])) {
                    $fields['registrar'] = [$blockFields['name'][0]];
                }
                continue;
            }

            if ($prefix === null) continue;

            if (isset($blockFields['name'])) $fields["{$prefix}_name"][] = $blockFields['name'][0];
            if (isset($blockFields['organization'])) $fields["{$prefix}_organization"][] = $blockFields['organization'][0];
            if (isset($blockFields['email'])) $fields["{$prefix}_email"][] = $blockFields['email'][0];
            if (isset($blockFields['phone'])) $fields["{$prefix}_phone"][] = $blockFields['phone'][0];

            // Build address
            $addrParts = [];
            if (isset($blockFields['street'])) $addrParts[] = $blockFields['street'][0];
            if (isset($blockFields['city'])) $addrParts[] = $blockFields['city'][0];
            if (isset($blockFields['postal code'])) $addrParts[] = $blockFields['postal code'][0];
            if (isset($blockFields['country code'])) $addrParts[] = $blockFields['country code'][0];
            if ($addrParts) $fields["{$prefix}_address"][] = implode(', ', $addrParts);
        }
    }

    private function parseTaiwaneseFormat(string $text, array &$fields): void
    {
        // Taiwanese .tw format: "Record expires on 2035-07-14 16:00:00 (UTC+8)"
        if (!preg_match('/Record (?:created|expires) on/m', $text)) {
            return;
        }

        if (preg_match('/Record created on\s+(.+?)(?:\s*\(UTC[+\-]?\d+\))?\s*$/m', $text, $m)) {
            $fields['creation_date'][] = trim($m[1]);
        }
        if (preg_match('/Record expires on\s+(.+?)(?:\s*\(UTC[+\-]?\d+\))?\s*$/m', $text, $m)) {
            $fields['expiry_date'][] = trim($m[1]);
        }

        // Registrant block: "   Registrant:\n      org\n      name\n      email\n      country"
        if (preg_match('/^\s+Registrant:\s*\n((?:\s+.+\n)+)/m', $text, $m)) {
            $lines = [];
            foreach (explode("\n", trim($m[1])) as $line) {
                $val = trim($line);
                if ($val !== '' && !preg_match('/^\(Redacted/i', $val)) {
                    $lines[] = $val;
                }
            }
            // Typical order: org (Chinese), name (English), email, country
            foreach ($lines as $line) {
                if (preg_match('/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/', $line)) {
                    $fields['registrant_email'][] = $line;
                } elseif (preg_match('/^[A-Z]{2}$/', $line)) {
                    $fields['registrant_country'][] = $line;
                } elseif (preg_match('/^[A-Za-z\s,.]+$/', $line)) {
                    $fields['registrant_name'][] = $line;
                } else {
                    // Chinese org name
                    if (!isset($fields['registrant_organization']) || empty($fields['registrant_organization'])) {
                        $fields['registrant_organization'][] = $line;
                    }
                }
            }
        }

        // Registration Service Provider as registrar
        if (preg_match('/^Registration Service Provider:\s*(.+)$/m', $text, $m)) {
            $fields['registrar'][] = trim($m[1]);
        }
        if (preg_match('/^Registration Service URL:\s*(.+)$/m', $text, $m)) {
            $fields['registrar_url'][] = trim($m[1]);
        }
    }

    private function parseTurkishFormat(string $text, array &$fields): void
    {
        // Turkish .tr format uses "** " prefixed section headers
        if (!preg_match('/^\*\* Domain Name:/m', $text)) {
            return;
        }

        // Domain name
        if (preg_match('/^\*\* Domain Name:\s*(.+)/m', $text, $m)) {
            $fields['domain_name'][] = strtolower(trim($m[1]));
        }

        // Registrant section: "** Registrant:\n   Name\n   addr..."
        if (preg_match('/^\*\* Registrant:\s*\n\s+(.+)/m', $text, $m)) {
            $name = trim($m[1]);
            if ($name !== '' && !preg_match('/^Hidden/i', $name)) {
                $fields['registrant_name'][] = $name;
            }
        }

        // Registrar section: "** Registrar:\nNIC Handle\t: ...\nOrganization Name\t: ..."
        if (preg_match('/^\*\* Registrar:\s*\n((?:.*\n)*?)(?:\n\*\*|\n\n)/m', $text, $m)) {
            $block = $m[1];
            if (preg_match('/Organization Name\s*:\s*(.+)/i', $block, $rm)) {
                $fields['registrar'][] = trim($rm[1]);
            }
            if (preg_match('/Phone\s*:\s*(.+)/i', $block, $rm)) {
                $phone = trim($rm[1]);
                if ($phone !== '' && $phone !== '-') {
                    $fields['registrar_abuse_phone'][] = $phone;
                }
            }
        }

        // Frozen/Transfer status lines
        if (preg_match('/^Frozen Status:\s*(.+)/m', $text, $m)) {
            $fields['status'][] = 'Frozen: ' . trim($m[1]);
        }
        if (preg_match('/^Transfer Status:\s*(.+)/m', $text, $m)) {
            $fields['status'][] = 'Transfer: ' . trim($m[1]);
        }

        // Domain Servers section
        if (preg_match('/^\*\* Domain Servers:\s*\n((?:.*\n)*?)(?:\n\*\*|\n\n)/m', $text, $m)) {
            foreach (explode("\n", trim($m[1])) as $ns) {
                $ns = strtolower(trim($ns));
                if ($ns !== '' && preg_match('/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$/i', $ns)) {
                    $fields['name_server'][] = $ns;
                }
            }
        }

        // Additional Info section with dot-padded dates
        if (preg_match('/Created on\.+:\s*(.+)\./m', $text, $m)) {
            $dateStr = trim($m[1]);
            $parsed = $this->parseDate($dateStr);
            if ($parsed !== null) {
                $fields['creation_date'][] = $parsed;
            }
        }
        if (preg_match('/Expires on\.+:\s*(.+)\./m', $text, $m)) {
            $dateStr = trim($m[1]);
            $parsed = $this->parseDate($dateStr);
            if ($parsed !== null) {
                $fields['expiry_date'][] = $parsed;
            }
        }
    }

    private function parseSerbianFormat(string $text, array &$fields): void
    {
        // Only apply for RNIDS .rs format (has "Domain name:" and "Registrant:" on same level)
        if (!preg_match('/^Domain name:\s+\S+\.rs$/m', $text)) {
            return;
        }

        // RNIDS .rs format: "Administrative contact: Name\nAddress: ...\nPostal Code: ..."
        foreach (['Administrative contact' => 'admin', 'Technical contact' => 'tech'] as $label => $prefix) {
            if (preg_match('/^' . preg_quote($label, '/') . ':\s*(.+)$/m', $text, $m)) {
                $name = trim($m[1]);
                if ($name !== '' && !isset($fields["{$prefix}_name"])) {
                    $fields["{$prefix}_name"][] = $name;
                }

                // Look for following Address/Postal Code lines
                $pos = strpos($text, $m[0]);
                $afterBlock = substr($text, $pos + strlen($m[0]));
                $addrParts = [];
                if (preg_match('/^Address:\s*(.+)$/m', $afterBlock, $am)) {
                    $addrParts[] = trim($am[1]);
                }
                if (preg_match('/^Postal Code:\s*(.+)$/m', $afterBlock, $pm)) {
                    $pc = trim($pm[1]);
                    if ($pc !== '') {
                        $addrParts[] = $pc;
                    }
                }
                if ($addrParts && !isset($fields["{$prefix}_address"])) {
                    $fields["{$prefix}_address"][] = implode(', ', $addrParts);
                }
            }
        }

        // Normalize "DNSSEC signed: no/yes" to "unsigned"/"signedDelegation" (Serbian RNIDS format)
        if (preg_match('/^DNSSEC signed:/m', $text) && isset($fields['dnssec'])) {
            foreach ($fields['dnssec'] as &$dv) {
                $dvLower = strtolower(trim($dv));
                if ($dvLower === 'no') {
                    $dv = 'unsigned';
                } elseif ($dvLower === 'yes') {
                    $dv = 'signedDelegation';
                }
            }
            unset($dv);
        }

        // Filter out "Individual" as registrant name (not useful info)
        if (isset($fields['registrant_name'])) {
            $fields['registrant_name'] = array_values(array_filter($fields['registrant_name'], function($v) {
                return strtolower(trim($v)) !== 'individual';
            }));
            if (empty($fields['registrant_name'])) {
                unset($fields['registrant_name']);
            }
        }
    }

    private function parseNameserverBlocks(string $text, array &$fields): void
    {
        // Generic: "Nameservers\n  hostname" (when not already parsed)
        if (isset($fields['name_server']) && !empty($fields['name_server'])) {
            return;
        }
        if (isset($fields['name_server_detail']) && !empty($fields['name_server_detail'])) {
            return;
        }

        if (preg_match('/^(?:Nameservers?|NAME SERVER INFORMATION:?|Domain servers in listed order:?)\s*\n((?:[ \t]*\S+.*\n)+)/m', $text, $m)) {
            foreach (explode("\n", trim($m[1])) as $ns) {
                $ns = strtolower(trim($ns));
                if ($ns !== '' && preg_match('/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$/i', $ns)) {
                    $fields['name_server'][] = $ns;
                }
            }
        }
    }

    private function normalizeKey(string $key): string
    {
        $key = strtolower(trim($key));
        // Strip trailing dots
        $key = rtrim($key, '.');
        // Transliterate common accented chars before stripping non-ASCII
        $key = strtr($key, [
            'é' => 'e', 'è' => 'e', 'ê' => 'e', 'ë' => 'e',
            'à' => 'a', 'â' => 'a', 'ä' => 'a',
            'ô' => 'o', 'ö' => 'o',
            'ù' => 'u', 'û' => 'u', 'ü' => 'u',
            'î' => 'i', 'ï' => 'i',
            'ç' => 'c', 'ñ' => 'n',
        ]);
        $key = preg_replace('/[\s\'-]+/', '_', $key);
        $key = preg_replace('/[^a-z0-9_]/', '', $key);

        return match ($key) {
            'domain', 'domain_name', 'domainname', 'domaintype',
            'domain_name_punycode', 'nom_de_domaine' => 'domain_name',
            'registrar', 'sponsoring_registrar', 'registrar_name', 'registrar_id',
            'registrarname', 'registration_service_provider' => 'registrar',
            'registrar_whois_server', 'whois_server', 'refer' => 'whois_server',
            'registrar_url', 'registrar_homepage', 'www', 'web', 'url', 'registrar_website',
            'registrarurl', 'referral_url', 'sponsoring_registrar_url' => 'registrar_url',
            'registrar_abuse_contact_email', 'abuse_contact_email' => 'registrar_abuse_email',
            'abuse_email', 'registrar_customer_service_email',
            'sponsoring_registrar_customer_service_email' => 'abuse_email',
            'registrar_email' => 'registrar_contact_email',
            'registrar_abuse_contact_phone', 'abuse_contact_phone' => 'registrar_abuse_phone',
            'abuse_phone' => 'abuse_phone',
            'registrar_iana_id', 'sponsoring_registrar_iana_id' => 'registrar_iana_id',
            'creation_date', 'created', 'created_date', 'created_on', 'createdon',
            'registration_date', 'registered_on', 'domain_registered',
            'reg_created_date', 'registration_time', 'registered',
            'domain_record_activated', 'record_created',
            'date_de_creation', 'regdate' => 'creation_date',
            'updated_date', 'last_modified', 'lastmodified', 'changed',
            'last_updated', 'modification_date', 'modified', 'domain_last_updated',
            'last_updated_on', 'domain_record_last_updated',
            'information_last_updated', 'updated', 'update_date',
            'last_update', 'derniere_modification' => 'updated_date',
            'registry_expiry_date', 'expiry_date', 'expiration_date', 'expires',
            'expire_date', 'paid_till', 'renewal_date', 'domain_expiration_date',
            'registrar_registration_expiration_date', 'expire', 'expires_on', 'expiry',
            'domain_expires', 'paidtill', 'free_date', 'expiration_time',
            'valid_until', 'date_d_expiration' => 'expiry_date',
            'domain_status', 'status', 'domain_state', 'registration_status',
            'registry_status', 'statut' => 'status',
            'name_server', 'nameserver', 'nserver', 'nameservers', 'name_servers',
            'dns', 'hostname', 'dns_servers', 'domain_nameservers',
            'ns_1', 'ns_2', 'ns_3', 'ns_4', 'ns_5', 'ns_6',
            'serveur_de_noms' => 'name_server',
            'dnssec', 'dnssec_ds_records', 'dnssec_signed' => 'dnssec',
            'registrant_name', 'registrant_contact', 'registrant',
            'registrant_contact_name', 'holder', 'holder_name',
            'owner_name' => 'registrant_name',
            'registrant_organization', 'registrant_organisation',
            'registrant_contact_organisation', 'registrant_contact_organization',
            'domain_owner', 'contact_organization',
            'registrant_compagnie_name' => 'registrant_organization',
            'registrant_email', 'holder_email', 'registrant_contact_email',
            'owner_email' => 'registrant_email',
            'registrant_phone', 'registrant_phone_number' => 'registrant_phone',
            'registrant_country', 'registrant_countrycode',
            'owner_country_code' => 'registrant_country',
            'registrant_address', 'registrant_street', 'registrant_street1',
            'owner_addr', 'owner_address' => 'registrant_address',
            'registrant_city', 'owner_locality' => 'registrant_city',
            'registrant_state_province', 'registrant_stateprovince', 'registrant_stateprovinc' => 'registrant_state',
            'registrant_postal_code', 'registrant_zip', 'owner_zipcode' => 'registrant_postal_code',
            'admin_name', 'admin_contact_name' => 'admin_name',
            'admin_email', 'admin_contact_email' => 'admin_email',
            'admin_phone', 'admin_contact_phone' => 'admin_phone',
            'admin_organization', 'admin_organisation' => 'admin_organization',
            'admin_country', 'admin_country_code' => 'admin_country',
            'admin_city', 'admin_locality' => 'admin_city',
            'admin_street', 'admin_address', 'admin_street1' => 'admin_address',
            'admin_state_province', 'admin_stateprovince' => 'admin_state',
            'admin_postal_code', 'admin_zipcode' => 'admin_postal_code',
            'tech_name', 'tech_contact_name', 'technical_contact_name' => 'tech_name',
            'tech_email', 'tech_contact_email', 'technical_contact_email' => 'tech_email',
            'tech_phone', 'tech_contact_phone' => 'tech_phone',
            'tech_organization', 'tech_organisation', 'tech_contact_organisation',
            'tech_contact_organization' => 'tech_organization',
            'tech_country', 'tech_country_code' => 'tech_country',
            'tech_city', 'tech_locality' => 'tech_city',
            'tech_street', 'tech_address', 'tech_street1' => 'tech_address',
            'tech_state_province', 'tech_stateprovince' => 'tech_state',
            'tech_postal_code', 'tech_zipcode' => 'tech_postal_code',
            'billing_name' => 'billing_name',
            'billing_email' => 'billing_email',
            'billing_organization' => 'billing_organization',
            'registrar_name2' => 'registrar', // .eu "Name:" inside Registrar block
            // IP-specific
            'inetnum', 'netrange', 'inet6num' => 'ip_range',
            'netname', 'network_name' => 'net_name',
            'descr', 'description', 'org_name', 'organization' => 'description',
            'orgname' => 'orgname',
            'country' => 'country',
            'origin', 'originas', 'origin_as' => 'origin_as',
            // ASN-specific
            'aut_num', 'ashandle', 'as_handle', 'asnumber' => 'asn',
            'as_name', 'asname' => 'as_name',
            // Don't map bare 'state' - it's ambiguous (geographic vs domain state)
            'state' => 'state',
            'person' => 'person',
            'org' => 'org',
            'registrant_name2' => 'registrant_name',
            default => $key,
        };
    }

    private function parseDomain(array $fields, string $text, string $serverHostname): DomainInfo
    {
        $domainName = $this->firstValue($fields, 'domain_name');
        if ($domainName !== null) {
            $domainName = strtolower(trim($domainName));
            // Extract punycode from IDN+punycode format: "казино-игри.бг (xn----7sbkofbbj4akz.xn--90ae)"
            // Also handle "pokerstars.bg (pokerstars.bg)" where parenthesized is ASCII domain
            if (preg_match('/\(([a-z0-9.-]+\.[a-z0-9-]{2,})\)\s*$/i', $domainName, $m)) {
                $domainName = strtolower($m[1]);
            }
        }

        // Try to extract domain from "object: xxx" for .gf format
        if ($domainName === null) {
            if (preg_match('/^object:\s+(\S+)/m', $text, $m)) {
                $domainName = strtolower(trim($m[1]));
            }
        }

        // Extract registrar info
        $registrarName = $this->firstValue($fields, 'registrar');
        // Filter placeholder registrar names
        if ($registrarName !== null && in_array(strtolower($registrarName), ['none', 'n/a', '-'], true)) {
            $registrarName = null;
        }
        // Filter registrar names containing non-Latin characters (encoding issues, Arabic text, etc.)
        if ($registrarName !== null && preg_match('/\?{2,}/', $registrarName)) {
            $registrarName = null;
        }
        // Filter specific registry handles used as registrar names
        if ($registrarName !== null && $registrarName === 'MARNET-REG') {
            $registrarName = null;
        }
        // Filter registrar for .biz.ua/.co.ua subdomains (these are UA registry entries, not real registrar names)
        if ($registrarName !== null && preg_match('/\(-?\w+-mnt-cunic\)$/i', $registrarName)
            && in_array($serverHostname, ['whois.biz.ua', 'whois.co.ua'], true)) {
            $registrarName = null;
        }
        $registrarIanaId = $this->firstValue($fields, 'registrar_iana_id');
        $registrarUrl = $this->firstValue($fields, 'registrar_url');
        // Filter out WHOIS server URLs and placeholder values that aren't real registrar websites
        if ($registrarUrl !== null && (
            preg_match('/^https?:\/\/whois\./i', $registrarUrl)
            || preg_match('/^RegistrarURL$/i', $registrarUrl)
            || !preg_match('/[.]/', $registrarUrl)
        )) {
            $registrarUrl = null;
        }
        // Filter "Registrar URL" that is actually a registry URL (not a registrar website)
        if ($registrarUrl !== null && (
            preg_match('/^https?:\/\/nic\./i', $registrarUrl)
            || preg_match('/^www\.nic\./i', $registrarUrl)
        )) {
            $registrarUrl = null;
        }
        // Prefer ICANN-standard "Registrar Abuse Contact Email/Phone" fields,
        // fall back to "Registry Abuse Contact Email" from boilerplate comments,
        // then to "Registrar Email" (but not generic "Abuse Email")
        $abuseEmail = $this->firstValue($fields, 'registrar_abuse_email')
            ?? $this->firstValue($fields, 'registry_abuse_email')
            ?? $this->firstValue($fields, 'registrar_contact_email');
        $abusePhone = $this->firstValue($fields, 'registrar_abuse_phone');


        // Filter out "not applicable" IANA IDs
        if ($registrarIanaId !== null && strtolower($registrarIanaId) === 'not applicable') {
            $registrarIanaId = null;
        }

        $registrar = null;
        if ($registrarName !== null || $registrarUrl !== null || $abuseEmail !== null || $abusePhone !== null || $registrarIanaId !== null) {
            $registrar = new Registrar(
                name: $registrarName,
                ianaId: $registrarIanaId,
                url: $registrarUrl,
                abuseEmail: $abuseEmail,
                abusePhone: $abusePhone,
            );
        }

        // Extract dates - prefer the most detailed value (with time) when duplicates exist
        $createdDate = $this->parseDate($this->bestDateValue($fields, 'creation_date'));
        $updatedDate = $this->parseDate($this->bestDateValue($fields, 'updated_date'));
        $expiresDate = $this->parseDate($this->bestDateValue($fields, 'expiry_date'));

        // Extract status codes
        // If "state:" and "status:" both present, "state" values (like "active") are domain state, not EPP status
        $statusValues = $fields['status'] ?? [];
        if (count($statusValues) > 1) {
            // Remove generic state values when EPP statuses are also present
            $hasEppStatus = false;
            foreach ($statusValues as $sv) {
                $svLower = strtolower(trim(preg_replace('/\s*\(?https?:\/\/.*$/', '', $sv)));
                if (in_array($svLower, ['ok', 'clienttransferprohibited', 'servertransferprohibited',
                    'clientdeleteprohibited', 'serverdeleteprohibited', 'clientupdateprohibited',
                    'serverupdateprohibited', 'clienthold', 'serverhold'], true)) {
                    $hasEppStatus = true;
                    break;
                }
            }
            if ($hasEppStatus) {
                $statusValues = array_filter($statusValues, function($sv) {
                    $svLower = strtolower(trim($sv));
                    return !in_array($svLower, ['active', 'registered', 'live'], true);
                });
            }
        }
        $statuses = [];
        foreach ($statusValues as $status) {
            $status = preg_replace('/\s*\(?https?:\/\/.*$/', '', $status);
            $status = trim($status);
            // Handle comma-separated statuses
            if (str_contains($status, ',')) {
                foreach (explode(',', $status) as $s) {
                    $s = trim($s);
                    if ($s !== '' && $s !== '-') {
                        $statuses[] = $s;
                    }
                }
            } elseif ($status !== '' && $status !== '-') {
                $statuses[] = $status;
            }
        }

        // Fall back to "state" field for .ru/.su format where "state:" = domain status
        if (empty($statuses) && isset($fields['state'])) {
            foreach ($fields['state'] as $stateVal) {
                $stateVal = trim($stateVal);
                // Only treat as status if it looks like domain state (all caps, keywords like REGISTERED)
                if (preg_match('/^[A-Z, ]+$/', $stateVal)) {
                    foreach (explode(',', $stateVal) as $sv) {
                        $sv = trim($sv);
                        if ($sv !== '') $statuses[] = $sv;
                    }
                }
            }
        }

        // Also check "Domain Status:" with indented continuation
        if (preg_match_all('/^(Domain Status|Registration status):\s*\n((?:[ \t]+\S+.*\n)+)/m', $text, $m)) {
            foreach ($m[2] as $statusBlock) {
                foreach (explode("\n", trim($statusBlock)) as $line) {
                    $s = trim($line);
                    $s = preg_replace('/\s*\(?https?:\/\/.*$/', '', $s);
                    if ($s !== '' && $s !== '-') {
                        $statuses[] = $s;
                    }
                }
            }
        }

        // Extract nameservers
        $nameservers = [];
        $seenHosts = [];

        // First, process detailed nameservers (with IPs)
        foreach ($fields['name_server_detail'] ?? [] as $nsJson) {
            $nsData = json_decode($nsJson, true);
            if ($nsData && isset($nsData['hostname'])) {
                $hostname = strtolower($nsData['hostname']);
                if (!isset($seenHosts[$hostname])) {
                    $seenHosts[$hostname] = true;
                    $nameservers[] = new Nameserver(
                        hostname: $hostname,
                        ipv4: $nsData['ipv4'] ?? null,
                        ipv6: $nsData['ipv6'] ?? null,
                    );
                }
            }
        }

        // Then simple nameservers
        foreach ($fields['name_server'] ?? [] as $ns) {
            $ns = strtolower(rtrim(trim($ns), '.'));
            // Some servers include IP after hostname
            $parts = preg_split('/\s+/', $ns, 2);
            $hostname = $parts[0];
            // Strip " | IPv4:  and IPv6: " suffixes (.pt format)
            $hostname = preg_replace('/\s*\|.*$/', '', $hostname);
            $hostname = rtrim($hostname, '.');
            if (!isset($seenHosts[$hostname]) && preg_match('/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$/i', $hostname)) {
                $seenHosts[$hostname] = true;
                $nameservers[] = new Nameserver(hostname: $hostname);
            }
        }

        // Transliterate special characters for Portuguese .pt format
        if ($serverHostname === 'whois.dns.pt') {
            $this->transliterateFields($fields, ['registrant_name', 'registrant_address',
                'admin_name', 'admin_address', 'tech_name', 'tech_address',
                'registrant_city', 'admin_city', 'tech_city']);
        }


        // For .pt format, take only first email from comma-separated list
        foreach (['registrant_email', 'admin_email', 'tech_email'] as $emailKey) {
            if (isset($fields[$emailKey])) {
                foreach ($fields[$emailKey] as &$emailVal) {
                    if (str_contains($emailVal, ',')) {
                        $emailVal = trim(explode(',', $emailVal)[0]);
                    }
                }
                unset($emailVal);
            }
        }

        // Extract contacts
        $contacts = $this->extractContacts($fields, $text);

        // DNSSEC
        $dnssec = $this->normalizeDnssec($this->firstValue($fields, 'dnssec'), $serverHostname);

        // Sort statuses
        $statuses = array_values(array_unique($statuses));
        sort($statuses);

        // Sort nameservers
        usort($nameservers, function($a, $b) {
            return strcmp($a->hostname, $b->hostname);
        });
        $nameservers = array_values(array_unique($nameservers, SORT_REGULAR));

        return new DomainInfo(
            name: $domainName,
            registrar: $registrar,
            createdDate: $createdDate,
            updatedDate: $updatedDate,
            expiresDate: $expiresDate,
            status: $statuses,
            nameservers: $nameservers,
            contacts: $contacts,
            dnssec: $dnssec,
        );
    }

    private function normalizeDnssec(?string $value, string $serverHostname): string|false|null
    {
        if ($value === null) {
            return null;
        }

        $lower = strtolower(trim($value));

        // "signedDelegation" or "Signed delegation" or "signed" or "yes"
        if ($lower === 'signeddelegation' || $lower === 'signed delegation' || $lower === 'signed' || $lower === 'yes') {
            return 'signedDelegation';
        }

        // Servers that should return false for "unsigned"
        $falseServers = [
            'whois.hkirc.hk',
            'whois.identitydigital.services',
            'whois.iis.nu',
            'whois.iis.se',
            'whois.imena.bg',
            'whois.irs.net.nz',
            'whois.isoc.org.il',
            'whois.kr',
        ];

        if (in_array($serverHostname, $falseServers, true)) {
            if ($lower === 'unsigned' || $lower === 'unsigned delegation' || $lower === 'inactive' || $lower === '미서명') {
                return false;
            }
        }

        // Keep specific values as-is
        if ($lower === 'unsigned') return 'unsigned';
        if ($lower === 'no') return 'no';
        if ($lower === 'inactive') return $value;

        return $value;
    }

    private function parseIp(array $fields, string $text, string $rawResponse): IpInfo
    {
        // Try RPSL object parsing for RIPE/APNIC/AFRINIC/LACNIC
        // RPSL uses lowercase hyphenated keys (inetnum, inet6num); ARIN uses CamelCase (NetRange)
        $objects = $this->parseRpslObjects($text);
        $primaryObj = $this->findPrimaryObject($objects, ['inetnum', 'inet6num']);

        if ($primaryObj !== null) {
            return $this->buildIpFromRpslObjects($primaryObj, $objects, $rawResponse);
        }

        // Fallback: ARIN or flat format
        $range = $this->firstValue($fields, 'ip_range');
        $netName = $this->firstValue($fields, 'net_name');
        $description = $this->firstValue($fields, 'orgname')
            ?? $this->firstValue($fields, 'description');
        $country = $this->firstValue($fields, 'country');
        $createdDate = $this->parseDate($this->firstValue($fields, 'creation_date')
            ?? $this->firstValue($fields, 'created'));
        $updatedDate = $this->parseDate($this->firstValue($fields, 'updated_date')
            ?? $this->firstValue($fields, 'last_modified'));

        // Extract origin AS number — use last value (multiple routes may exist)
        $asNumber = null;
        $originValues = $fields['origin_as'] ?? $fields['asn'] ?? [];
        if ($originValues !== []) {
            $lastOrigin = end($originValues);
            $asNumber = (int)preg_replace('/^AS/i', '', $lastOrigin);
            if ($asNumber === 0) {
                $asNumber = null;
            }
        }

        $contacts = $this->extractArinContacts($fields, $text);
        $status = $this->extractIpStatus($fields);

        return new IpInfo(
            range: $range,
            networkName: $netName,
            description: $description,
            asNumber: $asNumber,
            country: $country,
            createdDate: $createdDate,
            updatedDate: $updatedDate,
            status: $status,
            contacts: $contacts,
        );
    }

    private function parseAsn(array $fields, string $text, string $rawResponse): AsnInfo
    {
        // Try RPSL object parsing for RIPE/APNIC/AFRINIC/LACNIC
        // RPSL uses lowercase hyphenated keys (aut-num); ARIN uses CamelCase (ASNumber)
        $objects = $this->parseRpslObjects($text);
        $primaryObj = $this->findPrimaryObject($objects, ['aut-num']);

        if ($primaryObj !== null) {
            return $this->buildAsnFromRpslObjects($primaryObj, $objects, $rawResponse);
        }

        // Fallback: ARIN or flat format
        $asnStr = $this->firstValue($fields, 'asn');
        $asn = null;
        if ($asnStr !== null) {
            $asn = (int)preg_replace('/^AS/i', '', $asnStr);
        }

        $name = $this->firstValue($fields, 'as_name');
        $description = $this->firstValue($fields, 'orgname')
            ?? $this->firstValue($fields, 'description');
        $country = $this->firstValue($fields, 'country');
        $createdDate = $this->parseDate($this->firstValue($fields, 'creation_date')
            ?? $this->firstValue($fields, 'created'));
        $updatedDate = $this->parseDate($this->firstValue($fields, 'updated_date')
            ?? $this->firstValue($fields, 'last_modified'));

        $contacts = $this->extractArinContacts($fields, $text);

        return new AsnInfo(
            asn: $asn,
            name: $name,
            description: $description,
            country: $country,
            createdDate: $createdDate,
            updatedDate: $updatedDate,
            contacts: $contacts,
        );
    }

    /**
     * Parse RPSL-style WHOIS response into individual objects.
     * Objects are separated by blank lines and have "key: value" fields.
     * @return array<int, array{type: string, fields: array<string, string[]>}>
     */
    private function parseRpslObjects(string $text): array
    {
        $objects = [];
        $lines = explode("\n", $text);
        $currentFields = [];
        $currentType = null;

        foreach ($lines as $line) {
            $trimmed = trim($line);

            // Blank line = end of object
            if ($trimmed === '') {
                if ($currentType !== null && $currentFields !== []) {
                    $objects[] = ['type' => $currentType, 'fields' => $currentFields];
                }
                $currentFields = [];
                $currentType = null;
                continue;
            }

            // Parse "key: value" (with optional continuation lines using leading whitespace)
            if (preg_match('/^([a-z][a-z0-9_-]*)\s*:\s*(.*)/i', $trimmed, $m)) {
                $key = strtolower($m[1]);
                $value = trim($m[2]);
                if ($currentType === null) {
                    $currentType = $key;
                }
                $currentFields[$key][] = $value;
            } elseif (preg_match('/^\s+(.+)/', $line, $m) && $currentFields !== []) {
                // Continuation line — append to last key's last value
                $lastKey = array_key_last($currentFields);
                if ($lastKey !== null) {
                    $lastIdx = array_key_last($currentFields[$lastKey]);
                    $currentFields[$lastKey][$lastIdx] .= "\n" . trim($m[1]);
                }
            }
        }

        if ($currentType !== null && $currentFields !== []) {
            $objects[] = ['type' => $currentType, 'fields' => $currentFields];
        }

        return $objects;
    }

    /**
     * Find the primary object of a given type from parsed RPSL objects.
     */
    private function findPrimaryObject(array $objects, array $types): ?array
    {
        foreach ($objects as $obj) {
            if (in_array($obj['type'], $types, true)) {
                return $obj;
            }
        }
        return null;
    }

    /**
     * Resolve a nic-hdl reference to a person/role/organisation object.
     */
    private function resolveRpslContact(string $handle, array $objects): ?array
    {
        $handleLower = strtolower($handle);
        foreach ($objects as $obj) {
            $nicHdl = strtolower($obj['fields']['nic-hdl'][0] ?? '');
            if ($nicHdl === $handleLower) {
                return $obj;
            }
        }
        return null;
    }

    /**
     * Resolve an org reference to an organisation object.
     */
    private function resolveRpslOrg(string $orgId, array $objects): ?array
    {
        $orgIdLower = strtolower($orgId);
        foreach ($objects as $obj) {
            if ($obj['type'] === 'organisation') {
                $objOrgId = strtolower($obj['fields']['organisation'][0] ?? '');
                if ($objOrgId === $orgIdLower) {
                    return $obj;
                }
            }
        }
        return null;
    }

    /**
     * Build a Contact from a RPSL person/role object.
     */
    private function contactFromRpslObject(array $obj, ContactType $type, bool $appendCountry = false): ?Contact
    {
        $f = $obj['fields'];

        $name = $f['person'][0] ?? $f['role'][0] ?? null;
        $org = $f['org-name'][0] ?? null;
        $email = $f['e-mail'][0] ?? $f['abuse-mailbox'][0] ?? null;
        $phone = $f['phone'][0] ?? null;
        // Strip "tel:" prefix from phone (AFRINIC format)
        if ($phone !== null) {
            $phone = preg_replace('/^tel:/i', '', $phone);
        }
        $fax = $f['fax-no'][0] ?? null;
        if ($fax !== null) {
            $fax = preg_replace('/^tel:/i', '', $fax);
        }

        // Build address from address lines (may contain \n from continuation lines)
        $rawAddressLines = $f['address'] ?? [];
        $addressLines = [];
        foreach ($rawAddressLines as $line) {
            foreach (explode("\n", $line) as $subLine) {
                $subLine = trim($subLine);
                if ($subLine !== '') {
                    $addressLines[] = $subLine;
                }
            }
        }
        $country = $f['country'][0] ?? null;
        if ($country === 'ZZ') {
            $country = null;
        }
        $address = null;
        if ($addressLines !== []) {
            $address = implode(', ', $addressLines);
            if ($appendCountry && $country !== null && !str_contains($address, $country)) {
                $address .= ', ' . $country;
            }
        }

        if ($name === null && $org === null && $email === null && $phone === null && $fax === null && $address === null) {
            return null;
        }

        return new Contact(
            type: $type,
            name: $name,
            organization: $org,
            email: $email,
            phone: $phone,
            fax: $fax,
            address: $address,
        );
    }

    /**
     * Build IpInfo from RPSL objects (RIPE/APNIC/LACNIC/AFRINIC format).
     */
    private function buildIpFromRpslObjects(array $primaryObj, array $objects, string $text): IpInfo
    {
        $f = $primaryObj['fields'];

        $range = $f['inetnum'][0] ?? $f['inet6num'][0] ?? null;
        $netName = $f['netname'][0] ?? null;
        $description = $f['descr'][0] ?? $f['owner'][0] ?? null;
        $country = $f['country'][0] ?? null;

        $createdDate = $this->parseDate($f['created'][0] ?? null);
        $updatedDate = $this->parseDate($f['last-modified'][0] ?? $f['changed'][0] ?? null);

        // Status
        $status = [];
        foreach ($f['status'] ?? [] as $s) {
            $s = trim($s);
            if ($s !== '') {
                $status[] = $s;
            }
        }

        // Origin AS from route/route6 objects
        $asNumber = null;
        $originValues = [];
        // Also check aut-num field (LACNIC puts it in the inetnum object)
        foreach ($f['aut-num'] ?? [] as $autnum) {
            $originValues[] = $autnum;
        }
        foreach ($objects as $obj) {
            if (in_array($obj['type'], ['route', 'route6'], true)) {
                foreach ($obj['fields']['origin'] ?? [] as $origin) {
                    $originValues[] = $origin;
                }
            }
        }
        if ($originValues !== []) {
            $lastOrigin = end($originValues);
            $asNumber = (int)preg_replace('/^AS/i', '', $lastOrigin);
            if ($asNumber === 0) {
                $asNumber = null;
            }
        }

        // Resolve contacts
        $contacts = $this->resolveRpslContacts($primaryObj, $objects, $text);

        return new IpInfo(
            range: $range,
            networkName: $netName,
            description: $description,
            asNumber: $asNumber,
            country: $country,
            createdDate: $createdDate,
            updatedDate: $updatedDate,
            status: $status,
            contacts: $contacts,
        );
    }

    /**
     * Build AsnInfo from RPSL objects (RIPE/APNIC/LACNIC/AFRINIC format).
     */
    private function buildAsnFromRpslObjects(array $primaryObj, array $objects, string $text): AsnInfo
    {
        $f = $primaryObj['fields'];

        $asnStr = $f['aut-num'][0] ?? null;
        $asn = null;
        if ($asnStr !== null) {
            $asn = (int)preg_replace('/^AS/i', '', $asnStr);
        }

        $name = $f['as-name'][0] ?? null;
        $description = $f['descr'][0] ?? null;
        // For LACNIC, "owner" is the description
        if ($description === null) {
            $description = $f['owner'][0] ?? null;
        }
        $country = $f['country'][0] ?? null;

        // If country not in primary object, get it from the linked organisation
        if ($country === null) {
            $orgRef = $f['org'][0] ?? null;
            if ($orgRef !== null) {
                $orgObj = $this->resolveRpslOrg($orgRef, $objects);
                if ($orgObj !== null) {
                    $country = $orgObj['fields']['country'][0] ?? null;
                }
            }
        }

        $createdDate = $this->parseDate($f['created'][0] ?? null);
        $updatedDate = $this->parseDate($f['last-modified'][0] ?? $f['changed'][0] ?? null);

        // Status
        $status = [];
        foreach ($f['status'] ?? [] as $s) {
            $s = trim($s);
            if ($s !== '') {
                $status[] = $s;
            }
        }

        // Resolve contacts
        $contacts = $this->resolveRpslContacts($primaryObj, $objects, $text);

        return new AsnInfo(
            asn: $asn,
            name: $name,
            description: $description,
            country: $country,
            createdDate: $createdDate,
            updatedDate: $updatedDate,
            status: $status,
            contacts: $contacts,
        );
    }

    /**
     * Resolve contacts from RPSL objects using admin-c, tech-c, abuse-c, org references.
     * @return Contact[]
     */
    private function resolveRpslContacts(array $primaryObj, array $objects, string $text): array
    {
        $contacts = [];
        $f = $primaryObj['fields'];

        // Detect LACNIC format — has 'owner' or 'responsible' field
        $isLacnic = isset($f['owner']) || isset($f['responsible']);

        // Registrant from org -> organisation object
        $orgRef = $f['org'][0] ?? null;
        if ($orgRef !== null) {
            $orgObj = $this->resolveRpslOrg($orgRef, $objects);
            if ($orgObj !== null) {
                $contact = $this->contactFromRpslObject($orgObj, ContactType::Registrant);
                if ($contact !== null) {
                    $contacts[] = $contact;
                }
            }
        }

        // LACNIC: registrant from owner/responsible/address/phone in primary object
        if ($orgRef === null && isset($f['owner'])) {
            $responsible = $f['responsible'][0] ?? null;
            $address = isset($f['address']) ? implode(', ', $f['address']) : null;
            $lacCountry = $f['country'][0] ?? null;
            if ($address !== null && $lacCountry !== null && !str_contains($address, $lacCountry)) {
                $address .= ', ' . $lacCountry;
            }
            $phone = $f['phone'][0] ?? null;
            if ($responsible !== null || $phone !== null || $address !== null) {
                $contacts[] = new Contact(
                    type: ContactType::Registrant,
                    name: $responsible,
                    phone: $phone,
                    address: $address,
                );
            }
        }

        // Admin contact
        $adminRefs = $f['admin-c'] ?? [];
        foreach ($adminRefs as $ref) {
            $contactObj = $this->resolveRpslContact($ref, $objects);
            if ($contactObj !== null) {
                $contact = $this->contactFromRpslObject($contactObj, ContactType::Admin, $isLacnic);
                if ($contact !== null) {
                    $contacts[] = $contact;
                }
            }
        }

        // Tech contact
        $techRefs = $f['tech-c'] ?? [];
        foreach ($techRefs as $ref) {
            $contactObj = $this->resolveRpslContact($ref, $objects);
            if ($contactObj !== null) {
                $contact = $this->contactFromRpslObject($contactObj, ContactType::Tech, $isLacnic);
                if ($contact !== null) {
                    $contacts[] = $contact;
                }
            }
        }

        // Abuse contact — from abuse-c reference, or from "Abuse contact for ... is 'email'" comment
        $abuseRefs = $f['abuse-c'] ?? [];
        $abuseResolved = false;
        foreach ($abuseRefs as $ref) {
            $contactObj = $this->resolveRpslContact($ref, $objects);
            if ($contactObj !== null) {
                $contact = $this->contactFromRpslObject($contactObj, ContactType::Abuse, $isLacnic);
                if ($contact !== null) {
                    $contacts[] = $contact;
                    $abuseResolved = true;
                }
            }
        }

        // If no abuse-c was resolved, try the IRT object
        if (!$abuseResolved) {
            foreach ($objects as $obj) {
                if ($obj['type'] === 'irt') {
                    $contact = $this->contactFromRpslObject($obj, ContactType::Abuse, $isLacnic);
                    if ($contact !== null) {
                        $contacts[] = $contact;
                        $abuseResolved = true;
                        break;
                    }
                }
            }
        }

        // Fallback: extract abuse email from boilerplate comment
        if (!$abuseResolved && preg_match("/Abuse contact.*?is '([^']+)'/i", $text, $m)) {
            $contacts[] = new Contact(
                type: ContactType::Abuse,
                email: $m[1],
            );
        }

        // LACNIC: tech-c and abuse-c resolve to same nic-hdl objects
        $ownerCRefs = $f['owner-c'] ?? [];
        foreach ($ownerCRefs as $ref) {
            // owner-c typically points to the same contact as abuse-c in LACNIC
            // Don't duplicate if already resolved via abuse-c
        }

        return $contacts;
    }

    /**
     * Extract contacts from ARIN format (OrgTechName, OrgAbuseName, etc.).
     * @return Contact[]
     */
    private function extractArinContacts(array $fields, string $text): array
    {
        $contacts = [];

        // Registrant from OrgName + Address/City/State/Postal/Country
        $orgName = $this->firstValue($fields, 'orgname')
            ?? $this->firstValue($fields, 'description');
        $address = null;
        $addrParts = [];
        $addrField = $this->firstValue($fields, 'address');
        $city = $this->firstValue($fields, 'city');
        $state = $this->firstValue($fields, 'stateprov');
        $postal = $this->firstValue($fields, 'postalcode');
        $countryField = $this->firstValue($fields, 'country');
        if ($addrField) $addrParts[] = $addrField;
        if ($city) $addrParts[] = $city;
        if ($state) $addrParts[] = $state;
        if ($postal) $addrParts[] = $postal;
        if ($countryField) $addrParts[] = $countryField;
        if ($addrParts !== []) {
            $address = implode(', ', $addrParts);
        }

        if ($orgName !== null || $address !== null) {
            $contacts[] = new Contact(
                type: ContactType::Registrant,
                name: $orgName,
                address: $address,
            );
        }

        // Parse tech and abuse contacts in the order they appear in the text
        $contactBlocks = [];
        // Match OrgTech*, OrgAbuse*, RTech*, RAbuse*, RNOC* blocks
        if (preg_match_all('/^(OrgTech|OrgAbuse|RTech|RAbuse|RNOC)(Handle|Name|Phone|Email|Ref):\s*(.+)$/m', $text, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $m) {
                $prefix = $m[1];
                $field = strtolower($m[2]);
                $value = trim($m[3]);
                $contactBlocks[$prefix][$field] = $value;
            }
        }

        // Emit contacts in order of first appearance
        $seenTypes = [];
        foreach ($contactBlocks as $prefix => $block) {
            $ctype = match (true) {
                str_contains($prefix, 'Tech') || str_contains($prefix, 'NOC') => 'tech',
                str_contains($prefix, 'Abuse') => 'abuse',
                default => null,
            };
            if ($ctype === null || isset($seenTypes[$ctype])) {
                continue;
            }
            $seenTypes[$ctype] = true;

            $contactType = $ctype === 'tech' ? ContactType::Tech : ContactType::Abuse;
            $name = $block['name'] ?? null;
            $email = $block['email'] ?? null;
            $phone = isset($block['phone']) ? trim($block['phone']) : null;
            if ($name !== null || $email !== null || $phone !== null) {
                $contacts[] = new Contact(
                    type: $contactType,
                    name: $name,
                    email: $email,
                    phone: $phone,
                );
            }
        }

        return $contacts;
    }

    /**
     * Extract IP status from flat fields.
     * @return string[]
     */
    private function extractIpStatus(array $fields): array
    {
        $status = [];
        foreach ($fields['status'] ?? [] as $s) {
            $s = trim($s);
            if ($s !== '') {
                $status[] = $s;
            }
        }
        return $status;
    }

    /**
     * @return Contact[]
     */
    private function extractContacts(array $fields, string $text): array
    {
        $contacts = [];
        $typeMap = [
            'registrant' => ContactType::Registrant,
            'admin' => ContactType::Admin,
            'tech' => ContactType::Tech,
        ];

        foreach ($typeMap as $prefix => $type) {
            $name = $this->filterRedacted($this->firstValue($fields, "{$prefix}_name"));
            $org = $this->filterRedacted($this->firstValue($fields, "{$prefix}_organization"));
            $email = $this->filterRedacted($this->firstValue($fields, "{$prefix}_email"));
            $phone = $this->filterRedacted($this->firstValue($fields, "{$prefix}_phone"));
            $fax = $this->filterRedacted($this->firstValue($fields, "{$prefix}_fax"));
            // Build address from available fields
            $addrValues = array_values(array_unique($fields["{$prefix}_address"] ?? []));
            $address = null;

            $cityVal = $this->filterRedacted($this->firstValue($fields, "{$prefix}_city"));
            $stateVal = $this->filterRedacted($this->firstValue($fields, "{$prefix}_state"));
            $postalVal = $this->filterRedacted($this->firstValue($fields, "{$prefix}_postal_code"));
            $countryVal = $this->filterRedacted($this->firstValue($fields, "{$prefix}_country"));
            $addressSkippedDueToRedaction = false;

            // Filter postal codes that are actually phone country codes
            // (e.g., "256" for Uganda - the phone field starts with "256")
            if ($postalVal !== null && $phone !== null && strlen($postalVal) <= 3
                && preg_match('/^\+?' . preg_quote($postalVal, '/') . '/', $phone)) {
                $postalVal = null;
            }

            if (!empty($addrValues)) {
                // If we have component fields (city, state, etc.), build compound address
                if ($cityVal !== null || $stateVal !== null || $countryVal !== null) {
                    // Use all address lines + components
                    $parts = [];
                    foreach ($addrValues as $av) {
                        $filtered = $this->filterRedacted($av);
                        if ($filtered !== null) $parts[] = $filtered;
                    }
                    $hasRealAddrData = !empty($parts);
                    if ($cityVal !== null) $parts[] = $cityVal;
                    if ($stateVal !== null) $parts[] = $stateVal;
                    if ($postalVal !== null) $parts[] = $postalVal;
                    if ($countryVal !== null) $parts[] = $countryVal;
                    // If all address lines were redacted and city is also null, don't build from scraps
                    // Unless state is available (e.g. "Chhattisgarh, IN")
                    if (!$hasRealAddrData && $cityVal === null && $stateVal === null) {
                        $address = null;
                        $addressSkippedDueToRedaction = true;
                    } else {
                        $address = implode(', ', $parts);
                    }
                } else {
                    // Just address lines, combine
                    if (count($addrValues) > 1) {
                        // Use newlines if these are separate address lines (multiple field entries)
                        $address = $this->filterRedacted(implode("\n", $addrValues));
                    } else {
                        $address = $this->filterRedacted($addrValues[0]);
                    }
                    // Append country if available from bare field
                    if ($countryVal !== null && $address !== null && !str_contains($address, $countryVal)) {
                        $address .= ', ' . $countryVal;
                    }
                }
            } elseif ($cityVal !== null || $stateVal !== null) {
                // No address field, but have city/state components
                $parts = array_filter([$cityVal, $stateVal, $countryVal]);
                if ($parts) {
                    $address = implode(', ', $parts);
                }
            } elseif ($prefix === 'registrant' && $countryVal !== null) {
                // Check if street/city fields have REDACTED values (meaning data is hidden)
                $rawStreet = $this->firstValue($fields, "{$prefix}_address");
                $rawCity = $this->firstValue($fields, "{$prefix}_city");
                $hasRedactedFields = ($rawStreet !== null && $this->filterRedacted($rawStreet) === null)
                    || ($rawCity !== null && $this->filterRedacted($rawCity) === null);

                if ($hasRedactedFields && $stateVal !== null) {
                    // Street/city redacted but state is visible — use state + country
                    $address = implode(', ', array_filter([$stateVal, $countryVal]));
                } elseif ($hasRedactedFields) {
                    // All address data redacted — don't construct from scraps
                    $address = null;
                } elseif ($stateVal !== null) {
                    $address = implode(', ', array_filter([$stateVal, $countryVal]));
                } else {
                    $address = $countryVal;
                }
            }

            // Build address from component fields if not already set
            if ($address === null && !$addressSkippedDueToRedaction) {
                $addrParts = [];

                // Try street + city + state + postal + country
                $street = $this->filterRedacted($this->firstValue($fields, "{$prefix}_street1") ?? $this->firstValue($fields, "{$prefix}_address"));
                $city = $this->filterRedacted($this->firstValue($fields, "{$prefix}_city"));
                $state = $this->filterRedacted($this->firstValue($fields, "{$prefix}_state"));
                $postal = $this->filterRedacted($this->firstValue($fields, "{$prefix}_postal_code"));
                $country = $this->filterRedacted($this->firstValue($fields, "{$prefix}_country"));

                if ($street) $addrParts[] = $street;
                if ($city) $addrParts[] = $city;
                if ($state) $addrParts[] = $state;
                if ($postal) $addrParts[] = $postal;
                if ($country) $addrParts[] = $country;

                if ($addrParts) {
                    // If only country is available, include it only if no fields were redacted
                    if ($street || $city || $state || $postal) {
                        $address = implode(', ', $addrParts);
                    } elseif ($country) {
                        // Check if this is a case where other fields are redacted vs just missing
                        $rawStreet = $this->firstValue($fields, "{$prefix}_street1") ?? $this->firstValue($fields, "{$prefix}_address");
                        $rawCity = $this->firstValue($fields, "{$prefix}_city");
                        $hasRedactedFields = ($rawStreet !== null && $this->filterRedacted($rawStreet) === null)
                            || ($rawCity !== null && $this->filterRedacted($rawCity) === null);
                        if (!$hasRedactedFields) {
                            $address = $country;
                        }
                    }
                }
            }

            $hasPersonalData = ($name !== null || $org !== null || $email !== null || $phone !== null || $fax !== null);

            // Don't create address-only contacts when all personal data was redacted/filtered
            if (!$hasPersonalData && $address !== null) {
                $rawNameCheck = $this->firstValue($fields, "{$prefix}_name");
                $rawOrgCheck = $this->firstValue($fields, "{$prefix}_organization");
                $hadRedactedIdentity = (
                    ($rawNameCheck !== null && $this->filterRedacted($rawNameCheck) === null)
                    || ($rawOrgCheck !== null && $this->filterRedacted($rawOrgCheck) === null)
                );
                $isCountryOnly = (bool) preg_match('/^[A-Z]{2}$/', $address);
                if ($hadRedactedIdentity && $isCountryOnly) {
                    $address = null;
                }
            }

            if ($name !== null || $org !== null || $email !== null || $phone !== null || $fax !== null || $address !== null) {
                $contacts[] = new Contact(
                    type: $type,
                    name: $name,
                    organization: $org,
                    email: $email,
                    phone: $phone,
                    fax: $fax,
                    address: $address,
                );
            }
        }

        return $contacts;
    }

    /**
     * @return Contact[]
     */
    private function extractIpContacts(array $fields, string $text): array
    {
        $contacts = [];

        if (preg_match('/Abuse contact.*?is \'([^\']+)\'/i', $text, $m)) {
            $contacts[] = new Contact(
                type: ContactType::Abuse,
                email: $m[1],
            );
        }

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

    private function parseDate(?string $dateStr): ?string
    {
        if ($dateStr === null || $dateStr === '') {
            return null;
        }

        // If it's already in Y-m-d H:i:s format, return as-is
        if (preg_match('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $dateStr)) {
            return $dateStr;
        }

        // Strip ordinal suffixes: 1st, 2nd, 3rd, 23rd, etc.
        $dateStr = preg_replace('/(\d)(st|nd|rd|th)\b/i', '$1', $dateStr);

        // Strip day names
        $dateStr = preg_replace('/^(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)\s+/i', '', $dateStr);

        // Strip timezone abbreviations like "(JST)" or "CLST" or "(UTC+8)"
        $dateStr = preg_replace('/\s*\([A-Z]{2,5}(?:[+-]\d{1,2}(?::\d+)?)?\)\s*$/', '', $dateStr);
        $dateStr = preg_replace('/\s+[A-Z]{3,5}\s*$/', '', $dateStr);

        // Handle timezone offsets like "+03:00" or "+0000"
        $dateStr = preg_replace('/\s*\+\d{2}:\d{2}\s*$/', '', $dateStr);

        // Korean date: "2004. 10. 07." -> "2004-10-07"
        if (preg_match('/^(\d{4})\.\s*(\d{1,2})\.\s*(\d{1,2})\.\s*$/', $dateStr, $m)) {
            $dateStr = sprintf('%s-%02d-%02d', $m[1], (int)$m[2], (int)$m[3]);
        }

        // "dd-MM-yyyy HH:mm:ss GMT+N" format (Tunisian) - convert to UTC
        if (preg_match('/^(\d{2}-\d{2}-\d{4}\s+\d{2}:\d{2}:\d{2})\s*GMT([+-]\d+)\s*$/', $dateStr, $gmtm)) {
            $offsetHours = (int)$gmtm[2];
            $dt = \DateTimeImmutable::createFromFormat('d-m-Y H:i:s', $gmtm[1],
                new \DateTimeZone(sprintf('%+03d00', $offsetHours)));
            if ($dt !== false) {
                return $dt->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d H:i:s');
            }
        }
        $dateStr = preg_replace('/\s*GMT[+-]\d+\s*$/', '', $dateStr);

        // Formats with microseconds: strip sub-second parts
        $dateStr = preg_replace('/(\d{2}:\d{2}:\d{2})\.\d+/', '$1', $dateStr);

        $formats = [
            'Y-m-d\TH:i:sP',
            'Y-m-d\TH:i:s.uP',
            'Y-m-d\TH:i:sO',
            'Y-m-d\TH:i:s',
            'Y-m-d H:i:s',
            'Y-m-d',
            'd-M-Y',
            'd-M-Y H:i:s',
            'd/m/Y H:i:s',
            'd/m/Y',
            'm/d/Y',
            'Y/m/d',
            'Y/m/d H:i:s',
            'd.m.Y H:i:s',
            'd.m.Y',
            'd-m-Y H:i:s',
            'd-m-Y',
            'D M d H:i:s T Y',
            'd M Y',
            'M d Y',
            // "Mon Jan 12 2015"
            'D M d Y',
        ];

        $dateStr = trim($dateStr);

        // Date-only formats (should reset time to 00:00:00)
        $dateOnlyFormats = ['Y-m-d', 'd-M-Y', 'd/m/Y', 'm/d/Y', 'Y/m/d', 'd.m.Y', 'd-m-Y', 'd M Y', 'M d Y', 'D M d Y'];

        foreach ($formats as $format) {
            $dt = \DateTimeImmutable::createFromFormat($format, $dateStr);
            if ($dt !== false) {
                if (in_array($format, $dateOnlyFormats, true)) {
                    $dt = $dt->setTime(0, 0, 0);
                }
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

    private function bestDateValue(array $fields, string $key): ?string
    {
        $values = $fields[$key] ?? [];
        if (empty($values)) return null;
        if (count($values) === 1) return $values[0];

        // Filter to only values that look like dates (start with digit or month name)
        $dateValues = array_filter($values, function($v) {
            $v = trim($v);
            return preg_match('/^\d/', $v) || preg_match('/^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/i', $v);
        });
        if (empty($dateValues)) return $values[0];

        // Prefer the value with the most detail (longer string typically has time)
        usort($dateValues, fn($a, $b) => strlen($b) <=> strlen($a));
        return $dateValues[0];
    }

    private function firstValue(array $fields, string $key): ?string
    {
        return $fields[$key][0] ?? null;
    }

    private function transliterateFields(array &$fields, array $keys): void
    {
        foreach ($keys as $key) {
            if (isset($fields[$key])) {
                foreach ($fields[$key] as &$val) {
                    $val = $this->transliterate($val);
                }
                unset($val);
            }
        }
    }

    private function transliterate(string $value): string
    {
        if (function_exists('transliterator_transliterate')) {
            return transliterator_transliterate('Any-Latin; Latin-ASCII', $value);
        }

        // Manual Cyrillic (Ukrainian/Russian) transliteration
        static $cyrillicMap = [
            'А' => 'A', 'Б' => 'B', 'В' => 'V', 'Г' => 'G', 'Ґ' => 'G',
            'Д' => 'D', 'Е' => 'E', 'Є' => 'Ye', 'Ж' => 'Zh', 'З' => 'Z',
            'И' => 'I', 'І' => 'I', 'Ї' => 'Yi', 'Й' => 'Y', 'К' => 'K',
            'Л' => 'L', 'М' => 'M', 'Н' => 'N', 'О' => 'O', 'П' => 'P',
            'Р' => 'R', 'С' => 'S', 'Т' => 'T', 'У' => 'U', 'Ф' => 'F',
            'Х' => 'Kh', 'Ц' => 'Ts', 'Ч' => 'Ch', 'Ш' => 'Sh', 'Щ' => 'Shch',
            'Ъ' => '', 'Ы' => 'Y', 'Ь' => '', 'Э' => 'E', 'Ю' => 'Yu',
            'Я' => 'Ya',
            'а' => 'a', 'б' => 'b', 'в' => 'v', 'г' => 'g', 'ґ' => 'g',
            'д' => 'd', 'е' => 'e', 'є' => 'ye', 'ж' => 'zh', 'з' => 'z',
            'и' => 'i', 'і' => 'i', 'ї' => 'yi', 'й' => 'y', 'к' => 'k',
            'л' => 'l', 'м' => 'm', 'н' => 'n', 'о' => 'o', 'п' => 'p',
            'р' => 'r', 'с' => 's', 'т' => 't', 'у' => 'u', 'ф' => 'f',
            'х' => 'kh', 'ц' => 'ts', 'ч' => 'ch', 'ш' => 'sh', 'щ' => 'shch',
            'ъ' => '', 'ы' => 'y', 'ь' => '', 'э' => 'e', 'ю' => 'yu',
            'я' => 'ya',
            // Macedonian specific
            'Ѓ' => 'Gj', 'ѓ' => 'gj', 'Ј' => 'J', 'ј' => 'j',
            'Љ' => 'Lj', 'љ' => 'lj', 'Њ' => 'Nj', 'њ' => 'nj',
            'Ќ' => 'Kj', 'ќ' => 'kj', 'Џ' => 'Dz', 'џ' => 'dz',
            'Ѕ' => 'Dz', 'ѕ' => 'dz',
            // Latin diacritics
            'ã' => 'a', 'Ã' => 'A', 'ç' => 'c', 'Ç' => 'C',
            'ñ' => 'n', 'Ñ' => 'N', 'ó' => 'o', 'Ó' => 'O',
            'á' => 'a', 'Á' => 'A', 'é' => 'e', 'É' => 'E',
            'í' => 'i', 'Í' => 'I', 'ú' => 'u', 'Ú' => 'U',
            'ü' => 'u', 'Ü' => 'U', 'ö' => 'o', 'Ö' => 'O',
            'ä' => 'a', 'Ä' => 'A',
            'à' => 'a', 'è' => 'e', 'ì' => 'i', 'ò' => 'o', 'ù' => 'u',
            'â' => 'a', 'ê' => 'e', 'î' => 'i', 'ô' => 'o', 'û' => 'u',
            'Nº' => 'No', 'nº' => 'no', 'º' => 'o',
            'ā' => 'a', 'ī' => 'i', 'ū' => 'u',
            'ž' => 'z', 'Ž' => 'Z', 'š' => 's', 'Š' => 'S',
            'č' => 'c', 'Č' => 'C', 'ř' => 'r', 'Ř' => 'R',
            'ě' => 'e', 'Ě' => 'E', 'ý' => 'y', 'Ý' => 'Y',
            'ď' => 'd', 'Ď' => 'D', 'ť' => 't', 'Ť' => 'T',
            'ň' => 'n', 'Ň' => 'N',
        ];

        // Apply character mapping
        $result = strtr($value, $cyrillicMap);

        return $result;
    }

    private function filterRedacted(?string $value): ?string
    {
        if ($value === null) {
            return null;
        }

        $normalized = strtolower(trim($value));
        if (in_array($normalized, [
            'redacted',
            'redacted for privacy',
            'data protected',
            'not disclosed',
            'not available',
            'n/a',
            'gdpr masked',
            'gdpr protected',
            'hidden',
            'statutory masking enabled',
            '<not disclosed>',
        ], true)) {
            return null;
        }

        // Pattern: "REDACTED FOR PRIVACY", "REDACTED_FOR_PRIVACY", "REDACTED | ..."
        if (preg_match('/^redacted[\b_\s]/i', $value) || strtolower($value) === 'redacted') {
            return null;
        }

        // "GDPR protected" or "GDPR protected (GDPR protected)"
        if (preg_match('/^GDPR\s+protected/i', $value)) {
            return null;
        }

        // "hidden, hidden, hidden..." (all hidden parts)
        if (preg_match('/^(hidden[,\s]*)+$/i', $value)) {
            return null;
        }

        // Privacy-protected emails (e.g., hex@privacyprotected.net)
        if (preg_match('/@privacyprotected\./i', $value)) {
            return null;
        }

        // Migration/placeholder values
        if (preg_match('/^MIGRATION[-_]/i', $value)) {
            return null;
        }

        // "Please query..." or "Please contact..." or "Please ask..."
        if (preg_match('/^please\s+(query|contact|ask)\b/i', $value)) {
            return null;
        }

        // "Not Disclosed - Visit..."
        if (preg_match('/^not disclosed\s*-/i', $value)) {
            return null;
        }

        // "NOT DISCLOSED!"
        if (preg_match('/^NOT DISCLOSED/i', $value)) {
            return null;
        }

        // "Not shown, please visit..." or "(not shown)"
        if (preg_match('/^not shown|^\(not shown\)/i', $value)) {
            return null;
        }

        // Values that are mostly question marks (encoding issues, e.g., Arabic text in non-UTF8)
        if (preg_match('/^\?[\?\s]+$/', $value)) {
            return null;
        }

        // NIC handles that look like IDs (e.g., "ASCIO0732-866124", "AAIO6168489-NICAT")
        if (preg_match('/^[A-Z]{2,}\d{3,}-\d+$/i', $value)
            || preg_match('/^[A-Z0-9]+-NIC[A-Z]+$/i', $value)) {
            return null;
        }

        // URLs are not valid contact data
        if (preg_match('/^https?:\/\//i', $value)) {
            return null;
        }

        // "Visit www..." patterns
        if (preg_match('/^visit\s+/i', $value)) {
            return null;
        }

        return $value;
    }
}
