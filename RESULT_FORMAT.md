# Result JSON Format

All result types are returned by `toArray()` on the info object. Only non-null fields are included in the output. Empty arrays are omitted.

## Domain

Returned by `Whoeasy::domain()` or when querying a domain name.

```json
{
    "name": "example.com",
    "registrar": {
        "name": "Example Registrar Inc.",
        "ianaId": "1234",
        "url": "https://example-registrar.com",
        "abuseEmail": "abuse@example-registrar.com",
        "abusePhone": "+1.5551234567"
    },
    "createdDate": "2000-01-01 00:00:00",
    "updatedDate": "2024-01-01 00:00:00",
    "expiresDate": "2025-01-01 00:00:00",
    "status": [
        "clientTransferProhibited",
        "serverDeleteProhibited"
    ],
    "nameservers": [
        {
            "hostname": "ns1.example.com",
            "ipv4": "1.2.3.4",
            "ipv6": "2001:db8::1"
        },
        {
            "hostname": "ns2.example.com"
        }
    ],
    "contacts": [
        {
            "type": "registrant",
            "name": "John Doe",
            "organization": "Example Corp",
            "email": "john@example.com",
            "phone": "+1.5551234567",
            "fax": "+1.5559876543",
            "address": "US"
        }
    ],
    "dnssec": "signedDelegation"
}
```

### Fields

| Field | Type | Description |
|---|---|---|
| `name` | string | Domain name as returned by the server |
| `registrar` | object | Sponsoring registrar (see [Registrar](#registrar)) |
| `createdDate` | string | Registration date, normalized to `Y-m-d H:i:s` |
| `updatedDate` | string | Last modification date |
| `expiresDate` | string | Expiration date |
| `status` | string[] | EPP status codes (URL suffixes stripped) |
| `nameservers` | object[] | Authoritative nameservers (see [Nameserver](#nameserver)) |
| `contacts` | object[] | Domain contacts (see [Contact](#contact)) |
| `dnssec` | string | DNSSEC status, e.g. `"signedDelegation"`, `"unsigned"` |

## IP

Returned by `Whoeasy::ip()` or when querying an IPv4/IPv6 address.

```json
{
    "range": "8.8.8.0 - 8.8.8.255",
    "networkName": "GOGL",
    "description": "Google LLC",
    "country": "US",
    "createdDate": "2014-03-14 00:00:00",
    "updatedDate": "2014-03-14 00:00:00",
    "status": [
        "active"
    ],
    "contacts": [
        {
            "type": "registrant",
            "name": "Google LLC",
            "email": "arin-contact@google.com"
        },
        {
            "type": "abuse",
            "email": "network-abuse@google.com",
            "phone": "+1-650-253-0000"
        }
    ]
}
```

### Fields

| Field | Type | Description |
|---|---|---|
| `range` | string | IP range. Format varies: `"start - end"` (RDAP) or `"prefix/length"` (WHOIS) |
| `networkName` | string | Short network identifier (e.g. `"GOGL"`, `"CLOUDFLARENET"`) |
| `description` | string | Organization or network description |
| `country` | string | 2-letter ISO country code |
| `createdDate` | string | Registration date, normalized to `Y-m-d H:i:s` |
| `updatedDate` | string | Last modification date |
| `status` | string[] | Network status codes |
| `contacts` | object[] | Network contacts (see [Contact](#contact)) |

## ASN

Returned by `Whoeasy::asn()` or when querying an AS number.

```json
{
    "asn": 15169,
    "name": "GOOGLE",
    "description": "Google LLC",
    "country": "US",
    "createdDate": "2000-03-30 00:00:00",
    "updatedDate": "2012-02-24 00:00:00",
    "status": [
        "active"
    ],
    "contacts": [
        {
            "type": "registrant",
            "name": "Google LLC"
        },
        {
            "type": "tech",
            "name": "Google LLC",
            "email": "arin-contact@google.com"
        }
    ]
}
```

### Fields

| Field | Type | Description |
|---|---|---|
| `asn` | int | Autonomous System Number |
| `name` | string | AS name (e.g. `"GOOGLE"`, `"CLOUDFLARENET"`) |
| `description` | string | Organization or AS description |
| `country` | string | 2-letter ISO country code |
| `createdDate` | string | Registration date, normalized to `Y-m-d H:i:s` |
| `updatedDate` | string | Last modification date |
| `status` | string[] | AS status codes |
| `contacts` | object[] | AS contacts (see [Contact](#contact)) |

## Shared Types

### Registrar

Present only in domain results.

| Field | Type | Description |
|---|---|---|
| `name` | string | Registrar name |
| `ianaId` | string | IANA registrar ID |
| `url` | string | Registrar website URL |
| `abuseEmail` | string | Abuse contact email |
| `abusePhone` | string | Abuse contact phone |

### Nameserver

Present only in domain results.

| Field | Type | Description |
|---|---|---|
| `hostname` | string | **(always present)** Nameserver FQDN, lowercased |
| `ipv4` | string | Glue record IPv4 address |
| `ipv6` | string | Glue record IPv6 address |

### Contact

Used across all result types.

| Field | Type | Description |
|---|---|---|
| `type` | string | **(always present)** One of: `"registrant"`, `"admin"`, `"tech"`, `"abuse"` |
| `name` | string | Contact person or organization name |
| `organization` | string | Organization name (if separate from `name`) |
| `email` | string | Email address |
| `phone` | string | Phone number (typically E.164-ish, e.g. `"+1.5551234567"`) |
| `fax` | string | Fax number |
| `address` | string | Postal address or country code |

## Notes

- All fields except those marked "always present" are optional and omitted when null/empty.
- Dates are best-effort normalized to `Y-m-d H:i:s` format from whatever the server returns.
- WHOIS privacy/redaction placeholders (`"REDACTED"`, `"REDACTED FOR PRIVACY"`, etc.) are filtered out and treated as null.
- When using `QueryMode::Both`, RDAP fields take priority for scalars; arrays (status, contacts, nameservers) are merged with deduplication.
- Contact entries with all fields redacted/null (except `type`) are omitted entirely.
- EPP status codes have their ICANN URL suffixes stripped (e.g. `"clientTransferProhibited https://icann.org/..."` becomes `"clientTransferProhibited"`).
