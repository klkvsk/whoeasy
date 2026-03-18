# Generate expected.json for WHOIS and RDAP fixtures

Generate `.expected.json` files for fixture files that don't have one yet.

## Instructions

1. Find fixture files that do NOT have a corresponding `.expected.json` sidecar:
   - **WHOIS**: all `.txt` files under `tests/Fixture/Whois/`, excluding `nxdomain.txt`, `ratelimit.txt`, and `error.txt`
   - **RDAP**: all `.json` files under `tests/Fixture/Rdap/`, excluding `nxdomain.json` and `ratelimit.json`

2. For each file, read the response and manually extract structured data following the format in `RESULT_FORMAT.md`.
Note: if response is empty or a server message -- do not write .expected.json and report such files in the end.
Server status messages examples: no match, temporary error, rate limit, etc.

3. Write the `.expected.json` file next to the fixture file with the same base name (e.g. `foo.txt` → `foo.expected.json`, `bar.json` → `bar.expected.json`). Pretty-print with 4-space indentation.

## Detecting result type

Determine the result type from the fixture filename:
- `ip-*.txt` / `ip-*.json` → **IP result** (IPv4)
- `ip6-*.txt` / `ip6-*.json` → **IP result** (IPv6)
- `asn-*.txt` / `asn-*.json` → **ASN result**
- Everything else → **Domain result**

Do NOT add any metadata fields like `queryType` — the test harness detects the type from the filename.

## Format rules

- Output is a JSON object with only non-null fields. Empty arrays are omitted.
- **Domain results**: `name`, `registrar{name,ianaId,url,abuseEmail,abusePhone}`, `createdDate`, `updatedDate`, `expiresDate`, `status[]`, `nameservers[{hostname,ipv4,ipv6}]`, `contacts[{type,name,organization,email,phone,fax,address}]`, `dnssec`
- **IP results**: `range`, `networkName`, `description`, `asNumber` (int), `country`, `createdDate`, `updatedDate`, `status[]`, `contacts[{type,name,organization,email,phone,fax,address}]`
- **ASN results**: `asn` (int), `name`, `description`, `country`, `createdDate`, `updatedDate`, `status[]`, `contacts[{type,name,organization,email,phone,fax,address}]`
- **Dates**: normalize to `Y-m-d H:i:s` format (e.g. `"2024-01-15 00:00:00"`)
- **EPP status**: strip everything from `http` onwards (e.g. `"clientTransferProhibited https://icann.org/..."` → `"clientTransferProhibited"`)
- **REDACTED values**: treat `REDACTED`, `REDACTED FOR PRIVACY`, `Not Disclosed`, `Data Protected`, `N/A`, `GDPR masked`, `Hidden upon user request`, and any value starting with `REDACTED` as null. Omit from output.
- **Contacts**: if all fields (name, organization, email, phone, fax, address) are null/redacted, omit the contact entirely. `type` is one of: `"registrant"`, `"admin"`, `"tech"`, `"abuse"`.
- **Nameservers**: lowercase hostnames. Include `ipv4`/`ipv6` only if glue records are present.
- **Registrar**: only include fields that are present (name, ianaId, url, abuseEmail, abusePhone).
- **asNumber**: origin AS number as integer (strip "AS" prefix). If multiple origin ASNs, use the last one.
- Multiline/combined fields such as addresses are joined with `, `.

## RDAP-specific notes

- RDAP fixtures are JSON files. Parse the JSON structure to extract fields.
- Domain name: `ldhName` or `unicodeName`
- Dates: from `events` array (action: `registration`, `last changed`, `expiration`)
- Status: from `status` array
- Nameservers: from `nameservers` array, use `ldhName`
- Contacts: from `entities` array with `vcardArray` (jCard format)
- Registrar: entity with role `registrar`
- IP range: from `startAddress`-`endAddress` or `cidr0_cidrs`
- ASN origin: from non-standard fields `arin_originas0_originautnums` or `lacnic_originAutnum`
- ASN info: from `startAutnum`, `name`

## Parallelization

If there are many files (>10), split them into batches of ~20 and process in parallel using subagents for efficiency.

## After generating

Report the count of files generated and any files where the response was empty/unparseable.
Do not run tests on these files unless asked. Do not edit those files is tests are failing.