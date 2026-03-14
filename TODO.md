# TODO

## Registry Consolidation

Two registry systems exist:
- `src/Registry/` — currently used by `Whoeasy`. Simple TLD/IP/ASN lookup from generated data.
- `src/Client/Registry/` — unused (from earlier iteration). Contains server-specific customizations (custom query formats, HTTP-based WHOIS servers, special handling for .vn, .be, .de, ARIN, etc.) in `AdditionalServerRegistry`.

### Plan
- Migrate server-specific customizations from `Client/Registry/AdditionalServerRegistry` into `src/Registry/`.
- Split into protocol-specific registries: `WhoisRegistry` and `RdapRegistry` (or similar), since WHOIS and RDAP servers have different metadata needs.
- Investigate splitting `ServerInfo` into `WhoisServerInfo` (server hostname, custom query format, charset, port) and `RdapServerInfo` (base URL, supported object types). Current `ServerInfo` conflates both.
- Remove `src/Client/Registry/` once all customizations are migrated.

## Parser Result Model Refactor

`src/Parser/Data/` contains `AbstractResult` and descendants (`DomainResult`, `IpResult`, `AsnResult`, `ContactResult`) — mutable `stdClass`-based intermediate parse results.
`src/Result/` contains the final readonly value objects (`DomainInfo`, `IpInfo`, `AsnInfo`, `Contact`, etc.).

### Plan
- Evaluate whether the intermediate `Parser/Data/` classes can be eliminated in favor of building `Result/` objects directly during parsing.
- If intermediate representation is needed, make it internal to the parser — not part of the public API.

## Recursive Query Model

Current model uses `AuthLevel` enum (Auth/NonAuth) and `HopResponses` with two fixed slots (`auth`, `nonAuth`).

### Plan
- Replace `AuthLevel` with a boolean `recursive` option (default: true). When true, follow referral chain (registry -> registrar). When false, return only the first response.
- Replace `HopResponses` with an ordered array of hops, where each hop records the server that responded and its raw response. This naturally handles chains of any depth (e.g., registry -> regional -> registrar).
- Remove `AuthLevel` enum.

## Cleanup

- Remove `src/Client/Registry/` after registry consolidation (above).
- `bin/whoeasy` CLI script may reference old class names — audit and fix or remove.
- `QueryOptions::$authLevel` — remove after recursive query model is implemented.
