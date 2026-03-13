# WhoisParser v2 (Whoeasy) - Implementation Plan

## Epic 1: Project Foundation & Core Types

- [x] 1.1 Project skeleton - new src/ structure, composer.json update, PHPUnit, PHPStan config
- [x] 1.2 Enums (QueryMode, QueryType, AuthLevel, ContactType) & Exception hierarchy
- [x] 1.3 Result value objects (QueryResult, StructuredResult, DomainInfo, IpInfo, AsnInfo, Contact, Registrar, Nameserver, RawResponse, HopResponses)
- [x] 1.4 Config, QueryOptions & Whoeasy skeleton class

## Epic 2: Server Registry & Build Pipeline

- [x] 2.1 TLD Server Registry & Generator
- [x] 2.2 IP & ASN Range Registry
- [x] 2.3 Data Source Cross-Reference & Validation
- [x] 2.4 ServerRegistry Lookup Logic

## Epic 3: WHOIS Protocol

- [x] 3.1 WHOIS Client (TCP:43)
- [x] 3.2 Universal WHOIS Parser
- [x] 3.3 Server-Specific Parser Infrastructure & Generation

## Epic 4: RDAP Protocol

- [ ] 4.1 RDAP Client (HTTP/HTTPS) - partial: HTTP adapter works but no dedicated RDAP client
- [ ] 4.2 RDAP Parser (RFC 9083) - only basic rdapToWhois conversion exists

## Epic 5: Query Orchestration & Merging

- [x] 5.1 Single-Protocol Query Modes (WhoisOnly + result mapping from parser data to Result VOs)
- [ ] 5.2 Prefer Modes & Fallback
- [ ] 5.3 Both Mode & Result Merging

## Epic 6: Comprehensive Test Fixtures

- [ ] 6.1 WHOIS Fixture Collection & Test Harness
- [ ] 6.2 RDAP Fixture Collection & Test Harness
- [ ] 6.3 CI Regression Gate
