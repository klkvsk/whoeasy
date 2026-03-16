<?php
/**
 * RDAP base URLs where WHOIS (port 43) is known to be disabled/unsupported.
 * TLDs served by these RDAP endpoints will have their WHOIS server set to null
 * in the generated registry, forcing RDAP-only queries.
 *
 * Used by: generate-registry.php, collect-whois-fixtures.php
 */

return [
    'https://rdap.identitydigital.services/rdap/',
    'https://pubapi.registry.google/rdap/',
    'https://www.registry.google/rdap/',
];
