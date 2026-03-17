<?php
/**
 * TLDs that have been revoked, retired, or are otherwise invalid.
 * These will be excluded entirely from the generated registry.
 *
 * Used by: generate-registry.php
 */

return [
    '.abarth', // revoked
    '.fed.us', // whois.nic.gov does not work for this TLD
];
