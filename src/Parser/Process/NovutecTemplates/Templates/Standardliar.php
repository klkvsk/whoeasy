<?php

namespace Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Templates;

use Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Result\Result;

/**
 * Some DNS servers have been found to lie about domain status, causing a domain that we already know is registered
 * to be incorrectly reported as unregistered.
 *
 * This template resolves this issue by ignoring an unregistered state if the domain is already considered registered.
 */
class Standardliar extends Standard
{

    public function parse(Result $result, string $rawData): void
    {
        if (isset($this->available) && strlen($this->available)) {
            preg_match_all($this->available, $rawData, $matches);

            $registered = empty($matches[0]);
            if (!$registered) {
                if (isset($result->registered) && $result->registered) {
                    return;
                }
            }
        }

        parent::parse($result, $rawData);
    }
}
