<?php
/**
 * Novutec Domain Tools
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @category   Novutec
 * @package    DomainParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * @namespace Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Templates\Type
 */

namespace Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Templates\Type;

use Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Exception\AbstractException;
use Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Exception\RateLimitException;
use Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Result\Result;

/**
 * WhoisParser AbstractTemplate
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
abstract class AbstractTemplate
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     */
    protected array $blocks = [];

    /**
     * Items for each block
     *
     * @var array
     */
    protected array $blockItems = [];

    /**
     * RegEx to check availability of the domain name
     */
    protected ?string $available = null;

    /**
     * RegEx to check for rate limit error message
     * @var ?string
     */
    protected ?string $rateLimit = null;

    /**
     * Cut block from HTML output for $blocks
     */
    protected ?string $htmlBlock = null;

    /**
     * Load Template
     *
     * Returns a template object, if not null.
     */
    public static function factory(string $template, $customNamespace = null): AbstractTemplate
    {
        if (str_contains($template, '\\')) {
            $classFqcn = $template;
        } else {
            $className = ucfirst(str_replace('.', '_', $template));
            if ($customNamespace) {
                $namespace = rtrim($customNamespace, '\\') . '\\';
            } else {
                $namespace = 'Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Templates';
            }

            $classFqcn = "$namespace\\$className";
        }

        return new $classFqcn();
    }

    /**
     * @param object $WhoisParser
     * @return void
     */
    public function postProcess(object $WhoisParser): void
    {
    }


    /**
     * @throws AbstractException
     */
    public abstract function parse(Result $result, string $rawData): void;


    /**
     * @throws RateLimitException
     */
    protected function parseRateLimit(string $rawData): void
    {
        if (isset ($this->rateLimit) && strlen($this->rateLimit)) {
            if (preg_match($this->rateLimit, $rawData)) {
                throw new RateLimitException("Rate limit exceeded for server");
            }
        }
    }


    /**
     * Perform any necessary translation on the raw data before processing (for example, re-encoding to UTF-8)
     *
     * @param string $rawData
     * @return string
     */
    public function translateRawData(string $rawData): string
    {
        return $rawData;
    }
}