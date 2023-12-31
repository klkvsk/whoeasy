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
 * @namespace Novutec\Whois\Parser\Templates
 */

namespace Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Templates;

use Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Templates\Type\Regex;

/**
 * Template for .MD Domains
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Md extends Regex
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     */
    protected array $blocks = [ 1 => '/Domain name:(.*?)$/is' ];

    /**
     * Items for each block
     *
     * @var array
     */
    protected array $blockItems = [
        1 => [ '/Registrant:(.*)$/im'      => 'contacts:owner:name',
               '/Created: (.*)$/im'        => 'created', '/Expiration date: (.*)$/im' => 'expires',
               '/Name server: (.*) .*$/im' => 'nameserver',
               '/Name server: .* (.*)$/im' => 'ips' ] ];

    /**
     * RegEx to check availability of the domain name
     */
    protected ?string $available = '/No match for/i';
}