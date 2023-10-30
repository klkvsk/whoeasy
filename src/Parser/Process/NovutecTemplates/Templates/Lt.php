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
 * Template for .LT
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Lt extends Regex
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     */
    protected array $blocks = [ 1 => '/Domain:(?>[\x20\t]*)(.*?)(?=Registrar:)/is',
                                2 => '/Registrar:(?>[\x20\t]*)(.*?)(?=Contact (name|organization))/is',
                                3 => '/Contact (name|organization):(?>[\x20\t]*)(.*?)(?=Contact (name|organization)|Nameserver)/is',
                                4 => '/Nameserver:(?>[\x20\t]*)(.*?)$/is' ];

    /**
     * Items for each block
     *
     * @var array
     */
    protected array $blockItems = [
        1 => [ '/^Status:(?>[\x20\t]*)(.+)$/im'     => 'status',
               '/^Registered:(?>[\x20\t]*)(.+)$/im' => 'created' ],
        2 => [ '/^Registrar:(?>[\x20\t]*)(.+)$/im'         => 'registrar:name',
               '/^Registrar website:(?>[\x20\t]*)(.+)$/im' => 'registrar:url',
               '/^Registrar email:(?>[\x20\t]*)(.+)$/im'   => 'registrar:email' ],
        3 => [ '/^Contact name:(?>[\x20\t]*)(.+)$/im'         => 'contacts:owner:name',
               '/^Contact organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization',
               '/^Contact email:(?>[\x20\t]*)(.+)$/im'        => 'contacts:owner:email' ],
        4 => [ '/^Nameserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver' ] ];

    /**
     * RegEx to check availability of the domain name
     */
    protected ?string $available = '/available/i';
}