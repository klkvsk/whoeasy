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
 * Template for .SG
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Sg extends Regex
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     */
    protected array $blocks = [ 1 => '/registrar:(?>[\x20\t]*)(.*?)(?=registrant)/is',
                                2 => '/registrant:(?>[\x20\t]*)(.*?)(?=administrative contact)/is',
                                3 => '/administrative contact:(?>[\x20\t]*)(.*?)(?=technical contact)/is',
                                4 => '/technical contact:(?>[\x20\t]*)(.*?)(?=name servers)/is',
                                5 => '/name servers:(?>[\x20\t]*)(.*?)$/is' ];

    /**
     * Items for each block
     *
     * @var array
     */
    protected array $blockItems = [
        1 => [ '/registrar:(?>[\x20\t]*)(.+)$/im'       => 'registrar:name',
               '/creation date:(?>[\x20\t]*)(.+)$/im'   => 'created',
               '/modified date:(?>[\x20\t]*)(.+)$/im'   => 'changed',
               '/expiration date:(?>[\x20\t]*)(.+)$/im' => 'expires',
               '/domain status:(?>[\x20\t]*)(.+)$/im'   => 'status' ],
        2 => [ '/name:(?>[\x20\t]*)(.+) \(.+\)/im' => 'contacts:owner:name',
               '/name:(?>[\x20\t]*).+ \((.+)\)/im' => 'contacts:owner:handle' ],
        3 => [ '/name:(?>[\x20\t]*)(.+) \(.+\)/im' => 'contacts:admin:name',
               '/name:(?>[\x20\t]*).+ \((.+)\)/im' => 'contacts:admin:handle' ],
        4 => [ '/name:(?>[\x20\t]*)(.+) \(.+\)/im' => 'contacts:tech:name',
               '/name:(?>[\x20\t]*).+ \((.+)\)/im' => 'contacts:tech:handle',
               '/email:(?>[\x20\t]*)(.+)/im'       => 'contacts:tech:email' ],
        5 => [ '/\n(?>[\x20\t]+)(.+)$/im' => 'nameserver' ] ];

    /**
     * RegEx to check availability of the domain name
     */
    protected ?string $available = '/Domain Not Found/i';
}