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

/**
 * Template for IANA #625
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Buzz extends Type\Regex
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     * @access protected
     */
    protected array $blocks = [ 1 => '/domain name:(?>[\x20\t]*)(.*?)(?=>>>)/is' ];

    /**
     * Items for each block
     *
     * @var array
     * @access protected
     */
    protected array $blockItems = [
        1 => [ '/whois server:(?>[\x20\t]*)(.+)$/im'      => 'whoisserver',
               '/registrar:(?>[\x20\t]*)(.+)$/im'         => 'registrar:name',
               '/registrar iana id:(?>[\x20\t]*)(.+)$/im' => 'registrar:id',
               '/referral url:(?>[\x20\t]*)(.+)$/im'      => 'registrar:url',
               '/creation date:(?>[\x20\t]*)(.+)$/im'     => 'created',
               '/expiry date:(?>[\x20\t]*)(.+)$/im'       => 'expires',
               '/updated date:(?>[\x20\t]*)(.+)$/im'      => 'changed',
               '/name server:(?>[\x20\t]*)(.+)$/im'       => 'nameserver',
               '/dnssec:(?>[\x20\t]*)(.+)$/im'            => 'dnssec',
               '/status:(?>[\x20\t]*)(.+)$/im'            => 'status' ],
    ];
}
