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
 * Template for .QA
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Qa extends Regex
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     */
    protected array $blocks = [ 1 => '/domain name:(?>[\x20\t]*)(.*?)(?=registrant contact id)/is',
                                2 => '/registrant contact id:(?>[\x20\t]*)(.*?)(?=tech contact id)/is',
                                3 => '/tech contact id:(?>[\x20\t]*)(.*?)(?=name server)/is',
                                4 => '/name server:(?>[\x20\t]*)(.*?)$/is' ];

    /**
     * Items for each block
     *
     * @var array
     */
    protected array $blockItems = [
        1 => [ '/last modified:(?>[\x20\t]*)(.+)$/im'  => 'changed',
               '/registrar name:(?>[\x20\t]*)(.+)$/im' => 'registrar:name',
               '/status:(?>[\x20\t]*)(.+)$/im'         => 'status' ],
        2 => [ '/registrant contact id:(?>[\x20\t]*)(.+)$/im'      => 'contacts:owner:handle',
               '/registrant contact name:(?>[\x20\t]*)(.+)$/im'    => 'contacts:owner:name',
               '/registrant contact city:(?>[\x20\t]*)(.+)$/im'    => 'contacts:owner:city',
               '/registrant contact country:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country' ],
        3 => [ '/tech contact id:(?>[\x20\t]*)(.+)$/im'      => 'contacts:tech:handle',
               '/tech contact name:(?>[\x20\t]*)(.+)$/im'    => 'contacts:tech:name',
               '/tech contact city:(?>[\x20\t]*)(.+)$/im'    => 'contacts:tech:city',
               '/tech contact country:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country' ],
        4 => [ '/name server:(?>[\x20\t]*)(.+)$/im'    => 'nameserver',
               '/name server ip:(?>[\x20\t]*)(.+)$/im' => 'ips' ] ];

    /**
     * RegEx to check availability of the domain name
     */
    protected ?string $available = '/No Data Found/i';
}