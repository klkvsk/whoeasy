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
 * @namespace Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Templates
 */

namespace Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Templates;

use Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Templates\Type\Regex;

/**
 * Template for .DK
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Dk extends Regex
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     */
    protected array $blocks = [ 1 => '/domain:(?>[\x20\t]*)(.*?)(?=registrant)/is',
                                2 => '/registrant\n(.*?)(?=administrator)/is',
                                3 => '/administrator\n(.*?)(?=nameservers)/is', 4 => '/nameservers\n(.*?)$/is' ];

    /**
     * Items for each block
     *
     * @var array
     */
    protected array $blockItems = [
        1 => [ '/registered:(?>[\x20\t]*)(.+)$/im' => 'created',
               '/expires:(?>[\x20\t]*)(.+)$/im'    => 'expires',
               '/status:(?>[\x20\t]*)(.+)$/im'     => 'status' ],
        2 => [ '/handle:(?>[\x20\t]*)(.+)$/im'     => 'contacts:owner:handle',
               '/name:(?>[\x20\t]*)(.+)$/im'       => 'contacts:owner:name',
               '/address:(?>[\x20\t]*)(.+)$/im'    => 'contacts:owner:address',
               '/postalcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode',
               '/city:(?>[\x20\t]*)(.+)$/im'       => 'contacts:owner:city',
               '/country:(?>[\x20\t]*)(.+)$/im'    => 'contacts:owner:country',
               '/phone:(?>[\x20\t]*)(.+)$/im'      => 'contacts:owner:phone' ],
        3 => [ '/handle:(?>[\x20\t]*)(.+)$/im'     => 'contacts:admin:handle',
               '/name:(?>[\x20\t]*)(.+)$/im'       => 'contacts:admin:name',
               '/address:(?>[\x20\t]*)(.+)$/im'    => 'contacts:admin:address',
               '/postalcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:zipcode',
               '/city:(?>[\x20\t]*)(.+)$/im'       => 'contacts:admin:city',
               '/country:(?>[\x20\t]*)(.+)$/im'    => 'contacts:admin:country',
               '/phone:(?>[\x20\t]*)(.+)$/im'      => 'contacts:admin:phone' ],
        4 => [ '/hostname:(?>[\x20\t]*)(.+)$/im' => 'nameserver' ] ];

    /**
     * RegEx to check availability of the domain name
     */
    protected ?string $available = '/No entries found for the selected source/i';
}