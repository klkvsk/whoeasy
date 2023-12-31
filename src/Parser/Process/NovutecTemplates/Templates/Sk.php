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
 * Template for .SK
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Sk extends Regex
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     */
    protected array $blocks = [ 1 => '/admin-id(.*?)(?=tech-id)/is',
                                2 => '/tech-id(.*?)(?=dns_name)/is', 3 => '/dns_name(.*?)$/is' ];

    /**
     * Items for each block
     *
     * @var array
     */
    protected array $blockItems = [
        1 => [ '/admin-id(?>[\x20\t]*)(.+)$/im'        => 'contacts:admin:handle',
               '/admin-name(?>[\x20\t]*)(.+)$/im'      => 'contacts:admin:name',
               '/admin-address(?>[\x20\t]*)(.+)$/im'   => 'contacts:admin:address',
               '/admin-telephone(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone',
               '/admin-email(?>[\x20\t]*)(.+)$/im'     => 'contacts:admin:email',
               '/admin-org.-ID(?>[\x20\t]*)(.+)$/im'   => 'contacts:admin:orgid' ],

        2 => [ '/tech-id(?>[\x20\t]*)(.+)$/im'        => 'contacts:tech:handle',
               '/tech-name(?>[\x20\t]*)(.+)$/im'      => 'contacts:tech:name',
               '/tech-address(?>[\x20\t]*)(.+)$/im'   => 'contacts:tech:address',
               '/tech-telephone(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone',
               '/tech-email(?>[\x20\t]*)(.+)$/im'     => 'contacts:tech:email',
               '/tech-org.-ID(?>[\x20\t]*)(.+)$/im'   => 'contacts:tech:orgid' ],

        3 => [ '/dns_name(?>[\x20\t]*)(.+)$/im'      => 'nameserver',
               '/dns_ipv4(?>[\x20\t]*)(.+)$/im'      => 'ips',
               '/last-update(?>[\x20\t]*)(.+)$/im'   => 'changed',
               '/valid-date(?>[\x20\t]*)(.+)$/im'    => 'expires',
               '/domain-status(?>[\x20\t]*)(.+)$/im' => 'status' ] ];

    /**
     * RegEx to check availability of the domain name
     */
    protected ?string $available = '/Not found./i';
}