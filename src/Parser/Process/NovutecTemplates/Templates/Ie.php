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
 * Template for .IE
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Ie extends Regex
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     */
    protected array $blocks = [ 1 => '/descr:(?>[\x20\t]*)(.*?)(?=person)/is',
                                2 => '/person:(?>[\x20\t]*).*?[\n]{2}/is' ];

    /**
     * Items for each block
     *
     * @var array
     */
    protected array $blockItems = [
        1 => [ '/^descr:(?>[\x20\t]*)(.+)\n/i'       => 'contacts:owner:name',
               '/admin-c:(?>[\x20\t]*)(.+)$/im'      => 'network:contacts:admin',
               '/tech-c:(?>[\x20\t]*)(.+)$/im'       => 'network:contacts:tech',
               '/status:(?>[\x20\t]*)(.+)$/im'       => 'status',
               '/nserver:(?>[\x20\t]*)(.+)$/im'      => 'nameserver',
               '/registration:(?>[\x20\t]*)(.+)$/im' => 'created',
               '/renewal:(?>[\x20\t]*)(.+)$/im'      => 'expires' ],

        2 => [ '/nic-hdl:(?>[\x20\t]*)(.+)$/im' => 'contacts:handle',
               '/person:(?>[\x20\t]*)(.+)$/im'  => 'contacts:name' ] ];

    /**
     * RegEx to check availability of the domain name
     */
    protected ?string $available = '/Not Registered/i';
}