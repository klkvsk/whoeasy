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
 * Template for RIPE
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Ripe extends Regex
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     */
    protected array $blocks = [ 1 => '/(inetnum|inet6num|as-block):[\s]*(.*?)[\n]{2}/is',
                                2 => '/(role|person|organisation):[\s]*(.*?)[\n]{2}/is' ];

    /**
     * Items for each block
     *
     * @var array
     */
    protected array $blockItems = [
        1 => [ '/^as-block:(?>[\x20\t]*)(.+)$/im'      => 'network:as-block',
               '/^inetnum:(?>[\x20\t]*)(.+)$/im'       => 'network:inetnum',
               '/^inet6num:(?>[\x20\t]*)(.+)$/im'      => 'network:inetnum',
               '/^netname:(?>[\x20\t]*)(.+)$/im'       => 'network:name',
               '/^created:(?>[\x20\t]*)(.+)$/im'       => 'created',
               '/^last-modified:(?>[\x20\t]*)(.+)$/im' => 'changed',
               '/^mnt-by:(?>[\x20\t]*)(.+)$/im'        => 'network:maintainer',
               '/^status:(?>[\x20\t]*)(.+)$/im'        => 'status',
               '/^descr:(?>[\x20\t]*)(.+)$/im'         => 'network:description',
               '/^remarks:(?>[\x20\t]*)(.+)$/im'       => 'network:description',
               '/^org:(?>[\x20\t]*)(.+)$/im'           => 'network:contacts:owner',
               '/^admin-c:(?>[\x20\t]*)(.+)$/im'       => 'network:contacts:admin',
               '/^tech-c:(?>[\x20\t]*)(.+)$/im'        => 'network:contacts:tech' ],

        2 => [ '/^organisation:(?>[\x20\t]*)(.+)$/im'  => 'contacts:handle',
               '/^org:(?>[\x20\t]*)(.+)$/im'           => 'contacts:handle',
               '/^nic-hdl:(?>[\x20\t]*)(.+)$/im'       => 'contacts:handle',
               '/^org-name:(?>[\x20\t]*)(.+)$/im'      => 'contacts:name',
               '/^role:(?>[\x20\t]*)(.+)$/im'          => 'contacts:name',
               '/^person:(?>[\x20\t]*)(.+)$/im'        => 'contacts:name',
               '/^address:(?>[\x20\t]*)(.+)/im'        => 'contacts:address',
               '/^abuse-mailbox:(?>[\x20\t]*)(.+)$/im' => 'contacts:email',
               '/^phone:(?>[\x20\t]*)(.+)$/im'         => 'contacts:phone',
               '/^fax-no:(?>[\x20\t]*)(.+)$/im'        => 'contacts:fax' ] ];
}