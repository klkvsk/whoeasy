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
 * Template for .IR
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Ir extends Regex
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     */
    protected array $blocks = [ 1 => '/domain:(?>[\x20\t]*)(.*?)(?=source)/is',
                                2 => '/nic-hdl:(?>[\x20\t]*).*?[\n]{2}/is' ];

    /**
     * Items for each block
     *
     * @var array
     */
    protected array $blockItems = [
        1 => [ '/^nserver:(?>[\x20\t]*)(.+)$/im'      => 'nameserver',
               '/^last-updated:(?>[\x20\t]*)(.+)$/im' => 'changed',
               '/^expire-date:(?>[\x20\t]*)(.+)$/im'  => 'expires',
               '/^holder-c:(?>[\x20\t]*)(.+)$/im'     => 'network:contacts:owner',
               '/^admin-c:(?>[\x20\t]*)(.+)$/im'      => 'network:contacts:admin',
               '/^tech-c:(?>[\x20\t]*)(.+)$/im'       => 'network:contacts:tech' ],

        2 => [ '/^nic-hdl:(?>[\x20\t]*)(.+)$/im' => 'contacts:handle',
               '/^org:(?>[\x20\t]*)(.+)$/im'     => 'contacts:organization',
               '/^e-mail:(?>[\x20\t]*)(.+)$/im'  => 'contacts:email',
               '/^address:(?>[\x20\t]*)(.+)$/im' => 'contacts:address',
               '/^phone:(?>[\x20\t]*)(.+)$/im'   => 'contacts:phone',
               '/^fax-no:(?>[\x20\t]*)(.+)$/im'  => 'contacts:fax' ] ];

    /**
     * RegEx to check availability of the domain name
     */
    protected ?string $available = '/no entries found/i';
}