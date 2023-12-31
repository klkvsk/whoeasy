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
 * Template for .LV
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Lv extends Regex
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     */
    protected array $blocks = [ 1 => '/\[Domain\](.*?)(?=\[Holder\])/is',
                                2 => '/\[Holder\](.*?)(?=\[Tech\])/is',
                                3 => '/\[Tech\](.*?)(?=\[Registrar|Nservers\])/is',
                                4 => '/\[Registrar\](.*?)(?=\[Nservers\])/is', 5 => '/\[Nservers\].*?$/is' ];

    /**
     * Items for each block
     *
     * @var array
     */
    protected array $blockItems = [
        1 => [ '/^status:(?>[\x20\t]*)(.+)$/im'  => 'status',
               '/^changed:(?>[\x20\t]*)(.+)$/im' => 'changed' ],

        2 => [ '/^name:(?>[\x20\t]*)(.+)$/im'    => 'contacts:owner:name',
               '/^type:(?>[\x20\t]*)(.+)$/im'    => 'contacts:owner:type',
               '/^email:(?>[\x20\t]*)(.+)$/im'   => 'contacts:owner:email',
               '/^fax:(?>[\x20\t]*)(.+)$/im'     => 'contacts:owner:fax',
               '/^phone:(?>[\x20\t]*)(.+)$/im'   => 'contacts:owner:phone',
               '/^address:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address' ],

        3 => [ '/^name:(?>[\x20\t]*)(.+)$/im'    => 'contacts:tech:name',
               '/^type:(?>[\x20\t]*)(.+)$/im'    => 'contacts:tech:type',
               '/^email:(?>[\x20\t]*)(.+)$/im'   => 'contacts:tech:email',
               '/^fax:(?>[\x20\t]*)(.+)$/im'     => 'contacts:tech:fax',
               '/^phone:(?>[\x20\t]*)(.+)$/im'   => 'contacts:tech:phone',
               '/^address:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address' ],

        4 => [ '/^name:(?>[\x20\t]*)(.+)$/im'  => 'registrar:name',
               '/^email:(?>[\x20\t]*)(.+)$/im' => 'registrar:email' ],

        5 => [ '/^Nserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver' ] ];

    /**
     * RegEx to check availability of the domain name
     */
    protected ?string $available = '/Status: free/i';
}