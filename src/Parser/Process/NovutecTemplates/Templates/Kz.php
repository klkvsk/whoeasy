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
 * Template for .KZ
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Kz extends Regex
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     */
    protected array $blocks = [
        1 => '/Organization Using Domain Name(.*?)(?=Administrative Contact\/Agent)/is',
        2 => '/Administrative Contact\/Agent(.*?)(?=Nameserver in listed order)/is',
        3 => '/Nameserver in listed order(.*?)(?=Domain created)/is',
        4 => '/Domain created(.*?)$/is' ];

    /**
     * Items for each block
     *
     * @var array
     */
    protected array $blockItems = [
        1 => [
            '/^Name(?>[\.]*)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im'              => 'contacts:owner:name',
            '/^Organization Name(?>[\.]*)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization',
            '/^Street Address(?>[\.]*)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im'    => 'contacts:owner:address',
            '/^City(?>[\.]*)(?>[\x20\t]*):(?>[\x20\t]*)(.*)$/im'              => 'contacts:owner:city',
            '/^State(?>[\.]*)(?>[\x20\t]*):(?>[\x20\t]*)(.*)$/im'             => 'contacts:owner:state',
            '/^Postal Code(?>[\.]*)(?>[\x20\t]*):(?>[\x20\t]*)(.*)$/im'       => 'contacts:owner:zipcode' ],
        2 => [
            '/^NIC Handle(?>[\.]*)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im'    => 'contacts:admin:handle',
            '/^Name(?>[\.]*)(?>[\x20\t]*):(?>[\x20\t]*)(.*)$/im'          => 'contacts:admin:name',
            '/^Phone Number(?>[\.]*)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im'  => 'contacts:admin:phone',
            '/^Fax Number(?>[\.]*)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im'    => 'contacts:admin:fax',
            '/^Email Address(?>[\.]*)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email' ],
        3 => [
            '/^(Primary|Secondary) server(?>[\.]*)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im'     => 'nameserver',
            '/^(Primary|Secondary) ip address(?>[\.]*)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'ips' ],
        4 => [ '/^Last modified(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im'  => 'changed',
               '/^Domain created(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'created',
               '/^Domain status(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im'  => 'status' ] ];

    /**
     * RegEx to check availability of the domain name
     */
    protected ?string $available = '/Nothing found for this query/i';
}