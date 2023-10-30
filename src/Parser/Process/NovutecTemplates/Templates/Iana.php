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
 * Template for IANA
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Iana extends Regex
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     * @access protected
     */
    protected array $blocks = [
        1  => '/refer:(?>[\x20\t]*)(.*?)[\n]{2}/is',
        2  => '/domain:(?>[\x20\t]*)(.*?)[\n]{2}/is',
        3  => '/organisation:(?>[\x20\t]*)(.*?)(?=contact:(?>[\x20\t]*)administrative)/is',
        4  => '/contact:(?>[\x20\t]*)administrative(.*?)(?=contact:(?>[\x20\t]*)technical)/is',
        5  => '/contact:(?>[\x20\t]*)technical(.*?)(?=nserver)/is',
        6  => '/nserver:(?>[\x20\t]*)(.*?)(?=whois)/is',
        7  => '/whois:(?>[\x20\t]*)(.*?)[\n]{2}/is',
        8  => '/status:(?>[\x20\t]*)(.*?)(?=created)/is',
        9  => '/created:(?>[\x20\t]*)(.*?)$/is',
        10 => '/Domain Name.*/is',
    ];

    /**
     * Items for each block
     *
     * @var array
     * @access protected
     */
    protected array $blockItems = [
        1  => [
            '/^refer:(?>[\x20\t]*)(.+)$/im' => 'whoisserver',
        ],
        2  => [
            '/^domain:(?>[\x20\t]*)(.+)$/im' => 'name',
        ],
        3  => [
            '/organisation:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization',
            '/address:(?>[\x20\t]*)(.+)$/im'      => 'contacts:owner:address' ]
        ,
        4  => [
            '/organisation:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:organization',
            '/address:(?>[\x20\t]*)(.+)$/im'      => 'contacts:admin:address',
            '/phone:(?>[\x20\t]*)(.+)$/im'        => 'contacts:admin:phone',
            '/fax-no:(?>[\x20\t]*)(.+)$/im'       => 'contacts:admin:fax',
            '/e-mail:(?>[\x20\t]*)(.+)$/im'       => 'contacts:admin:email',
        ],
        5  => [
            '/organisation:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization',
            '/address:(?>[\x20\t]*)(.+)$/im'      => 'contacts:tech:address',
            '/phone:(?>[\x20\t]*)(.+)$/im'        => 'contacts:tech:phone',
            '/fax-no:(?>[\x20\t]*)(.+)$/im'       => 'contacts:tech:fax',
            '/e-mail:(?>[\x20\t]*)(.+)$/im'       => 'contacts:tech:email',
        ],
        6  => [
            '/nserver:(?>[\x20\t]*)(.+) .+ .+$/im' => 'nameserver',
            '/nserver:(?>[\x20\t]*).+ (.+) .+$/im' => 'ips',
            '/ds-rdata:(?>[\x20\t]*)(.+)$/im'      => 'dnssec',
        ],
        7  => [
            '/^whois:(?>[\x20\t]*)(.+)$/im' => 'whoisserver',
        ],
        8  => [
            '/^status:(?>[\x20\t]*)(.+)$/im' => 'status',
        ],
        9  => [
            '/created:(?>[\x20\t]*)(.+)$/im' => 'created',
            '/changed:(?>[\x20\t]*)(.+)$/im' => 'changed',
        ],
        10 => [
            '/Registrar WHOIS Server(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'whoisserver',
        ],
    ];

    /**
     * After parsing do something
     *
     * If result contains domain then we have to ask a domain name registry for
     * the full and correct whois output about the domain name.
     *
     * If result contains only whois server and not domain then we have to ask
     * a RIR for the full and correct whois output about the IP address.
     *
     * If result is just a top-level domain name we are stopping the processing
     *
     * @param object $WhoisParser
     * @return void
     */
    public function postProcess(object $WhoisParser): void
    {
        $Result = $WhoisParser->getResult();

        if ($Result->dnssec != '') {
            $Result->dnssec = true;
        } else {
            $Result->dnssec = false;
        }

    }
}