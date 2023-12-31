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
 * Template for .PT
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Pt extends Regex
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     */
    protected array $blocks = [ 1 => '/nome de dom(?>[\x20\t]*)(.*?)(?=titular)/is',
                                2 => '/registrant(?>[\x20\t]*)(.*?)(?=entidade gestora)/is',
                                3 => '/billing contact(?>[\x20\t]*)(.*?)(?=respons)/is',
                                4 => '/tech contact(?>[\x20\t]*)(.*?)(?=nameserver information)/is',
                                5 => '/nameserver information(?>[\x20\t]*)(.*?)$/is' ];

    /**
     * Items for each block
     *
     * @var array
     */
    protected array $blockItems = [
        1 => [ '/status:(?>[\x20\t]*)(.*?)$/im'                           => 'status',
               '/creation date \(dd\/mm\/yyyy\):(?>[\x20\t]*)(.*?)$/im'   => 'created',
               '/expiration date \(dd\/mm\/yyyy\):(?>[\x20\t]*)(.*?)$/im' => 'expires' ],
        2 => [ '/registrant(?>[\x20\t\n]*)(.*?)(?=email:)/is' => 'contacts:owner:address',
               '/email:(?>[\x20\t]*)(.*?)$/im'                => 'contacts:owner:email' ],
        3 => [ '/billing contact\n(?>[\x20\t]*)(.*?)$/im' => 'contacts:billing:name',
               '/email:(?>[\x20\t]*)(.*?)$/im'            => 'contacts:billing:email' ],
        4 => [ '/tech contact\n(?>[\x20\t]*)(.*?)$/im' => 'contacts:tech:name',
               '/email:(?>[\x20\t]*)(.*?)$/im'         => 'contacts:tech:email' ],
        5 => [ '/nameserver: .+(?>[\x20\t]+)ns(?>[\x20\t]+)(.+).$/im' => 'nameserver',
               '/nameserver: .+(?>[\x20\t]+)ds(?>[\x20\t]+)(.+)$/im'  => 'dnssec' ] ];

    /**
     * RegEx to check availability of the domain name
     */
    protected ?string $available = '/no match/i';

    /**
     * After parsing do something
     *
     * Fix contact addresses and set dnssec
     *
     * @param object $WhoisParser
     * @return void
     */
    public function postProcess(object $WhoisParser): void
    {
        $ResultSet = $WhoisParser->getResult();

        if ($ResultSet->dnssec != '') {
            $ResultSet->dnssec = true;
        } else {
            $ResultSet->dnssec = false;
        }

        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $contactObject->address = array_map('utf8_encode', explode("\n", trim($contactObject->address)));
                $contactObject->address = array_map('trim', $contactObject->address);

                if (sizeof($contactObject->address) > 1) {
                    $contactObject->organization = $contactObject->address[0];
                    $contactObject->city = $contactObject->address[2];
                    $contactObject->zipcode = $contactObject->address[3];
                    $contactObject->address = $contactObject->address[1];
                } else {
                    $contactObject->address = null;
                    $contactObject->organization = $contactObject->address[0];
                }

                $contactObject->name = utf8_encode($contactObject->name);

                if (strpos($contactObject->email, ';')) {
                    $contactObject->email = explode(';', $contactObject->email);
                }
            }
        }
    }
}