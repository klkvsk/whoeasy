<?php
/** @noinspection PhpMissingFieldTypeInspection */

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
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * @namespace Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Result
 */

namespace Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Result;

use stdClass;

/**
 * WhoisParser Result
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Result extends AbstractResult
{

    /**
     * Name of domain or IP address
     *
     * @var string
     */
    protected $name;

    /**
     * IDN converted name of domain or IP address
     *
     * @var string
     */
    protected $idnName;

    /**
     * Status of domain or IP address
     *
     * @var array
     */
    protected $status;

    /**
     * Array of Nameservers
     *
     * @var array
     */
    protected $nameserver;

    /**
     * Array of Nameservers IPs
     *
     * @var array
     */
    protected $ips;

    /**
     * Created date of domain or IP address
     *
     * @var string
     */
    protected $created;

    /**
     * Last changed date of domain or IP address
     *
     * @var string
     */
    protected $changed;

    /**
     * Expire date of domain or IP address
     *
     * @var string
     */
    protected $expires;

    /**
     * Is domain name or IP address registered
     *
     * @var boolean
     */
    protected $registered;

    /**
     * Has domain name DNSSEC
     *
     * @var boolean
     */
    protected $dnssec;

    /**
     * Queried whois server
     *
     * @var string
     */
    protected $whoisserver;

    /**
     * Contact handles of domain name or IP address
     *
     * @var object
     */
    protected $contacts;

    /**
     * Registrar of domain name or IP address
     *
     * @var object
     */
    protected $registrar;

    /**
     * Raw response from whois server
     *
     * @var array
     */
    public $rawdata = [];

    /**
     * Network information of domain name or IP address
     *
     * @var object
     */
    protected $network;

    /**
     * Exception
     *
     * @var string
     */
    protected $exception;

    /**
     * Have contacts been parsed?
     *
     * @var boolean
     */
    protected $parsedContacts;

    /**
     * Name of the actual template
     */
    public ?string $template = null;

    private ?string $lastHandle = null;
    private int $lastId = -1;

    public function __construct()
    {
        $this->contacts = new stdClass();
    }

    /**
     * @param string $target
     * @param mixed $value
     * @param bool $append Append values rather than overwriting? (Ignored for registrars and contacts)
     * @return void
     */
    public function addItem(string $target, mixed $value, bool $append = false): void
    {
        if (is_array($value) && count($value) === 1) {
            $value = $value[0];
        }
        // Don't overwrite existing values with empty values, unless we explicitly pass through NULL
        if (is_array($value) && count($value) === 0) {
            return;
        }
        if ($value === '') {
            return;
        }

        // reservedType is sometimes need by templates like .DE
        if ($target === 'contacts:reservedType') {
            if ($this->lastHandle !== strtolower($value)) {
                $this->lastId = -1;
            }

            $this->lastHandle = strtolower($value);
            $this->lastId++;
            return;
        }

        if ($target == 'rawdata') {
            $this->{$target}[] = $value;
            return;
        }

        if (strpos($target, ':')) {
            // split target by :
            $targetArray = explode(':', $target);
            $element = &$this;

            // lookup target to determine where we should add the item
            foreach ($targetArray as $key => $type) {
                if ($targetArray[0] === 'contacts' && $key === 1 && sizeof($targetArray) === 2) {
                    // estimate handle match by network contacts
                    if (isset($this->network->contacts) && $targetArray[1] === 'handle') {
                        // look through all network contacts
                        foreach ($this->network->contacts as $networkContactKey => $networkContactValue) {
                            // if it is an array, then there are more contacts
                            // of the same type
                            if (is_array($networkContactValue)) {
                                // look through the array of one type
                                foreach ($networkContactValue as $multiContactKey => $multiContactValue) {
                                    if (strtolower($multiContactValue) === strtolower($value)) {
                                        if ($this->lastHandle !== $networkContactKey) {
                                            $this->lastId = -1;
                                        }

                                        $this->lastHandle = $networkContactKey;
                                        $this->lastId++;
                                        unset($this->network->contacts->{$networkContactKey}[$multiContactKey]);
                                        break 2;
                                    }
                                }
                            } else {
                                if (strtolower($networkContactValue) === strtolower($value)) {
                                    if ($this->lastHandle !== $networkContactKey) {
                                        $this->lastId = -1;
                                    }
                                    $this->lastHandle = $networkContactKey;
                                    $this->lastId++;
                                    unset($this->network->contacts->$networkContactKey);
                                    break;
                                }
                            }
                        }
                    }

                    if (!isset($this->contacts->{$this->lastHandle}[$this->lastId])) {
                        if (null === $this->lastHandle) {
                            continue;
                        }
                        $this->contacts->{$this->lastHandle}[$this->lastId] = new Contact();
                    }

                    $this->contacts->{$this->lastHandle}[$this->lastId]->$type = $value;
                } else {
                    // if last element of target is reached we need to add value
                    if ($key === sizeof($targetArray) - 1) {
                        if (is_array($element)) {
                            $element[sizeof($element) - 1]->$type = $value;
                        } else {
                            $element->$type = $value;
                        }
                        break;
                    }

                    if (!isset($element->$type)) {
                        switch ($targetArray[0]) {
                            case 'contacts':
                                $element->$type ??= [];
                                $element->$type[] = new Contact();
                                break;
                            case 'registrar':
                                $element->$type = new Registrar();
                                break;
                            default:
                                $element->$type = new stdClass();
                        }
                    }

                    $element = &$element->$type;
                }
            }
        } else {
            if ($append && isset($this->{$target})) {
                if (!is_array($this->{$target})) {
                    $this->{$target} = [ $this->{$target} ];
                }
                $this->{$target}[] = $value;
            } else {
                $this->{$target} = $value;
            }
        }
    }

    public function toArray(): array
    {
        $output = get_object_vars($this);
        $contacts = [];
        $network = [];

        // lookup all contact handles and convert to array
        foreach ($this->contacts as $type => $handle) {
            foreach ($handle as $number => $object) {
                $contacts[$type][$number] = $object->toArray();
            }
        }
        $output['contacts'] = $contacts;

        if (!empty($this->registrar)) {
            $output['registrar'] = $this->registrar->toArray();
        }

        if (!empty($this->network)) {
            // lookup network for all properties
            foreach ($this->network as $type => $value) {
                // if there is an object we need to convert it to array
                if (is_object($value)) {
                    $value = (array)$value;
                    // if converted array is empty there is no need to add it
                    if (!empty($value)) {
                        $network[$type] = $value;
                    }
                } else {
                    $network[$type] = $value;
                }
            }
            $output['network'] = $network;
        }

        return $output;
    }

    /**
     * Serialize properties
     */
    public function serialize(): string
    {
        return serialize($this->toArray());
    }

    /**
     * Convert properties to xml by using SimpleXMLElement
     *
     * @noinspection PhpComposerExtensionStubsInspection
     * @noinspection PhpFullyQualifiedNameUsageInspection
     */
    public function toXml(): string
    {
        $xml = new \SimpleXMLElement(
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><whois></whois>');

        $output = get_object_vars($this);

        // lookup all object variables
        foreach ($output as $name => $var) {
            // if variable is an array add it to xml
            if (is_array($var)) {
                $child = $xml->addChild($name);

                foreach ($var as $firstKey => $firstValue) {
                    $child->addChild('item', trim(htmlspecialchars($firstValue)));
                }
            } elseif (is_object($var)) {
                // if variable is an object we need to convert it to array
                $child = $xml->addChild($name);

                // if it is not a stdClass object we have the toArray() method
                if (!$var instanceof stdClass) {
                    $firstArray = $var->toArray();

                    foreach ($firstArray as $firstKey => $firstValue) {
                        if (!is_array($firstValue)) {
                            $child->addChild($firstKey, trim(htmlspecialchars($firstValue)));
                        } else {
                            $secondChild = $child->addChild($firstKey);

                            foreach ($firstValue as $secondKey => $secondString) {
                                $secondChild->addChild('item', trim(htmlspecialchars($secondString)));
                            }
                        }
                    }
                } else {
                    // if it is an stdClass object we need to convert it
                    // manually

                    // lookup all properties of stdClass and convert it
                    foreach ($var as $firstKey => $firstValue) {
                        if (!$firstValue instanceof stdClass && !is_array($firstValue) &&
                            !is_string($firstValue)) {
                            $secondChild = $child->addChild($firstKey);

                            $firstArray = $firstValue->toArray();

                            foreach ($firstArray as $secondKey => $secondValue) {
                                $secondChild->addChild($secondKey, trim(htmlspecialchars($secondValue)));
                            }
                        } elseif (is_array($firstValue)) {
                            $secondChild = $child->addChild($firstKey);

                            foreach ($firstValue as $secondKey => $secondValue) {
                                $secondArray = $secondValue->toArray();
                                $thirdChild = $secondChild->addChild('item');

                                foreach ($secondArray as $thirdKey => $thirdValue) {
                                    if (!is_array($thirdValue)) {
                                        $thirdChild->addChild($thirdKey, trim(htmlspecialchars($thirdValue)));
                                    } else {
                                        $fourthChild = $thirdChild->addChild($thirdKey);

                                        foreach ($thirdValue as $fourthKey => $fourthValue) {
                                            $fourthChild->addChild('item', trim(htmlspecialchars($fourthValue)));
                                        }
                                    }
                                }
                            }
                        } elseif (is_string($firstValue)) {
                            $secondChild = $child->addChild($firstKey, $firstValue);
                        }
                    }
                }
            } else {
                $xml->addChild($name, trim($var));
            }
        }

        return $xml->asXML();
    }

    /**
     * cleanUp method will be called before output
     */
    public function cleanUp($config, $dateformat): void
    {
        // add WHOIS server to output
        $this->addItem('whoisserver', ($config['adapter'] === 'http') ? $config['server'] .
            str_replace('%domain%', $this->name, $config['format']) : $config['server']);

        // remove helper vars from result
        if (isset($this->lastId)) {
            unset($this->lastId);
        }

        if (isset($this->lastHandle)) {
            unset($this->lastHandle);
        }

        if (isset($this->network->contacts) && !empty($this->network->contacts)) {
            $this->network = null;
        }

        // format dates
        $this->template = $config['template'];
        $this->changed = $this->formatDate($dateformat, $this->changed);
        $this->created = $this->formatDate($dateformat, $this->created);
        $this->expires = $this->formatDate($dateformat, $this->expires);

        foreach ($this->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $contactObject->created = $this->formatDate($dateformat, $contactObject->created);
                $contactObject->changed = $this->formatDate($dateformat, $contactObject->changed);
            }
        }

        // check if contacts have been parsed
        if (sizeof(get_object_vars($this->contacts)) > 0) {
            $this->addItem('parsedContacts', true);
        } else {
            $this->addItem('parsedContacts', false);
        }
    }

    /**
     * Format given dates by date format
     */
    private function formatDate(string $dateformat, $date): ?string
    {
        if (!is_string($date)) {
            return null;
        }
        $timestamp = strtotime(str_replace('/', '-', $date));

        if ($timestamp == '') {
            $timestamp = strtotime(str_replace('/', '.', $date));
        }

        return (strlen($timestamp) ? date($dateformat, $timestamp) : $date);
    }
}
