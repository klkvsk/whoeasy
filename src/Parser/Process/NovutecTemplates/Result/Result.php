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
    public $name;

    /**
     * @var string
     */
    public $description;

    /**
     * Status of domain or IP address
     *
     * @var array
     */
    public $status;

    /**
     * Array of Nameservers
     *
     * @var array
     */
    public $nameserver;

    /**
     * Array of Nameservers IPs
     *
     * @var array
     */
    public $ips;

    /**
     * Created date of domain or IP address
     *
     * @var string
     */
    public $created;

    /**
     * Last changed date of domain or IP address
     *
     * @var string
     */
    public $changed;

    /**
     * Expire date of domain or IP address
     *
     * @var string
     */
    public $expires;

    /**
     * Is domain name or IP address registered
     *
     * @var boolean
     */
    public $registered;

    /**
     * Has domain name DNSSEC
     *
     * @var boolean
     */
    public $dnssec;

    /**
     * Queried whois server
     *
     * @var string
     */
    public $whoisserver;

    /**
     * Contact handles of domain name or IP address
     *
     * @var object
     */
    public $contacts;

    /**
     * Registrar of domain name or IP address
     *
     * @var object
     */
    public $registrar;


    /**
     * Network information of domain name or IP address
     *
     * @var object
     */
    public $network;

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
                                    if (self::isSameValue($multiContactValue, $value)) {
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
                                if (self::isSameValue($networkContactValue, $value)) {
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
        $output = [
            'name' => $this->name,
            'status' => $this->status,
            'created' => $this->created,
            'changed' => $this->changed,
            'expires' => $this->expires,
            'registered' => $this->registered,
            'registrar' => [],
            'contacts' => [],
            'network' => [],
            'whoisserver' => $this->whoisserver,
            'nameserver' => $this->nameserver,
            'ips' => $this->ips,
            'dnssec' => $this->dnssec,
        ];

        // lookup all contact handles and convert to array
        foreach ($this->contacts as $type => $handle) {
            foreach ($handle as $object) {
                $output['contacts'][$type][] = $object->toArray();
            }
        }

        if (!empty($this->registrar)) {
            $output['registrar'] = $this->registrar->toArray();
        }

        if (!empty($this->network)) {
            $network = [];
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

        $dynamicFields = array_diff_key(
            get_object_vars($this),
            get_class_vars(static::class)
        );

        foreach ($dynamicFields as $field => $value) {
            if (is_object($value)) {
                $value = $value->toArray();
            }
            $output[$field] = $value;
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

    public function formatDates(string $dateformat): void
    {
        $this->changed = $this->formatDate($dateformat, $this->changed);
        $this->created = $this->formatDate($dateformat, $this->created);
        $this->expires = $this->formatDate($dateformat, $this->expires);

        foreach ($this->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $contactObject->created = $this->formatDate($dateformat, $contactObject->created);
                $contactObject->changed = $this->formatDate($dateformat, $contactObject->changed);
            }
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

    private static function isSameValue(mixed $a, mixed $b): bool
    {
        if (is_array($a)) {
            sort($a);
            $a = implode(',', $a);
        }
        if (is_array($b)) {
            sort($b);
            $b = implode(',', $b);
        }
        if (is_string($a)) {
            $a = strtolower($a);
        }
        if (is_string($b)) {
            $a = strtolower($b);
        }

        return $a == $b;
    }
}
