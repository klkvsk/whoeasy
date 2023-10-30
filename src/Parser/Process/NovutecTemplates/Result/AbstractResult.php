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
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * @namespace Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Result
 */

namespace Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Result;

use JsonSerializable;

/**
 * WhoisParser AbstractResult
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
abstract class AbstractResult implements JsonSerializable
{

    /**
     * Writing data to properties
     */
    public function __set(string $name, $value): void
    {
        $this->{$name} = $value;
    }

    /**
     * Checking data
     */
    public function __isset(string $name): bool
    {
        return isset($this->{$name});
    }

    /**
     * Reading data from properties
     */
    public function __get(string $name)
    {
        if (isset($this->{$name})) {
            return $this->{$name};
        }

        return null;
    }

    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * Convert properties to json
     *
     * @return string
     */
    public function toJson(): string
    {
        return json_encode($this->toArray());
    }

    /**
     * Convert properties to array
     */
    public function toArray(): array
    {
        return get_object_vars($this);
    }
}