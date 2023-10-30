<?php

namespace Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Templates\Type;

use Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Exception\RateLimitException;
use Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Exception\ReadErrorException;
use Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Result\Result;

/**
 * Parser based on simple responses containing only 'key: value' entries.
 * An alternative to the default regex-blocks based parser that allows us to not care about missing entries
 * or the order of entries
 *
 * @package Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Templates\Type
 */
abstract class KeyValue extends AbstractTemplate
{

    protected array $data = [];

    protected array $regexKeys = [];


    /**
     * @param Result $result
     * @param string $rawData
     * @throws ReadErrorException if data was read from the whois response
     * @throws RateLimitException
     */
    public function parse(Result $result, string $rawData): void
    {
        $this->parseRateLimit($rawData);

        // check availability upon type - IP addresses are always registered
        $parsedAvailable = false;
        if (isset($this->available) && strlen($this->available)) {
            preg_match_all($this->available, $rawData, $matches);
            $parsedAvailable = count($matches);

            $result->addItem('registered', empty($matches[0]));
        }

        $this->data = $this->parseRawData($rawData);
        $this->reformatData();
        $matches = $this->parseKeyValues($result, $this->data, $this->regexKeys);

        if (($matches < 1) && (!$parsedAvailable)) {
            throw new ReadErrorException("Template did not correctly parse the response");
        }
    }


    protected function parseRawData($rawData): array
    {
        $data = [];
        $rawData = explode("\n", $rawData);
        foreach ($rawData as $line) {
            $line = trim($line);
            $lineParts = explode(':', $line, 2);
            if (count($lineParts) < 2) {
                continue;
            }

            $key = trim($lineParts[0]);
            $value = trim($lineParts[1]);

            if (array_key_exists($key, $data)) {
                if (!is_array($data[$key])) {
                    $data[$key] = [ $data[$key] ];
                }
                $data[$key][] = $value;
                continue;
            }

            $data[$key] = $value;
        }

        return $data;
    }


    protected function parseKeyValues($result, $dataArray, $regexKeys, $append = false): int
    {
        $matches = 0;
        foreach ($dataArray as $key => $value) {
            foreach ($regexKeys as $dataKey => $regexList) {
                if (!is_array($regexList)) {
                    $regexList = [ $regexList ];
                }

                foreach ($regexList as $regex) {
                    if (preg_match($regex, $key)) {
                        $matches++;
                        $result->addItem($dataKey, $value, $append);
                        break 2;
                    }
                }
            }
        }

        return $matches;
    }


    /**
     * Perform any necessary reformatting of data (for example, reformatting dates)
     */
    protected function reformatData(): void
    {
    }
}
