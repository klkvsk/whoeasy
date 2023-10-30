<?php

new class {
    protected array $servers = [];
    protected array $toplevelRefs = [];
    protected array $ipv4Ranges = [];
    protected array $ipv6Ranges = [];
    protected array $asnRanges = [];

    protected array $novutecTemplates = [];

    public function __construct()
    {
        $files = [
            'new_gtlds_list'       => $this->parseNewGTld(...),
            'tld_serv_list'        => $this->parseTldServ(...),
            'servers_charset_list' => $this->parseServerCharset(...),
            'nic_handles_list'     => $this->parseNicHandle(...),
        ];

        foreach ($files as $file => $importFn) {
            $this->importWhoisListFile($file, $importFn);
        }

        $this->importNovutecIniFile('novutec.ini');

        $this->generateCode(__DIR__ . '/../src/Client/Registry/BuiltinRegistryRegistry.php');
        $this->generateCode(__DIR__ . '/../src/Parser/Process/NovutecTemplates.php');

    }

    protected function parseNewGTld(string $line): void
    {
        if (!preg_match('/^([a-z]{3,}|xn--[a-z0-9-]+)$/', $line)) {
            throw new UnexpectedValueException($line);
        }

        $tld = $line;
        $serverName = "whois.nic.$tld";

        $this->servers = self::merge(
            $this->servers,
            [
                $serverName => [
                    'uri'      => "whois://$serverName",
                    'tlds'     => [ ".$tld" ],
                ],
            ]
        );

        $this->toplevelRefs = self::merge(
            $this->toplevelRefs,
            [ ".$tld" => $serverName ],
        );
    }

    protected function parseTldServ(string $line): void
    {
        $cols = preg_split("/\s+/", $line, -1, PREG_SPLIT_NO_EMPTY);

        if ($cols && str_starts_with($cols[0], '.')) {
            $tld = array_shift($cols);
        }
        if ($cols && preg_match('/^[A-Z0-9]+$/', $cols[0])) {
            $type = array_shift($cols);
        }
        if ($cols && preg_match('/^([a-z][a-z0-9\-.]+|http.+)$/', $cols[0])) {
            $server = array_shift($cols);
        }

        if ($cols && $cols[0] === '#') {
            array_shift($cols);
            $comment = implode(' ', $cols);
            $cols = [];
        }

        if (!empty($cols) || !isset($tld)) {
            throw new UnexpectedValueException("'$line'");
        }

        $type ??= null;
        $server ??= null;

        if ($type === 'NONE') {
            $server = 'whois.iana.org';
        }
        if ($type === 'ARPA' || $type === 'IP6') {
            $server = 'whois.arin.org';
        }
        if ($type === 'WEB') {
            if (!str_starts_with($server, 'http')) {
                throw new UnexpectedValueException("wrong WEB type: '$line'");
            }
            $address = $server;
            $server = parse_url($address, PHP_URL_HOST);
        }

        if (!isset($server)) {
            throw new UnexpectedValueException("'$line'");
        }

        $address ??= "whois://$server";

        if ($server) {
            $this->servers = self::merge(
                $this->servers,
                [
                    $server => [
                        'uri'     => $address,
                        'comment' => $comment ?? null,
                        'tlds'    => [ $tld ],
                    ],
                ]
            );
        }

        $this->toplevelRefs = self::merge(
            $this->toplevelRefs,
            [ $tld => $server ],
        );
    }

    private function parseServerCharset($line): void
    {
        $cols = preg_split("/\s+/", $line, 3, PREG_SPLIT_NO_EMPTY);
        if ($cols < 2) {
            throw new UnexpectedValueException("'$line'");
        }

        $server = $cols[0];
        $charset = $cols[1];
        $options = $cols[2] ?? null;

        if (isset($this->servers[$server])) {
            $this->servers = self::merge(
                $this->servers,
                [
                    $server => [
                        'charset' => $charset,
                        'options' => $options ? [ $options ] : [],
                    ],
                ]
            );
        }
    }

    private function parseNicHandle($line): void
    {
        if (!preg_match('/^(-[a-z]+)\s+([a-z.\-0-9]+)/', $line, $cols)) {
            throw new UnexpectedValueException("'$line'");
        }

        [ $_, $handle, $server ] = $cols;

        $this->servers = self::merge(
            $this->servers,
            [
                $server => [
                    'uri'     => "whois://$server",
                    'handles' => [ $handle ],
                ],
            ]
        );
        $this->toplevelRefs = self::merge(
            $this->toplevelRefs,
            [
                $handle => $server,
            ]
        );
    }

    private static function merge(array $a, array $b, bool $allowOverwrite = true): array
    {
        foreach ($b as $key => $new) {
            $old = $a[$key] ?? null;

            if ($old === null || $old === '') {
                if ($new !== null && $new !== '' && $new !== []) {
                    if (is_array($new) && !array_is_list($new)) {
                        $a[$key] = self::merge([], $new, $allowOverwrite);
                    } else {
                        $a[$key] = $new;
                    }
                }
                continue;
            } else {
                if ($new === null || $new === '') {
                    if ($allowOverwrite) {
                        unset($a[$key]);
                    }
                    continue;
                }
            }

            if (is_array($old) && array_is_list($old)) {
                $oldType = 'list';
            } else {
                $oldType = gettype($old);
            }

            if (is_array($new) && array_is_list($new)) {
                $newType = 'list';
            } else {
                $newType = gettype($new);
            }

            if ($oldType !== $newType) {
                throw new UnexpectedValueException("Type mismatch in key $key: $oldType <> $newType");
            }

            if (is_array($new)) {
                if (array_is_list($new)) {
                    $newList = array_merge($old, $new);
                    $newList = array_unique($newList);
                    sort($newList);
                    $a[$key] = $newList;
                } else {
                    $a[$key] = self::merge($old, $new, $allowOverwrite);
                }
                continue;
            }

            if ($allowOverwrite) {
                $a[$key] = $new;
            } else {
                throw new Exception("Refusing to overwrite in $key: $old -> $new");
            }
        }

        return $a;
    }

    protected function dumpArray(array $array, string $indent, string $eol): string
    {
        $out = '[' . $eol;
        $nextIndent = $indent . '    ';
        $maxKeyLength = max(array_map(strlen(...), array_keys($array))) + 2;
        foreach ($array as $key => $value) {
            $out .= $nextIndent . sprintf("%-{$maxKeyLength}s", json_encode($key)) . ' => ';
            if (is_array($value)) {
                if (array_is_list($value)) {
                    $formattedValue = self::dumpList($value, $nextIndent, $eol);
                } else {
                    $formattedValue = self::dumpArray($value, $nextIndent, $eol);
                }
            } else if (is_string($value) && str_starts_with($value, '\\')) {
                $formattedValue = $value . '::class';
            } else if (is_string($value) && str_ends_with($value, '::class')) {
                $formattedValue = $value;
            } else {
                $formattedValue = json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            }

            $out .= $formattedValue . ',' . $eol;
        }

        $out .= $indent . ']';

        return $out;
    }

    protected function dumpList(array $list, string $indent, string $eol, bool $multiline = null, int $maxWidth = 80): string
    {
        $widthTest = '';
        if (is_null($multiline)) {
            $multiline = false;
            foreach ($list as $value) {
                if (is_array($value)) {
                    $multiline = true;
                    break;
                }
                if ($widthTest) {
                    $widthTest .= ', ';
                }
                $widthTest .= json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_UNICODE);
                if (strlen($widthTest) > $maxWidth) {
                    $multiline = true;
                    break;
                }
            }
        }

        if (!$multiline) {
            $elements = [];
            foreach ($list as $value) {
                $elements[] = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            }
            return '[ ' . implode(', ', $elements) . ' ]';
        }

        $nextIndent = $indent . '    ';
        $out = '[' . $eol;
        $line = '';
        foreach ($list as $value) {
            if (is_array($value)) {
                $out .= $nextIndent;
                if ($line) {
                    $out .= $line . ',' . $eol . $nextIndent;
                    $line = '';
                }
                if (array_is_list($value)) {
                    $out .= self::dumpList($value, $nextIndent, $eol);
                } else {
                    $out .= self::dumpArray($value, $nextIndent, $eol);
                }
                $out .= ', ' . $eol;
            } else {
                $element = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
                if (strlen($line . ', ' . $element) > $maxWidth) {
                    $out .= $nextIndent . $line . ',' . $eol;
                    $line = $element;
                } else {
                    if ($line) {
                        $line .= ', ';
                    }
                    $line .= $element;
                }
            }
        }

        if ($line) {
            $out .= $nextIndent . $line . $eol;
        }

        $out .= $indent . ']';

        return $out;
    }

    protected function importWhoisListFile(string $file, callable $importFn): void
    {
        $data = file_get_contents($file);
        if (!$data) {
            throw new Exception('empty or failed to read: ' . $file);
        }
        $lines = explode("\n", $data);
        foreach ($lines as $line) {
            $line = trim($line);
            if (str_starts_with($line, '#')) {
                continue;
            }
            if (empty($line)) {
                continue;
            }
            $importFn($line);
        }
    }

    protected function importNovutecIniFile(string $file): void
    {
        $config = parse_ini_file($file);
        $mapping = [];
        foreach ($config as $key => $params) {
            $template = $params['template'] ?? null;
            if (!$template) {
                continue;
            }
            if (isset($params['server'])) {
                $server = $params['server'];
                $toplevel = $key;
            } else {
                $server = $key;
                $toplevel = '*';
            }

            if ($template === 'int') {
                $template = 'int_';
            }

            $templateClass = 'NovutecTemplates\\Templates\\' . ucfirst($template) . '::class';

            $mapping[$server] ??= [];
            $mapping[$server][$toplevel] = $templateClass;
        }

        foreach ($mapping as $server => &$templates) {
            $firstTemplate = reset($templates);
            if (count(array_unique($templates)) == 1) {
                // if only a single template specified - use for all
                $mapping[$server] = [ '*' => $firstTemplate ];
                continue;
            }
            // sort from longest to shortest for iterative matching
            uasort($templates, fn ($a, $b) => strlen($b) <=> strlen($a));

            // add fallback to first occurred template
            if (!isset($templates['*'])) {
                $templates['*'] = $firstTemplate;
            }
        }

        $this->novutecTemplates = $mapping;
    }

    protected function generateCode(string $file): void
    {
        $file = realpath($file);
        $registryFile = file($file);
        $modifiedFile = [];
        $skipUntil = null;
        foreach ($registryFile as $line) {
            if ($skipUntil && !str_contains($line, $skipUntil)) {
                continue;
            }
            $skipUntil = null;
            $modifiedFile[] = $line;
            if (preg_match("/^(\s+).*@generator-begin=([a-z0-9]+).+(\s+)$/", $line, $m)) {
                $indent = $m[1];
                $blockName = $m[2];
                $eol = $m[3];
                $skipUntil = "@generator-end=$blockName";
                switch ($blockName) {
                    case 'servers':
                        foreach ($this->servers as $serverName => $server) {
                            $modifiedFile[] = $indent . '"' . $serverName . '" => '
                                . self::dumpArray($server, $indent, $eol) . ',' . $eol;
                        }
                        break;

                    case 'toplevel':
                        foreach ($this->toplevelRefs as $ref => $serverName) {
                            $maxKeyLength = max(array_map(strlen(...), array_keys($this->toplevelRefs))) + 2;
                            $modifiedFile[] = $indent . sprintf("%-{$maxKeyLength}s", json_encode($ref))
                                . ' => ' . json_encode($serverName) . ',' . $eol;
                        }
                        break;

                    case 'ipv4':
                    case 'ipv6':
                    case 'asn':
                        break;

                    case 'novutec':
                        foreach ($this->novutecTemplates as $server => $templates) {
                            $modifiedFile[] = $indent . json_encode($server)
                                . ' => ' . self::dumpArray($templates, $indent, $eol) . ',' . $eol;
                        }
                        break;

                    default:
                        trigger_error("Unknown block name '$blockName'", E_USER_WARNING);
                }
            }
        }

        file_put_contents($file, implode('', $modifiedFile));
        echo "Updated file $file\n";
    }

};