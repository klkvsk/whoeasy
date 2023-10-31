<?php
set_error_handler(fn ($s, $m, $f = null, $l = null) => new ErrorException($m, 0, $s, $f, $l), E_ALL);

/** @throws ErrorException */
function exception_error_handler($severity, $message, $file = null, $line = null)
{
    throw new ErrorException($message, 0, $severity, $file, $line);
}

set_error_handler("exception_error_handler", E_ALL);


new class {
    public function __construct()
    {
        $files = [
            'https://raw.githubusercontent.com/rfc1036/whois/master/new_gtlds_list',
            'https://raw.githubusercontent.com/rfc1036/whois/master/tld_serv_list',
            'https://raw.githubusercontent.com/rfc1036/whois/master/servers_charset_list',
            'https://raw.githubusercontent.com/rfc1036/whois/master/nic_handles_list',
            'https://raw.githubusercontent.com/rfc1036/whois/master/ip_del_list',
            'https://raw.githubusercontent.com/rfc1036/whois/master/ip_del_recovered.h',
            'https://raw.githubusercontent.com/rfc1036/whois/master/ip6_del_list',
            'https://raw.githubusercontent.com/rfc1036/whois/master/as_del_list',
            'https://raw.githubusercontent.com/rfc1036/whois/master/as32_del_list',
        ];

        foreach ($files as $file) {
            echo "Updating $file...\n";
            $this->fetch($file);
        }
        echo "Done\n";
    }

    protected function fetch(string $file, string $saveTo = null): void
    {
        $saveTo ??= basename($file);
        $content = file_get_contents($file);
        if (file_exists($saveTo)) {
            $oldContent = file_get_contents($saveTo);
            if ($oldContent === $content) {
                echo " -> not changed\n";
                return;
            } else {
                echo " -> got new version, run build.php\n";
            }
        } else {
            echo " -> created new\n";
        }
        file_put_contents($saveTo, $content);
    }
};