<?php

namespace Klkvsk\Whoeasy\Client\Adapter;

use Klkvsk\Whoeasy\Client\Exception\ClientException;
use Klkvsk\Whoeasy\Client\Exception\ClientRequestException;
use Klkvsk\Whoeasy\Client\Exception\ClientTimeoutException;
use Klkvsk\Whoeasy\Client\RequestInterface;
use Klkvsk\Whoeasy\Client\Response;
use Klkvsk\Whoeasy\Client\ResponseInterface;

class NativeBin implements AdapterInterface
{
    public function __construct(
        protected string $binPath = 'whois',
    )
    {
    }

    public function canHandle(RequestInterface $request): bool
    {
        return str_starts_with($request->getServer()->getUri(), 'whois://');
    }

    public function handle(RequestInterface $request): ResponseInterface
    {
        $command = $this->binPath;
        //$command .= ' --verbose';
        $command .= ' --no-recursion';

        $url = parse_url($request->getServer()->getUri());

        $serverName = $url['host'];
        $command .= ' -h ' . escapeshellarg($serverName);
        $command .= ' -p ' . escapeshellarg($url['port'] ?? 43);

        $queryString = $request->getQueryString();
        $command .= ' ' . escapeshellarg($queryString);

        $timeStart = microtime(true);

        $procHandle = @proc_open(
            $command,
            [
                0 => [ 'pipe', 'r' ],
                1 => [ 'pipe', 'w' ],
                2 => [ 'pipe', 'w' ],
            ],
            $pipes,
            null,
            [ ...$_ENV, 'LC_ALL=C' ]
        );

        if (!is_resource($procHandle)) {
            $error = error_get_last()['message'] ?? 'unknown error while at proc_open()';
            throw new ClientException($error);
        }

        array_map(fn($p) => stream_set_blocking($p, false), $pipes);
        [ $stdin, $stdout, $stderr ] = $pipes;
        $output = $error = '';
        do {
            $read = [ $stderr, $stdout ];
            $write = null;
            $except = null;
            stream_select($read, $write, $except, 0, 50_000);
            foreach ($read as $stream) {
                $line = fgets($stream);
                if ($stream === $stdout) {
                    $output .= $line;
                }
                if ($stream === $stderr) {
                    $error .= $line;
                }
            }

            if (microtime(true) - $timeStart > $request->getTimeout()) {
                proc_terminate($procHandle);
                proc_close($procHandle);
                throw (new ClientTimeoutException("Timed out after {$request->getTimeout()} sec"))
                    ->withRequest($request);
            }

        } while (!feof($stdout) || !feof($stderr));

        $status = proc_get_status($procHandle);
        $exitCode = $status['exitcode'] ?? 0;
        if ($exitCode > 0 && !$error) {
            $error = "Process exited with code $exitCode";
        }
        if ($error) {
            throw (new ClientRequestException($error))
                ->withRequest($request);
        }

        return new Response($output);
    }

}