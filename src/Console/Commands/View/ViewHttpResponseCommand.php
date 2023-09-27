<?php
declare(strict_types = 1);

namespace Watchr\Console\Commands\View;

use Exception;
use InvalidArgumentException;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Watchr\Console\Contracts\HTTP\HttpRequestMethodEnum;
use Watchr\Console\DataObjects\HTTP\HttpConfiguration;
use Watchr\Console\Services\HttpService;
use Watchr\Console\Traits\DateUtilsTrait;

#[AsCommand('view:http-resp', 'View HTTP Response details')]
final class ViewHttpResponseCommand extends Command {
  use DateUtilsTrait;

  private HttpService $httpService;

  protected function configure(): void {
    $this
      ->addOption(
        'method',
        'm',
        InputOption::VALUE_REQUIRED,
        'The desired action to be performed',
        'GET'
      )
      ->addOption(
        'add-header',
        'd',
        InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY,
        'Additional headers to be sent with request (format <name>:<value>)',
        []
      )
      ->addOption(
        'body',
        'b',
        InputOption::VALUE_REQUIRED,
        'Request body for POST, PUT and PATCH methods (prefix a filename with "@" to read its contents)'
      )
      ->addOption(
        'auth-path',
        'a',
        InputOption::VALUE_REQUIRED,
        'Path to a json file containing authentication type and required values'
      )
      ->addOption(
        'json',
        'j',
        InputOption::VALUE_NONE,
        'Format the output as a JSON string'
      )
      ->addArgument(
        'url',
        InputArgument::REQUIRED,
        'URL to be requested'
      );
  }

  protected function execute(InputInterface $input, OutputInterface $output): int {
    $jsonOutput = (bool)$input->getOption('json');
    $url = $input->getArgument('url');
    try {
      if (filter_var($url, FILTER_VALIDATE_URL) === false) {
        throw new InvalidArgumentException('argument url must be a valid url');
      }

      $method = HttpRequestMethodEnum::tryFrom(strtoupper((string)$input->getOption('method')));
      $headers = (array)$input->getOption('add-header');
      $body = (string)$input->getOption('body');

      $authentication = null;
      $authPath = (string)$input->getOption('auth-path');
      if ($authPath !== '' && is_readable($authPath)) {}

      $response = $this->httpService->request(
        $url,
        $method,
        new HttpConfiguration($authentication, $body, $headers)
      );

      if ($jsonOutput === true) {
        $output->write(json_encode($response));

        return Command::SUCCESS;
      }

      $output->writeln('');
      $table = new Table($output);
      $table
        ->setHeaderTitle('Details & Metrics')
        ->setHeaders(['Description', 'Value'])
        ->addRows(
          [
            [
              'Time it took from the start until the SSL connect/handshake was completed',
              $this->fromMicroseconds($response->appConnectTime)
            ],
            [
              'TLS certificate chain size',
              count($response->certChain) . ' certificates'
            ],
            [
              'Time it took to establish the connection',
              $this->fromMicroseconds($response->connectTime)
            ],
            [
              'Content length of download, read from "Content-Length" header',
              $response->contentLength === -1 ? '-' : $response->contentLength . ' bytes'
            ],
            [
              'The "Content-Type" of the requested document',
              $response->contentType ?? '-'
            ],
            [
              'The version used in the last HTTP connection',
              $response->httpVersion === 0 ? '-' : 'HTTP/' . $response->httpVersion
            ],
            [
              'Time until name resolving was complete',
              $this->fromMicroseconds($response->namelookupTime)
            ],
            [
              'Time from start until just before file transfer begins',
              $this->fromMicroseconds($response->preTransferTime)
            ],
            [
              'IP address of the most recent connection',
              $response->primaryIp
            ],
            [
              'Destination port of the most recent connection',
              $response->primaryPort
            ],
            [
              'The last response code',
              $response->responseCode
            ],
            [
              'Time until the first byte is about to be transferred',
              $this->fromMicroseconds($response->startTransferTime)
            ],
            [
              'Total transaction time for last transfer',
              $this->fromMicroseconds($response->totalTime)
            ],
            [
              'The redirect URL found in the last transaction',
              $response->redirectUrl ?: '-'
            ],
            [
              'Last effective URL',
              $response->url
            ]
          ]
        )
        ->render();
      $output->writeln('');

      $output->writeln('');
      $table = new Table($output);
      $table
        ->setHeaderTitle('Response Headers')
        ->setHeaders(['Name', 'Value'])
        ->addRows(
          array_map(
            static function (string $value, string $key): array {
              if (strlen($value) > 100) {
                $value = substr($value, 0, 45) . '...' . substr($value, -45);
              }

              return [$key, $value];
            },
            array_values($response->headers),
            array_keys($response->headers)
          )
        )
        ->render();
      $output->writeln('');


      return Command::SUCCESS;
    } catch (Exception $exception) {
      if ($jsonOutput === true) {
        $out = ['error' => $exception->getMessage()];
        if ($output->isDebug() === true) {
          $out['trace'] = $exception->getTrace();
        }

        $output->write(json_encode($out));

        return Command::FAILURE;
      }

      $output->writeln($exception->getMessage());
      if ($output->isDebug() === true) {
        $output->writeln($exception->getTraceAsString());
      }

      return Command::FAILURE;
    }
  }

  public function __construct(HttpService $httpService) {
    parent::__construct();

    $this->httpService = $httpService;
  }
}
