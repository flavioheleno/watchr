<?php
declare(strict_types = 1);

namespace Watchr\Console\Commands\Check;

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
use Watchr\Console\Traits\ErrorPrinterTrait;

#[AsCommand('check:http-resp', 'Run multiple checks on a HTTP response')]
final class CheckHttpResponseCommand extends Command {
  use ErrorPrinterTrait;

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
        'status-code',
        'S',
        InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY,
        'Expected Response status code',
        [200, 201, 202, 203, 204, 205, 206]
      )
      ->addOption(
        'match-keyword',
        'K',
        InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY,
        'Keyword expected to match in the Response body contents'
      )
      ->addOption(
        'not-match-keyword',
        'N',
        InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY,
        'Keyword expected not to match in the Response body contents'
      )
      ->addOption(
        'no-body',
        'B',
        InputOption::VALUE_NONE,
        'Assert that the Response body is empty'
      )
      ->addOption(
        'fail-fast',
        'f',
        InputOption::VALUE_NONE,
        'Exit immediately when a check fails instead of running all checks'
      )
      ->addArgument(
        'url',
        InputArgument::REQUIRED,
        'URL to be checked'
      );
  }

  protected function execute(InputInterface $input, OutputInterface $output): int {

    $method = HttpRequestMethodEnum::tryFrom(strtoupper((string)$input->getOption('method')));
    $headers = (array)$input->getOption('add-header');
    $body = (string)$input->getOption('body');

    $authentication = null;
    $authPath = (string)$input->getOption('auth-path');
    if ($authPath !== '' && is_readable($authPath)) {}

    $statusCodes = (array)$input->getOption('status-code');

    $matchKeywords = (array)$input->getOption('match-keyword');
    $notMatchKeywords = (array)$input->getOption('not-match-keyword');
    $noBody = (bool)$input->getOption('no-body');

    $checks = [
      'statusCodes' => $statusCodes !== [],
      'matchKeywords' => $matchKeywords !== [],
      'notMatchKeywords' => $notMatchKeywords !== [],
      'noBody' => $noBody === true
    ];

    $failFast = (bool)$input->getOption('fail-fast');
    $url = (string)$input->getArgument('url');

    try {
      if (filter_var($url, FILTER_VALIDATE_URL) === false) {
        throw new InvalidArgumentException(
          'argument url must be a valid url'
        );
      }

      if ($output->isDebug() === true) {
        $output->writeln('');
        $table = new Table($output);
        $table
          ->setHeaders(['Verification', 'Status', 'Value'])
          ->addRows(
            [
              [
                'Status Code',
                ($checks['statusCodes'] ? '<fg=green>enabled</>' : '<fg=red>disabled</>'),
                $statusCodes === [] ? '-' : implode(', ', $statusCodes)
              ],
              [
                'Match Keywords',
                ($checks['matchKeywords'] ? '<fg=green>enabled</>' : '<fg=red>disabled</>'),
                $matchKeywords === [] ? '-' : implode(', ', $matchKeywords)
              ],
              [
                'Not Match Keywords',
                ($checks['notMatchKeywords'] ? '<fg=green>enabled</>' : '<fg=red>disabled</>'),
                $notMatchKeywords === [] ? '-' : implode(', ', $notMatchKeywords)
              ],
              [
                'Empty Response Body',
                ($checks['noBody'] ? '<fg=green>enabled</>' : '<fg=red>disabled</>'),
                '-'
              ]
            ]
          )
          ->render();

        $output->writeln('');
      }

      $needHttp = (
        $checks['statusCodes'] ||
        $checks['matchKeywords'] ||
        $checks['notMatchKeywords'] ||
        $checks['noBody']
      );

      if ($needHttp === false) {
        $output->writeln(
          'All HTTP Response verifications are disabled, leaving',
          OutputInterface::VERBOSITY_VERBOSE
        );

        return Command::SUCCESS;
      }

      $output->writeln(
        'Starting HTTP Response checks',
        OutputInterface::VERBOSITY_VERBOSE
      );

      $response = $this->httpService->request(
        $url,
        $method,
        new HttpConfiguration($authentication, $body, $headers)
      );

      $errors = [];
      if ($checks['statusCodes'] === true) {
        $output->writeln(
          sprintf(
            'Response status code: <options=bold>%d</>',
            $response->responseCode
          ),
          OutputInterface::VERBOSITY_VERBOSE
        );

        if (in_array($response->responseCode, $statusCodes, true) === false) {
          $errors[] = sprintf(
            'Response status code is not within expected list'
          );

          if ($failFast === true) {
            $this->printErrors($errors, $output);

            return Command::FAILURE;
          }
        }
      }

      $bodyContents = (string)$response->body;
      $output->writeln(
        sprintf(
          'Response body is <options=bold>%d</> bytes long',
          strlen($bodyContents)
        ),
        OutputInterface::VERBOSITY_VERBOSE
      );

      if ($checks['matchKeywords'] === true) {
        if ($bodyContents === '') {
          $errors[] = 'Response body is empty, cannot match any keyword';

          if ($failFast === true) {
            $this->printErrors($errors, $output);

            return Command::FAILURE;
          }
        }

        foreach ($matchKeywords as $keyword) {
          if (str_contains($bodyContents, $keyword) === false) {
            $errors[] = sprintf(
              'Keyword "%s" was not found in response body',
              $keyword
            );

            if ($failFast === true) {
              $this->printErrors($errors, $output);

              return Command::FAILURE;
            }
          }
        }
      }

      if ($checks['notMatchKeywords'] === true) {
        foreach ($notMatchKeywords as $keyword) {
          if (str_contains($bodyContents, $keyword) === true) {
            $errors[] = sprintf(
              'Keyword "%s" was found in response body',
              $keyword
            );

            if ($failFast === true) {
              $this->printErrors($errors, $output);

              return Command::FAILURE;
            }
          }
        }
      }

      if ($checks['noBody'] === true && $bodyContents !== '') {
        $errors[] = 'Response body should be empty';

        if ($failFast === true) {
          $this->printErrors($errors, $output);

          return Command::FAILURE;
        }
      }
    } catch (Exception $exception) {
      $errors[] = $exception->getMessage();
      $this->printErrors($errors, $output);

      return Command::FAILURE;
    }

    $output->writeln(
      'Finished HTTP Response checks',
      OutputInterface::VERBOSITY_VERBOSE
    );

    if (count($errors) > 0) {
      $this->printErrors($errors, $output);

      return Command::FAILURE;
    }

    return Command::SUCCESS;
  }

  public function __construct(HttpService $httpService) {
    parent::__construct();

    $this->httpService = $httpService;
  }
}
