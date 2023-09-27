<?php
declare(strict_types = 1);

namespace Watchr\Console\Commands\Check;

use DateTimeInterface;
use Exception;
use Psr\Clock\ClockInterface;
use RuntimeException;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Watchr\Console\Services\DomainService;
use Watchr\Console\Traits\DateUtilsTrait;
use Watchr\Console\Traits\ErrorPrinterTrait;

#[AsCommand('check:domain', 'Run multiple checks on a domain name')]
final class CheckDomainCommand extends Command {
  use DateUtilsTrait;
  use ErrorPrinterTrait;

  private ClockInterface $clock;
  private DomainService $domainService;

  protected function configure(): void {
    $this
      ->addOption(
        'expiration-threshold',
        'e',
        InputOption::VALUE_REQUIRED,
        'Number of days until the domain expiration date',
        5
      )
      ->addOption(
        'registrar-name',
        'r',
        InputOption::VALUE_REQUIRED,
        'Match the name of the company where the domain has been registered'
      )
      ->addOption(
        'status-codes',
        's',
        InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY,
        'List of Extensible Provisioning Protocol (EPP) status codes that should be active',
        ['clientTransferProhibited']
      )
      ->addOption(
        'fail-fast',
        'f',
        InputOption::VALUE_NONE,
        'Exit immediately when a check fails instead of running all checks'
      )
      ->addArgument(
        'domain',
        InputArgument::REQUIRED,
        'Domain Name to be checked'
      );
  }

  protected function execute(InputInterface $input, OutputInterface $output): int {
    $expirationThreshold = (int)$input->getOption('expiration-threshold');
    $registrarName = (string)$input->getOption('registrar-name');
    $statusCodes = (array)$input->getOption('status-codes');

    $checks = [
      'expirationDate' => $expirationThreshold > 0,
      'registrarName' => $registrarName !== '',
      'statusCodes' => $statusCodes !== []
    ];

    $failFast = (bool)$input->getOption('fail-fast');
    $domain = $input->getArgument('domain');

    if ($output->isDebug() === true) {
      $output->writeln('');
      $table = new Table($output);
      $table
        ->setHeaders(['Verification', 'Status'])
        ->addRows(
          [
            [
              'Expiration Date',
              ($checks['expirationDate'] ? '<fg=green>enabled</>' : '<fg=red>disabled</>'),
              $expirationThreshold > 0 ? "{$expirationThreshold} days" : '-'
            ],
            [
              'Registrar Name',
              ($checks['registrarName'] ? '<fg=green>enabled</>' : '<fg=red>disabled</>'),
              $registrarName ?: '-'
            ],
            [
              'Status Codes',
              ($checks['statusCodes'] ? '<fg=green>enabled</>' : '<fg=red>disabled</>'),
              $statusCodes === [] ? '-' : implode(', ', $statusCodes)
            ]
          ]
        )
        ->render();

      $output->writeln('');
    }

    $errors = [];
    if (
      strpos($domain, '.') === false ||
      filter_var($domain, FILTER_VALIDATE_DOMAIN, ['flags' => FILTER_FLAG_HOSTNAME]) === false
    ) {
      $errors[] = 'argument <options=bold>domain</> contains an invalid domain name';
    }

    if (count($errors) > 0) {
      $this->printErrors($errors, $output);

      return Command::FAILURE;
    }

    $needWhois = (
      $checks['expirationDate'] ||
      $checks['registrarName'] ||
      $checks['statusCodes']
    );

    if ($needWhois === false) {
      $output->writeln(
        'All domain verifications are disabled, leaving',
        OutputInterface::VERBOSITY_VERBOSE
      );

      return Command::SUCCESS;
    }

    // required for expiration checks
    $now = $this->clock->now();

    $output->writeln(
      'Starting domain checks',
      OutputInterface::VERBOSITY_VERBOSE
    );

    try {
      $info = $this->domainService->lookup($domain);
      if ($info === null) {
        throw new RuntimeException('Failed to load domain information');
      }

      if ($checks['expirationDate'] === true) {
        if ($info->expirationDate === null) {
          $errors[] = sprintf(
            'Failed to retrieve the expiration date for domain "%s"',
            $domain
          );

          if ($failFast === true) {
            return Command::FAILURE;
          }
        }

        $output->writeln(
          sprintf(
            'Domain expiration date: <options=bold>%s</> (%d)',
            $info->expirationDate->format(DateTimeInterface::ATOM),
            $info->expirationDate->getTimestamp()
          ),
          OutputInterface::VERBOSITY_VERBOSE
        );

        $interval = $now->diff($info->expirationDate);
        if ($interval->days <= 0) {
          $errors[] = sprintf(
            'Domain "%s" expired %s ago',
            $domain,
            $this->humanReadableInterval($interval)
          );

          if ($failFast === true) {
            $this->printErrors($errors, $output);

            return Command::FAILURE;
          }
        }

        if ($interval->days <= $expirationThreshold) {
          $errors[] = sprintf(
            'Domain "%s" will expire in %d days (threshold: %d)',
            $domain,
            $interval->days,
            $expirationThreshold
          );

          if ($failFast === true) {
            $this->printErrors($errors, $output);

            return Command::FAILURE;
          }
        }

        $output->writeln(
          sprintf(
            'Domain expires in: <options=bold>%d days</>',
            $interval->days
          ),
          OutputInterface::VERBOSITY_VERBOSE
        );
      }

      if ($checks['registrarName'] === true) {
        if ($info->registrar === '') {
          $errors[] = sprintf(
            'Failed to retrieve the registrar name for domain "%s"',
            $domain
          );

          if ($failFast === true) {
            $this->printErrors($errors, $output);

            return Command::FAILURE;
          }
        }

        $output->writeln(
          sprintf(
            'Registrar name: <options=bold>%s</>',
            $info->registrar
          ),
          OutputInterface::VERBOSITY_VERBOSE
        );

        if ($info->registrar !== $registrarName) {
          $errors[] = sprintf(
            'Registrar name for domain "%s" does not match the expected "%s", found: "%s"',
            $domain,
            $registrarName,
            $info->registrar
          );

          if ($failFast === true) {
            $this->printErrors($errors, $output);

            return Command::FAILURE;
          }
        }
      }

      if ($checks['statusCodes'] === true) {
        if ($info->states === []) {
          $errors[] = sprintf(
            'Failed to retrieve the status code list for domain "%s"',
            $domain
          );

          if ($failFast === true) {
            $this->printErrors($errors, $output);

            return Command::FAILURE;
          }
        }

        $output->writeln(
          sprintf(
            'Active status flags <options=bold>%s</>',
            implode('</>, <options=bold>', $info->states)
          ),
          OutputInterface::VERBOSITY_VERBOSE
        );

        $diff = array_diff(
          array_map('strtolower', $statusCodes),
          array_map('strtolower', $info->states)
        );
        if ($diff !== []) {
          $errors[] = sprintf(
            'Not all required status flags are active (missing: %s)',
            implode(', ', $diff)
          );

          if ($failFast === true) {
            $this->printErrors($errors, $output);

            return Command::FAILURE;
          }
        }
      }
    } catch (Exception $exception) {
      $errors[] = $exception->getMessage();

      if ($failFast === true) {
        $this->printErrors($errors, $output);

        return Command::FAILURE;
      }
    }

    $output->writeln(
      'Finished domain checks',
      OutputInterface::VERBOSITY_VERBOSE
    );

    if (count($errors) > 0) {
      $this->printErrors($errors, $output);

      return Command::FAILURE;
    }

    return Command::SUCCESS;
  }

  public function __construct(
    ClockInterface $clock,
    DomainService $domainService
  ) {
    parent::__construct();

    $this->clock = $clock;
    $this->domainService = $domainService;
  }
}
