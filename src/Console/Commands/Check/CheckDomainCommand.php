<?php
declare(strict_types = 1);

namespace Watchr\Console\Commands\Check;

use DateTimeImmutable;
use DateTimeInterface;
use Exception;
use Iodev\Whois\Whois;
use Psr\Clock\ClockInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Watchr\Console\Traits\DateUtilsTrait;
use Watchr\Console\Traits\ErrorPrinterTrait;

#[AsCommand('check:domain', 'Run multiple checks on a domain name')]
final class CheckDomainCommand extends Command {
  use DateUtilsTrait;
  use ErrorPrinterTrait;

  private ClockInterface $clock;
  private Whois $whois;

  protected function configure(): void {
    $this
      ->addOption(
        'skip-expiration-date',
        null,
        InputOption::VALUE_NONE,
        'Skip Domain expiration date validation'
      )
      ->addOption(
        'domain-expiration-threshold',
        null,
        InputOption::VALUE_REQUIRED,
        'Number of days left to domain expiration that will trigger an error',
        5
      )
      ->addOption(
        'skip-registrar-name',
        null,
        InputOption::VALUE_NONE,
        'Skip Domain Registrar Name validation'
      )
      ->addOption(
        'registrar-name',
        null,
        InputOption::VALUE_REQUIRED,
        'Registrar\'s Name where the Domain Name has been registered'
      )
      ->addOption(
        'skip-transfer-prohibited',
        null,
        InputOption::VALUE_NONE,
        'Skip Domain transfer lock status validation'
      )
      ->addOption(
        'fail-fast',
        null,
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
    $checks = [
      'expirationDate' => (bool)$input->getOption('skip-expiration-date') === false,
      'registrarName' => (bool)$input->getOption('skip-registrar-name') === false,
      'transferProhibited' => (bool)$input->getOption('skip-transfer-prohibited') === false
    ];

    $expirationThreshold = (int)$input->getOption('domain-expiration-threshold');
    $registrarName = (string)$input->getOption('registrar-name');

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
              ($checks['expirationDate'] ? '<fg=green>enabled</>' : '<fg=red>disabled</>')
            ],
            [
              'Registrar Name',
              ($checks['registrarName'] ? '<fg=green>enabled</>' : '<fg=red>disabled</>')
            ],
            [
              'Transfer Prohibited',
              ($checks['transferProhibited'] ? '<fg=green>enabled</>' : '<fg=red>disabled</>')
            ]
          ]
        )
        ->render();

      $output->writeln('');
    }


    $errors = [];
    if ($checks['registrarName'] === true && trim($registrarName) === '') {
      $errors[] = '<options=bold>--registrar-name</> option is required unless <options=bold>--skip-registrar-name</> is set';
    }

    if (filter_var($domain, FILTER_VALIDATE_DOMAIN, ['flags' => FILTER_FLAG_HOSTNAME]) === false) {
      $errors[] = 'argument <options=bold>domain</> contains an invalid domain name';
    }

    if (count($errors) > 0) {
      $this->printErrors($errors, $output);

      return Command::FAILURE;
    }

    $needWhois = (
      $checks['expirationDate'] ||
      $checks['registrarName'] ||
      $checks['transferProhibited']
    );

    if ($needWhois === false) {
      return Command::SUCCESS;
    }

    // required for expiration checks
    $now = $this->clock->now();

    $output->writeln(
      'Starting domain checks',
      OutputInterface::VERBOSITY_DEBUG
    );

    try {
      $info = $this->whois->loadDomainInfo($domain);

      if ($checks['expirationDate'] === true) {
        if ($info->expirationDate === 0) {
          $errors[] = sprintf(
            'Failed to retrieve the expiration date for domain "%s"',
            $domain
          );

          if ($failFast === true) {
            return Command::FAILURE;
          }
        }

        $expiresAt = (new DateTimeImmutable())->setTimestamp($info->expirationDate);
        $output->writeln(
          sprintf(
            'Domain expiration date: <options=bold>%s</> (%d)',
            $expiresAt->format(DateTimeInterface::ATOM),
            $info->expirationDate
          ),
          OutputInterface::VERBOSITY_DEBUG
        );

        $interval = $now->diff($expiresAt);
        if ($interval->days <= 0) {
          $errors[] = sprintf(
            'Domain "%s" expired %s ago',
            $domain,
            $this->timeAgo($interval)
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
          OutputInterface::VERBOSITY_DEBUG
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
          OutputInterface::VERBOSITY_DEBUG
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

      if ($checks['transferProhibited'] === true) {
        if ($info->states === []) {
          $errors[] = sprintf(
            'Failed to retrieve the status for domain "%s"',
            $domain
          );

          if ($failFast === true) {
            $this->printErrors($errors, $output);

            return Command::FAILURE;
          }
        }

        if (in_array('clienttransferprohibited', $info->states, true) === false) {
          $errors[] = sprintf(
            'Domain "%s" does not have the "clientTransferProhibited" status activated (active: %s)',
            $domain,
            implode(', ', $info->states)
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
      OutputInterface::VERBOSITY_DEBUG
    );

    if (count($errors) > 0) {
      $this->printErrors($errors, $output);

      return Command::FAILURE;
    }

    return Command::SUCCESS;
  }

  public function __construct(
    ClockInterface $clock,
    Whois $whois
  ) {
    parent::__construct();

    $this->clock = $clock;
    $this->whois = $whois;
  }
}
