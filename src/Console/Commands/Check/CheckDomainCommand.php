<?php
declare(strict_types = 1);

namespace Watchr\Console\Commands\Check;

use DateTimeImmutable;
use DateTimeInterface;
use Exception;
use InvalidArgumentException;
use Iodev\Whois\Whois;
use League\Config\Configuration;
use Psr\Clock\ClockInterface;
use RuntimeException;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Watchr\Console\Utils\DateUtils;

#[AsCommand('check:domain', 'Run multiple checks on a domain name')]
final class CheckDomainCommand extends Command {
  private Configuration $config;
  private ClockInterface $clock;
  private Whois $whois;

  /**
   * @param string[] $errors
   */
  private function printErrors(array $errors, OutputInterface $output): void {
    if (count($errors) > 1) {
      $output->writeln(
        [
          'Found ' . count($errors) . ' errors:',
          ...array_map(
            static function (string $error): string {
              return "\t$error";
            },
            $errors
          )
        ],
        OutputInterface::VERBOSITY_VERBOSE
      );

      return;
    }

    $output->writeln(
      'Error: ' . array_pop($errors),
      OutputInterface::VERBOSITY_VERBOSE
    );
  }

  protected function configure(): void {
    $this
      ->addOption(
        'config',
        'c',
        InputOption::VALUE_REQUIRED,
        'Path to configuration file',
        getcwd() . '/watchr.json'
      );
  }

  protected function execute(InputInterface $input, OutputInterface $output): int {
    $configPath = $input->getOption('config');
    if (is_readable($configPath) === false) {
      throw new InvalidArgumentException('Configuration file is not readable');
    }

    $contents = file_get_contents($configPath);
    if ($contents === false) {
      throw new RuntimeException('Failed to read configuration file contents');
    }

    $this->config->merge(json_decode($contents, true, flags: JSON_THROW_ON_ERROR));

    $subject = $this->config->get('subject');

    $output->writeln(
      sprintf(
        'Subject: <options=bold>%s</>',
        $subject
      ),
      OutputInterface::VERBOSITY_VERBOSE
    );

    if ((bool)$this->config->get('domain.enabled') === false) {
      $output->writeln(
        'Domain check is disabled, leaving',
        OutputInterface::VERBOSITY_VERBOSE
      );

      return Command::SUCCESS;
    }

    $checks = [
      'expirationDate' => true,
      'registrarName' => true,
      'statusFlags' => true
    ];

    $expirationThreshold = (int)$this->config->get('domain.expirationThreshold');
    if ($expirationThreshold === -1) {
      $checks['expirationDate'] = false;
    }

    $registrarName = (string)$this->config->get('domain.registrarName');
    if ($registrarName === '') {
      $checks['registrarName'] = false;
    }

    $statusFlags = (array)$this->config->get('domain.statusFlags');
    if ($statusFlags === []) {
      $checks['statusFlags'] = false;
    }

    $failFast = (bool)$this->config->get('failFast');

    if ($output->isDebug() === true) {
      $output->writeln('');
      $table = new Table($output);
      $table
        ->setHeaders(['Verification', 'Status', 'Value'])
        ->addRows(
          [
            [
              'Expiration Date',
              ($checks['expirationDate'] ? '<fg=green>enabled</>' : '<fg=red>disabled</>'),
              $expirationThreshold > -1 ? "{$expirationThreshold} days" : '-'
            ],
            [
              'Registrar Name',
              ($checks['registrarName'] ? '<fg=green>enabled</>' : '<fg=red>disabled</>'),
              $registrarName ?: '-'
            ],
            [
              'Status Flags',
              ($checks['statusFlags'] ? '<fg=green>enabled</>' : '<fg=red>disabled</>'),
              $statusFlags === [] ? '-' : implode(', ', $statusFlags)
            ]
          ]
        )
        ->render();

      $output->writeln('');
    }

    $needWhois = (
      $checks['expirationDate'] ||
      $checks['registrarName'] ||
      $checks['statusFlags']
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
      'Starting domain check',
      OutputInterface::VERBOSITY_DEBUG
    );

    try {
      $info = $this->whois->loadDomainInfo($subject);

      $errors = [];
      if ($checks['expirationDate'] === true) {
        if ($info->expirationDate === 0) {
          $errors[] = 'Failed to retrieve the expiration date';

          if ($failFast === true) {
            return Command::FAILURE;
          }
        }

        $expiresAt = (new DateTimeImmutable())->setTimestamp($info->expirationDate);
        $output->writeln(
          sprintf(
            'Domain expiration date is <options=bold>%s</> (%d)',
            $expiresAt->format(DateTimeInterface::ATOM),
            $info->expirationDate
          ),
          OutputInterface::VERBOSITY_DEBUG
        );

        $interval = $now->diff($expiresAt);
        if ($interval->days <= 0) {
          $errors[] = sprintf(
            'Domain has expired %s ago',
            DateUtils::timeAgo($interval)
          );

          if ($failFast === true) {
            $this->printErrors($errors, $output);

            return Command::FAILURE;
          }
        }

        if ($interval->days <= $expirationThreshold) {
          $errors[] = sprintf(
            'Domain will expire in %d days (threshold: %d)',
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
            'Domain expires in <options=bold>%d days</>',
            $interval->days
          ),
          OutputInterface::VERBOSITY_DEBUG
        );
      }

      if ($checks['registrarName'] === true) {
        if ($info->registrar === '') {
          $errors[] = 'Failed to retrieve the registrar name';

          if ($failFast === true) {
            $this->printErrors($errors, $output);

            return Command::FAILURE;
          }
        }

        $output->writeln(
          sprintf(
            'Registrar name <options=bold>%s</>',
            $info->registrar
          ),
          OutputInterface::VERBOSITY_DEBUG
        );

        if ($info->registrar !== $registrarName) {
          $errors[] = sprintf(
            'Registrar name does not match the expected name "%s", found: "%s"',
            $registrarName,
            $info->registrar
          );

          if ($failFast === true) {
            $this->printErrors($errors, $output);

            return Command::FAILURE;
          }
        }
      }

      if ($checks['statusFlags'] === true) {
        if ($info->states === []) {
          $errors[] = 'Failed to retrieve the status flags';

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
          OutputInterface::VERBOSITY_DEBUG
        );

        $diff = array_diff(
          array_map('strtolower', $statusFlags),
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
      'Finished domain check',
      OutputInterface::VERBOSITY_DEBUG
    );

    if (count($errors) > 0) {
      $this->printErrors($errors, $output);

      return Command::FAILURE;
    }

    return Command::SUCCESS;
  }

  public function __construct(
    Configuration $config,
    ClockInterface $clock,
    Whois $whois
  ) {
    parent::__construct();

    $this->config = $config;
    $this->clock = $clock;
    $this->whois = $whois;
  }
}
