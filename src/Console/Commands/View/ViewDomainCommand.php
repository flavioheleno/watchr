<?php
declare(strict_types = 1);

namespace Watchr\Console\Commands\View;

use DateTimeInterface;
use Exception;
use InvalidArgumentException;
use Psr\Clock\ClockInterface;
use RuntimeException;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Watchr\Console\Services\DomainService;
use Watchr\Console\Traits\DateUtilsTrait;
use Watchr\Console\Traits\ErrorPrinterTrait;

#[AsCommand('view:domain', 'View domain name details')]
final class ViewDomainCommand extends Command {
  use DateUtilsTrait;
  use ErrorPrinterTrait;

  private ClockInterface $clock;
  private DomainService $domainService;

  protected function configure(): void {
    $this
      ->addOption(
        'json',
        'j',
        InputOption::VALUE_NONE,
        'Format the output as a JSON string'
      )
      ->addArgument(
        'domain',
        InputArgument::REQUIRED,
        'Domain Name to be viewed'
      );
  }

  protected function execute(InputInterface $input, OutputInterface $output): int {
    $jsonOutput = (bool)$input->getOption('json');
    $domain = $input->getArgument('domain');
    try {
      if (
        strpos($domain, '.') === false ||
        filter_var($domain, FILTER_VALIDATE_DOMAIN, ['flags' => FILTER_FLAG_HOSTNAME]) === false
      ) {
        throw new InvalidArgumentException('argument <options=bold>domain</> contains an invalid domain name');
      }

      $info = $this->domainService->lookup($domain);
      if ($info === null) {
        throw new RuntimeException('Failed to load domain information');
      }

      if ($jsonOutput === true) {
        $output->write(json_encode($info));

        return Command::SUCCESS;
      }

      $now = $this->clock->now();

      $lines = [];
      $lines[] = sprintf('Domain: <options=bold>%s</>', $info->domainName);
      $lines[] = 'Name Servers';
      foreach ($info->nameServers as $nameServer) {
        $lines[] = sprintf('  * <options=bold>%s</>', $nameServer);
      }

      $lines[] = sprintf(
        'Creation date: <options=bold>%s</> (%s)',
        $info->creationDate->format(DateTimeInterface::ATOM),
        $this->humanReadableInterval($now->diff($info->creationDate))
      );
      $lines[] = sprintf(
        'Expiration date: <options=bold>%s</> (%s)',
        $info->expirationDate->format(DateTimeInterface::ATOM),
        $this->humanReadableInterval($now->diff($info->expirationDate))
      );
      $lines[] = sprintf(
        'Last update: <options=bold>%s</> (%s)',
        $info->updatedDate->format(DateTimeInterface::ATOM),
        $this->humanReadableInterval($now->diff($info->updatedDate))
      );
      $lines[] = 'EPP Flags';
      foreach ($info->states as $state) {
        $lines[] = sprintf('  * <options=bold>%s</>', $state);
      }

      $lines[] = sprintf('Registrar: <options=bold>%s</>', $info->registrar);
      $lines[] = sprintf('DNSSEC: <options=bold>%s</>', $info->dnssec === null ? 'NO' : 'YES');

      $output->writeln($lines);

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

      $errors = [$exception->getMessage()];
      if ($output->isDebug() === true) {
        $errors[] = $exception->getTraceAsString();
      }

      $this->printErrors($errors, $output);

      return Command::FAILURE;
    }
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
