<?php
declare(strict_types = 1);

namespace Watchr\Console\Commands\Check;

use DateTimeInterface;
use Exception;
use RuntimeException;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Watchr\Console\Utils\DateUtils;

#[AsCommand('check:http-resp', 'Run multiple checks on a HTTP response')]
final class CheckHttpResponseCommand extends Command {

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
      ->addArgument(
        'url',
        InputArgument::REQUIRED,
        'URL to be checked'
      );
  }

  protected function execute(InputInterface $input, OutputInterface $output): int {
    return Command::SUCCESS;
  }
}
