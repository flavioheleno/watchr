<?php
declare(strict_types = 1);

namespace Watchr\Console\Traits;

use Symfony\Component\Console\Output\OutputInterface;

trait ErrorPrinterTrait {
  /**
   * @param string[] $errors
   */
  private function printErrors(array $errors, OutputInterface $output): void {
    $errorCount = count($errors);
    if ($errorCount === 0) {
      return;
    }

    if ($errorCount > 1) {
      $output->writeln(
        [
          "Found {$errorCount} errors:",
          ...array_map(
            static function (string $error): string {
              return " - {$error}";
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
}
