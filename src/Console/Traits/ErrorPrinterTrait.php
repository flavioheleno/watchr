<?php
declare(strict_types = 1);

namespace Watchr\Console\Traits;

use Symfony\Component\Console\Output\OutputInterface;

trait ErrorPrinterTrait {
  /**
   * @param string[] $messages
   */
  private function printMessages(
    string $listTemplate,
    string $lineTemplate,
    array $messages,
    OutputInterface $output,
    int $verbosityLevel
  ): void {
    $messageCount = count($messages);
    if ($messageCount === 0) {
      return;
    }

    if ($messageCount > 1) {
      $output->writeln(
        [
          sprintf($listTemplate, $messageCount),
          ...array_map(
            static function (string $message): string {
              return sprintf(
                ' - %s',
                // properly indent multi-line messages
                trim(
                  implode(
                    PHP_EOL,
                    array_map(
                      static function (string $line): string {
                        return str_repeat(' ', 3) . $line;
                      },
                      explode(PHP_EOL, $message)
                    )
                  )
                )
              );
            },
            $messages
          )
        ],
        OutputInterface::VERBOSITY_VERBOSE
      );

      return;
    }

    $output->writeln(
      sprintf($lineTemplate, array_pop($messages)),
      OutputInterface::VERBOSITY_VERBOSE
    );
  }

  /**
   * @param string[] $warnings
   */
  private function printWarnings(array $warnings, OutputInterface $output): void {
    $this->printMessages(
      'Found <options=bold>%d</> warnings:',
      'Warning: %s',
      $warnings,
      $output,
      OutputInterface::VERBOSITY_VERBOSE
    );
  }

  /**
   * @param string[] $errors
   */
  private function printErrors(array $errors, OutputInterface $output): void {
    $this->printMessages(
      'Found <options=bold>%d</> errors:',
      'Error: %s',
      $errors,
      $output,
      OutputInterface::VERBOSITY_VERBOSE
    );
  }
}
