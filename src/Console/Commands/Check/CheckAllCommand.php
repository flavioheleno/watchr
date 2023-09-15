<?php
declare(strict_types = 1);

namespace Watchr\Console\Commands\Check;

use InvalidArgumentException;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand('check:all', 'Run all checks combined')]
final class CheckAllCommand extends Command {
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

    $app = $this->getApplication();

    return max(
      $app->doRun(
        new ArrayInput(['command' => 'check:domain', '--config' => $configPath]),
        $output
      ),
      $app->doRun(
        new ArrayInput(['command' => 'check:certificate', '--config' => $configPath]),
        $output
      )
    );
  }
}
