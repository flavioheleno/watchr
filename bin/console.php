#!/usr/bin/env php
<?php
declare(strict_types = 1);

date_default_timezone_set('UTC');
setlocale(LC_ALL, 'en_US.UTF8');
error_reporting(E_ALL);

if (in_array(PHP_SAPI, ['cli', 'phpdbg', 'embed'], true) === false) {
  echo PHP_EOL, 'This app may only be invoked from a command-line, got "', PHP_SAPI, '"', PHP_EOL;

  exit(1);
}

require_once dirname(__DIR__) . '/vendor/autoload.php';

use Composer\InstalledVersions;
use DI\ContainerBuilder;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\CommandLoader\ContainerCommandLoader;
use Watchr\Console\Commands\Check\CheckAllCommand;
use Watchr\Console\Commands\Check\CheckCertificateCommand;
use Watchr\Console\Commands\Check\CheckDomainCommand;
use Watchr\Console\Commands\Check\CheckHttpResponseCommand;
use Watchr\Console\Commands\View\ViewDomainCommand;
use Watchr\Console\Commands\View\ViewHttpResponseCommand;

define(
  '__VERSION__',
  sprintf(
    '%s@%s',
    InstalledVersions::getPrettyVersion('flavioheleno/watchr') ?? 'unknown',
    substr(InstalledVersions::getReference('flavioheleno/watchr') ?? 'unknown', 0, 7)
  )
);

// default PHP_ENV to "prod"
if (isset($_ENV['PHP_ENV']) === false) {
  $_ENV['PHP_ENV'] = 'prod';
}

// Instantiate PHP-DI ContainerBuilder
$containerBuilder = new ContainerBuilder();

// Set up dependencies
$dependencies = require_once dirname(__DIR__) . '/config/dependencies.php';
$dependencies($containerBuilder);

// Build PHP-DI Container instance
$container = $containerBuilder->build();

$app = new Application('watchr command-line utility', __VERSION__);
$app->setCommandLoader(
  new ContainerCommandLoader(
    $container,
    [
      CheckAllCommand::getDefaultName() => CheckAllCommand::class,
      CheckCertificateCommand::getDefaultName() => CheckCertificateCommand::class,
      CheckDomainCommand::getDefaultName() => CheckDomainCommand::class,
      CheckHttpResponseCommand::getDefaultName() => CheckHttpResponseCommand::class,
      ViewDomainCommand::getDefaultName() => ViewDomainCommand::class,
      ViewHttpResponseCommand::getDefaultName() => ViewHttpResponseCommand::class
    ]
  )
);

$app->run();
