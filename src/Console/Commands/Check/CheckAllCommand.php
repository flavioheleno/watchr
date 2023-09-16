<?php
declare(strict_types = 1);

namespace Watchr\Console\Commands\Check;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand('check:all', 'Run all checks combined')]
final class CheckAllCommand extends Command {
  protected function configure(): void {
    $this
      ->addOption(
        'skip-domain-checks',
        null,
        InputOption::VALUE_NONE,
        'Skips all domain related validations'
      )
      ->addOption(
        'skip-domain-expiration-date',
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
        'skip-domain-registrar-name',
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
        'skip-domain-transfer-prohibited',
        null,
        InputOption::VALUE_NONE,
        'Skip Domain transfer lock status validation'
      )
      ->addOption(
        'skip-certificate-checks',
        null,
        InputOption::VALUE_NONE,
        'Skips all certificate related validations'
      )
      ->addOption(
        'skip-certificate-expiration-date',
        null,
        InputOption::VALUE_NONE,
        'Skip Certificate expiration date validation'
      )
      ->addOption(
        'certificate-expiration-threshold',
        null,
        InputOption::VALUE_REQUIRED,
        'Number of days left to certificate expiration that will trigger an error',
        5
      )
      ->addOption(
        'skip-certificate-fingerprint',
        null,
        InputOption::VALUE_NONE,
        'Skip Certificate Fingerprint validation'
      )
      ->addOption(
        'certificate-fingerprint',
        null,
        InputOption::VALUE_REQUIRED,
        'Certificate\'s Fingerprint'
      )
      ->addOption(
        'skip-certificate-serial-number',
        null,
        InputOption::VALUE_NONE,
        'Skip Certificate Serial Number validation'
      )
      ->addOption(
        'certificate-serial-number',
        null,
        InputOption::VALUE_REQUIRED,
        'Certificate\'s Serial Number'
      )
      ->addOption(
        'skip-certificate-issuer-name',
        null,
        InputOption::VALUE_NONE,
        'Skip Certificate issuer name validation'
      )
      ->addOption(
        'certificate-issuer-name',
        null,
        InputOption::VALUE_REQUIRED,
        'Certificate Authority that issued the TLS Certificate'
      )
      ->addOption(
        'skip-certificate-ocsp-revoked',
        null,
        InputOption::VALUE_NONE,
        'Skip Certificate OCSP revocation validation'
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
      'domainExpirationDate' => (bool)$input->getOption('skip-domain-expiration-date') === false,
      'domainRegistrarName' => (bool)$input->getOption('skip-domain-registrar-name') === false,
      'domainTransferProhibited' => (bool)$input->getOption('skip-domain-transfer-prohibited') === false,
      'certificateExpirationDate' => (bool)$input->getOption('skip-certificate-expiration-date') === false,
      'certificateFingerprint' => (bool)$input->getOption('skip-certificate-fingerprint') === false,
      'certificateSerialNumber' => (bool)$input->getOption('skip-certificate-serial-number') === false,
      'certificateIssuerName' => (bool)$input->getOption('skip-certificate-issuer-name') === false,
      'certificateOcspRevoked' => (bool)$input->getOption('skip-certificate-ocsp-revoked') === false
    ];

    // skips all domain related validations
    if ((bool)$input->getOption('skip-domain-checks') === true) {
      $output->writeln(
        'Disabling domain checks (--skip-domain-checks)',
        OutputInterface::VERBOSITY_DEBUG
      );

      $checks['domainExpirationDate'] = false;
      $checks['domainRegistrarName'] = false;
      $checks['domainTransferProhibited'] = false;
    }

    $domainExpirationThreshold = (int)$input->getOption('domain-expiration-threshold');
    $registrarName = (string)$input->getOption('registrar-name');

    // skips all certificate related validations
    if ((bool)$input->getOption('skip-certificate-checks') === true) {
      $output->writeln(
        'Disabling certificate checks (--skip-certificate-checks)',
        OutputInterface::VERBOSITY_DEBUG
      );

      $checks['certificateExpirationDate'] = false;
      $checks['certificateFingerprint'] = false;
      $checks['certificateSerialNumber'] = false;
      $checks['certificateIssuerName'] = false;
      $checks['certificateOcspRevoked'] = false;
    }

    $certificateExpirationThreshold = (int)$input->getOption('certificate-expiration-threshold');
    $certificateFingerprint = (string)$input->getOption('certificate-fingerprint');
    $certificateSerialNumber = (string)$input->getOption('certificate-serial-number');
    $certificateIssuerName = (string)$input->getOption('certificate-issuer-name');

    $failFast = (bool)$input->getOption('fail-fast');
    $domain = $input->getArgument('domain');

    $returnCode = Command::SUCCESS;

    if (
      $checks['domainExpirationDate'] ||
      $checks['domainRegistrarName'] ||
      $checks['domainTransferProhibited']
    ) {
      $domainInput = new ArrayInput(
        [
          'command' => 'check:domain',
          'domain' => $domain,
          '--fail-fast' => $failFast,
          '--skip-expiration-date' => !$checks['domainExpirationDate'],
          '--skip-registrar-name' => !$checks['domainRegistrarName'],
          '--skip-transfer-prohibited' => !$checks['domainTransferProhibited'],
          '--domain-expiration-threshold' => $domainExpirationThreshold,
          '--registrar-name' => $registrarName
        ]
      );

      $retCode = $this->getApplication()->doRun($domainInput, $output);
      if ($retCode === Command::FAILURE) {
        if ($failFast === true) {
          return Command::FAILURE;
        }

        $returnCode = Command::FAILURE;
      }
    }

    if (
      $checks['certificateExpirationDate'] ||
      $checks['certificateFingerprint'] ||
      $checks['certificateSerialNumber'] ||
      $checks['certificateIssuerName'] ||
      $checks['certificateOcspRevoked']
    ) {
      $certInput = new ArrayInput(
        [
          'command' => 'check:certificate',
          'domain' => $domain,
          '--fail-fast' => $failFast,
          '--skip-expiration-date' => !$checks['certificateExpirationDate'],
          '--skip-fingerprint' => !$checks['certificateFingerprint'],
          '--skip-serial-number' => !$checks['certificateSerialNumber'],
          '--skip-issuer-name' => !$checks['certificateIssuerName'],
          '--skip-ocsp-revoked' => !$checks['certificateOcspRevoked'],
          '--expiration-threshold' => $certificateExpirationThreshold,
          '--fingerprint' => $certificateFingerprint,
          '--serial-number' => $certificateSerialNumber,
          '--issuer-name' => $certificateIssuerName
        ]
      );

      $retCode = $this->getApplication()->doRun($certInput, $output);
      if ($retCode === Command::FAILURE) {
        if ($failFast === true) {
          return Command::FAILURE;
        }

        $returnCode = Command::FAILURE;
      }
    }

    return $returnCode;
  }
}
