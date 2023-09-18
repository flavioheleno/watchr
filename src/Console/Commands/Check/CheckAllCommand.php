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
        'domain-expiration-threshold',
        null,
        InputOption::VALUE_REQUIRED,
        'Number of days until the domain expiration date',
        5
      )
      ->addOption(
        'registrar-name',
        null,
        InputOption::VALUE_REQUIRED,
        'Match the name of the company where the domain has been registered'
      )
      ->addOption(
        'status-codes',
        null,
        InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY,
        'List of Extensible Provisioning Protocol (EPP) status codes that should be active',
        ['clientTransferProhibited']
      )
      ->addOption(
        'skip-certificate-checks',
        null,
        InputOption::VALUE_NONE,
        'Skips all certificate related validations'
      )
      ->addOption(
        'certificate-expiration-threshold',
        null,
        InputOption::VALUE_REQUIRED,
        'Number of days until the certification expiration date',
        5
      )
      ->addOption(
        'fingerprint',
        null,
        InputOption::VALUE_REQUIRED,
        'Match the certificate SHA-256 Fingerprint'
      )
      ->addOption(
        'serial-number',
        null,
        InputOption::VALUE_REQUIRED,
        'Match the certificate Serial Number'
      )
      ->addOption(
        'issuer-name',
        null,
        InputOption::VALUE_REQUIRED,
        'Match the Certificate Authority (CA) that issued the TLS Certificate'
      )
      ->addOption(
        'skip-ocsp-revoked',
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
    // check:domain options
    $domainExpirationThreshold = (int)$input->getOption('domain-expiration-threshold');
    $registrarName = (string)$input->getOption('registrar-name');
    $statusCodes = (array)$input->getOption('status-codes');

    // check:certificate options
    $certificateExpirationThreshold = (int)$input->getOption('certificate-expiration-threshold');
    $fingerprint = (string)$input->getOption('fingerprint');
    $serialNumber = (string)$input->getOption('serial-number');
    $issuerName = (string)$input->getOption('issuer-name');

    $checks = [
      'domainExpirationDate' => $domainExpirationThreshold > 0,
      'domainRegistrarName' => $registrarName !== '',
      'domainStatusCodes' => $statusCodes !== [],
      'certificateExpirationDate' => $certificateExpirationThreshold > 0,
      'certificateFingerprint' => $fingerprint !== '',
      'certificateSerialNumber' => $serialNumber !== '',
      'certificateIssuerName' => $issuerName !== '',
      'certificateOcspRevoked' => (bool)$input->getOption('skip-ocsp-revoked') === false
    ];

    // skips all domain related validations
    if ((bool)$input->getOption('skip-domain-checks') === true) {
      $output->writeln(
        'Disabling domain checks (--skip-domain-checks)',
        OutputInterface::VERBOSITY_DEBUG
      );

      $checks['domainExpirationDate'] = false;
      $checks['domainRegistrarName'] = false;
      $checks['domainStatusCodes'] = false;
    }

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


    $failFast = (bool)$input->getOption('fail-fast');
    $domain = $input->getArgument('domain');

    $returnCode = Command::SUCCESS;

    if (
      $checks['domainExpirationDate'] ||
      $checks['domainRegistrarName'] ||
      $checks['domainStatusCodes']
    ) {
      $domainInput = new ArrayInput(
        [
          'command' => 'check:domain',
          'domain' => $domain,
          '--fail-fast' => $failFast,
          '--expiration-threshold' => $domainExpirationThreshold,
          '--registrar-name' => $registrarName,
          '--status-codes' => $statusCodes
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
          '--skip-ocsp-revoked' => !$checks['certificateOcspRevoked'],
          '--expiration-threshold' => $certificateExpirationThreshold,
          '--fingerprint' => $fingerprint,
          '--serial-number' => $serialNumber,
          '--issuer-name' => $issuerName
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
