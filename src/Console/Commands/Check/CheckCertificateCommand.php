<?php
declare(strict_types = 1);

namespace Watchr\Console\Commands\Check;

use DateTimeInterface;
use Exception;
use InvalidArgumentException;
use Psr\Clock\ClockInterface;
use RuntimeException;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Watchr\Console\Services\CertificateService;
use Watchr\Console\Traits\DateUtilsTrait;
use Watchr\Console\Traits\ErrorPrinterTrait;

#[AsCommand('check:certificate', 'Run multiple checks on a certificate chain')]
final class CheckCertificateCommand extends Command {
  use DateUtilsTrait;
  use ErrorPrinterTrait;

  private CertificateService $certificateService;
  private ClockInterface $clock;

  /**
   * @param string[] $haystack
   */
  private function subjectMatch(string $needle, array $haystack): bool {
    // remove the host from $needle
    $needleParts = array_slice(explode('.', $needle), 1);
    foreach ($haystack as $candidate) {
      if ($needle === $candidate) {
        return true;
      }

      if (str_starts_with($candidate, '*.') === true) {
        $candidateParts = explode('.', substr($candidate, 2));

        if ($needleParts === $candidateParts) {
          return true;
        }
      }
    }

    return false;
  }

  protected function configure(): void {
    $this
      ->addOption(
        'expiration-threshold',
        'e',
        InputOption::VALUE_REQUIRED,
        'Number of days until the certification expiration date',
        5
      )
      ->addOption(
        'fingerprint',
        'p',
        InputOption::VALUE_IS_ARRAY | InputOption::VALUE_REQUIRED,
        'Match the certificate SHA-256 Fingerprint'
      )
      ->addOption(
        'serial-number',
        's',
        InputOption::VALUE_IS_ARRAY | InputOption::VALUE_REQUIRED,
        'Match the certificate Serial Number'
      )
      ->addOption(
        'issuer-name',
        'i',
        InputOption::VALUE_IS_ARRAY | InputOption::VALUE_REQUIRED,
        'Match the Certificate Authority (CA) that issued the TLS Certificate'
      )
      ->addOption(
        'skip-ocsp-revoked',
        'o',
        InputOption::VALUE_NONE,
        'Skip Certificate OCSP revocation validation'
      )
      ->addOption(
        'fail-fast',
        'f',
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
    $expirationThreshold = (int)$input->getOption('expiration-threshold');
    $fingerprints = (array)$input->getOption('fingerprint');
    $serialNumbers = (array)$input->getOption('serial-number');
    $issuerNames = (array)$input->getOption('issuer-name');

    $checks = [
      'expirationDate' => $expirationThreshold > 0,
      'fingerprint' => empty($fingerprints) === false && function_exists('openssl_x509_fingerprint') === true,
      'serialNumber' => empty($serialNumbers) === false,
      'issuerName' => empty($issuerNames) === false,
      'ocspRevoked' => (bool)$input->getOption('skip-ocsp-revoked') === false
    ];

    $failFast = (bool)$input->getOption('fail-fast');
    $domain = $input->getArgument('domain');

    $errors = [];
    $warnings = [];
    try {
      if (
        strpos($domain, '.') === false ||
        filter_var($domain, FILTER_VALIDATE_DOMAIN, ['flags' => FILTER_FLAG_HOSTNAME]) === false
      ) {
        throw new InvalidArgumentException('argument domain must be a valid domain name');
      }

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
                $expirationThreshold > 0 ? "{$expirationThreshold} days" : '-'
              ],
              [
                'SHA-256 Fingerprint',
                ($checks['fingerprint'] ? '<fg=green>enabled</>' : '<fg=red>disabled</>'),
                empty($fingerprints) ? '-' : implode(', ', $fingerprints)
              ],
              [
                'Serial Number',
                ($checks['serialNumber'] ? '<fg=green>enabled</>' : '<fg=red>disabled</>'),
                empty($serialNumbers) ? '-' : implode(', ', $serialNumbers)
              ],
              [
                'Issuer Name',
                ($checks['issuerName'] ? '<fg=green>enabled</>' : '<fg=red>disabled</>'),
                empty($issuerNames) ? '-' : implode(', ', $issuerNames)
              ],
              [
                'OCSP Revoked',
                ($checks['ocspRevoked'] ? '<fg=green>enabled</>' : '<fg=red>disabled</>'),
                '-'
              ]
            ]
          )
          ->render();

        $output->writeln('');
      }

      $needCertificate = (
        $checks['expirationDate'] ||
        $checks['fingerprint'] ||
        $checks['serialNumber'] ||
        $checks['issuerName'] ||
        $checks['ocspRevoked']
      );

      if ($needCertificate === false) {
        $output->writeln(
          'All certificate verifications are disabled, leaving',
          OutputInterface::VERBOSITY_VERBOSE
        );

        return Command::SUCCESS;
      }

      // required for expiration checks
      $now = $this->clock->now();

      $output->writeln(
        'Starting certificate checks',
        OutputInterface::VERBOSITY_VERBOSE
      );

      $chain = $this->certificateService->get($domain);
      $cert0 = $chain->at(0);

      $output->writeln(
        sprintf(
          'Certificate chain size: <options=bold>%d</>',
          count($chain)
        ),
        OutputInterface::VERBOSITY_VERBOSE
      );

      if (
        $domain !== $cert0->subjectCommonName &&
        $this->subjectMatch($domain, $cert0->subjectAlternativeNames) === false
      ) {
        $errors[] = sprintf(
          'Domain "%s" does not match the certificate subject (%s) or any of the alternative names (%s)',
          $domain,
          $cert0->subjectCommonName,
          implode(', ', $cert0->subjectAlternativeNames)
        );

        if ($failFast === true) {
          $this->printWarnings($warnings, $output);
          $this->printErrors($errors, $output);

          return Command::FAILURE;
        }
      }

      if ($checks['expirationDate'] === true) {
        $output->writeln(
          sprintf(
            'Certificate expiration date: <options=bold>%s</>',
            $cert0->validTo->format(DateTimeInterface::ATOM),
          ),
          OutputInterface::VERBOSITY_VERBOSE
        );

        $interval = $now->diff($cert0->validTo);
        if ($interval->days <= 0) {
          $errors[] = sprintf(
            'Certificate for domain "%s" expired %s ago',
            $domain,
            $this->humanReadableInterval($interval)
          );

          if ($failFast === true) {
            $this->printWarnings($warnings, $output);
            $this->printErrors($errors, $output);

            return Command::FAILURE;
          }
        }

        if ($interval->days <= $expirationThreshold) {
          $errors[] = sprintf(
            'Certificate for domain "%s" will expire in %d days (threshold: %d)',
            $domain,
            $interval->days,
            $expirationThreshold
          );

          if ($failFast === true) {
            $this->printWarnings($warnings, $output);
            $this->printErrors($errors, $output);

            return Command::FAILURE;
          }
        }

        $output->writeln(
          sprintf(
            'Certificate expires in: <options=bold>%d days</>',
            $interval->days
          ),
          OutputInterface::VERBOSITY_VERBOSE
        );
      }


      if ($checks['fingerprint'] === true) {
        if (count($fingerprints) > count($chain)) {
          $warnings[] = sprintf(
            'Fingerprint list is %d items long, but the chain is only %d items long',
            count($fingerprints),
            count($chain)
          );
        }

        foreach ($chain as $index => $cert) {
          if (isset($fingerprints[$index]) === false) {
            // skip if a fingerprint was not given
            continue;
          }

          $output->writeln(
            sprintf(
              'Certificate Fingerprint: <options=bold>%s</>',
              $cert->sha256Fingerprint
            ),
            OutputInterface::VERBOSITY_VERBOSE
          );

          if ($cert->sha256Fingerprint !== $fingerprints[$index]) {
            $errors[] = sprintf(
              'Certificate #%d Fingerprint does not match the expected "%s", found: "%s"',
              $index,
              $fingerprints[$index],
              $cert->sha256Fingerprint
            );

            if ($failFast === true) {
              $this->printWarnings($warnings, $output);
              $this->printErrors($errors, $output);

              return Command::FAILURE;
            }
          }
        }
      }

      if ($checks['serialNumber'] === true) {
        if (count($serialNumbers) > count($chain)) {
          $warnings[] = sprintf(
            'Serial Number list is %d items long, but the chain is only %d items long',
            count($serialNumbers),
            count($chain)
          );
        }

        foreach ($chain as $index => $cert) {
          if (isset($serialNumbers[$index]) === false) {
            // skip if a serial number was not given
            continue;
          }

          if ($cert->serialNumber === null) {
            $errors[] = "Failed to retrieve Certificate\'s Serial Number for certificate #{$index} in chain";

            if ($failFast === true) {
              $this->printWarnings($warnings, $output);
              $this->printErrors($errors, $output);

              return Command::FAILURE;
            }
          }

          $output->writeln(
            sprintf(
              'Certificate Serial Number: <options=bold>%s</>',
              $cert->serialNumber
            ),
            OutputInterface::VERBOSITY_VERBOSE
          );

          if ($cert->serialNumber !== $serialNumbers[$index]) {
            $errors[] = sprintf(
              'Certificate #%d Serial Number does not match the expected "%s", found: "%s"',
              $index,
              $serialNumbers[$index],
              $cert->serialNumber
            );

            if ($failFast === true) {
              $this->printWarnings($warnings, $output);
              $this->printErrors($errors, $output);

              return Command::FAILURE;
            }
          }
        }
      }

      if ($checks['issuerName'] === true) {
        if (count($issuerNames) > count($chain)) {
          $warnings[] = sprintf(
            'Issuer Name list is %d items long, but the chain is only %d items long',
            count($issuerNames),
            count($chain)
          );
        }

        foreach ($chain as $index => $cert) {
          if (isset($issuerNames[$index]) === false) {
            // skip if a issuer name was not given
            continue;
          }

          if ($cert->issuerOrganization === null && $cert->issuerCommonName === null) {
            $errors[] = "Failed to retrieve the Certificate\'s Issuer Name for certificate #{$index} in chain";

            if ($failFast === true) {
              $this->printWarnings($warnings, $output);
              $this->printErrors($errors, $output);

              return Command::FAILURE;
            }
          }

          $output->writeln(
            sprintf(
              'Certificate Issuer Name: <options=bold>%s</>',
              $cert->issuerOrganization ?? $cert->issuerCommonName
            ),
            OutputInterface::VERBOSITY_VERBOSE
          );

          if (
            $cert->issuerOrganization !== $issuerNames[$index] &&
            $cert->issuerCommonName !== $issuerNames[$index]
          ) {
            $errors[] = sprintf(
              'Certificate #%d Issuer Name does not match the expected "%s", found: "%s"',
              $index,
              $issuerNames[$index],
              $cert->issuerOrganization ?? $cert->issuerCommonName
            );

            if ($failFast === true) {
              $this->printWarnings($warnings, $output);
              $this->printErrors($errors, $output);

              return Command::FAILURE;
            }
          }
        }
      }

      if ($checks['ocspRevoked'] === true) {
        $status = $this->certificateService->status($chain);

        if ($status->isRevoked()) {
          $errors[] = sprintf(
            'Certificate for domain "%s" was revoked on %s (reason: %s)',
            $domain,
            $status->revokedOn,
            $status->revocationReason
          );

          if ($failFast === true) {
            $this->printWarnings($warnings, $output);
            $this->printErrors($errors, $output);

            return Command::FAILURE;
          }
        }

        $interval = $now->diff($status->lastUpdate);
        $output->writeln(
          sprintf(
            'OCSP Revocation list last update: <options=bold>%s</> (%s)',
            $this->humanReadableInterval($interval),
            $status->lastUpdate->format(DateTimeInterface::ATOM)
          ),
          OutputInterface::VERBOSITY_VERBOSE
        );
      }
    } catch (Exception $exception) {
      $errors[] = $exception->getMessage();
      if ($output->isDebug() === true) {
        $errors[] = $exception->getTraceAsString();
      }

      $this->printWarnings($warnings, $output);
      $this->printErrors($errors, $output);

      return Command::FAILURE;
    }

    $output->writeln(
      'Finished certificate checks',
      OutputInterface::VERBOSITY_VERBOSE
    );

    $this->printWarnings($warnings, $output);
    if (count($errors) > 0) {
      $this->printErrors($errors, $output);

      return Command::FAILURE;
    }

    return Command::SUCCESS;
  }

  public function __construct(
    CertificateService $certificateService,
    ClockInterface $clock
  ) {
    parent::__construct();

    $this->certificateService = $certificateService;
    $this->clock = $clock;
  }
}
