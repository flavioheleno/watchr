<?php
declare(strict_types = 1);

namespace Watchr\Console\Commands\Check;

use AcmePhp\Ssl\Certificate;
use AcmePhp\Ssl\Parser\CertificateParser;
use DateTimeInterface;
use Exception;
use Ocsp\CertificateInfo;
use Ocsp\CertificateLoader;
use Ocsp\Ocsp;
use Ocsp\Response;
use Psr\Clock\ClockInterface;
use RuntimeException;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Watchr\Console\Utils\DateUtils;

#[AsCommand('check:certificate', 'Run multiple checks on a certificate chain')]
final class CheckCertificateCommand extends Command {
  private CertificateInfo $certInfo;
  private CertificateLoader $certLoader;
  private CertificateParser $certParser;
  private ClockInterface $clock;
  private Ocsp $ocsp;

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
      'certificateExpirationDate' => (bool)$input->getOption('skip-certificate-expiration-date') === false,
      'certificateFingerprint' => (bool)$input->getOption('skip-certificate-fingerprint') === false,
      'certificateSerialNumber' => (bool)$input->getOption('skip-certificate-serial-number') === false,
      'certificateIssuerName' => (bool)$input->getOption('skip-certificate-issuer-name') === false,
      'certificateOcspRevoked' => (bool)$input->getOption('skip-certificate-ocsp-revoked') === false
    ];

    $certificateExpirationThreshold = (int)$input->getOption('certificate-expiration-threshold');
    $certificateFingerprint = (string)$input->getOption('certificate-fingerprint');
    $certificateSerialNumber = (string)$input->getOption('certificate-serial-number');
    $certificateIssuerName = (string)$input->getOption('certificate-issuer-name');

    $failFast = (bool)$input->getOption('fail-fast');
    $domain = $input->getArgument('domain');

    if ($output->isDebug() === true) {
      $output->writeln('');
      $table = new Table($output);
      $table
        ->setHeaders(['Verification', 'Status'])
        ->addRows(
          [
            [
              'Certificate Expiration Date',
              ($checks['certificateExpirationDate'] ? '<fg=green>enabled</>' : '<fg=red>disabled</>')
            ],
            [
              'Certificate Fingerprint',
              ($checks['certificateFingerprint'] ? '<fg=green>enabled</>' : '<fg=red>disabled</>')
            ],
            [
              'Certificate Serial Number',
              ($checks['certificateSerialNumber'] ? '<fg=green>enabled</>' : '<fg=red>disabled</>')
            ],
            [
              'Certificate Issuer Name',
              ($checks['certificateIssuerName'] ? '<fg=green>enabled</>' : '<fg=red>disabled</>')
            ],
            [
              'Certificate OCSP Revoked',
              ($checks['certificateOcspRevoked'] ? '<fg=green>enabled</>' : '<fg=red>disabled</>')
            ]
          ]
        )
        ->render();

      $output->writeln('');
    }

    $errors = [];
    if ($checks['certificateFingerprint'] === true && trim($certificateFingerprint) === '') {
      $errors[] = '<options=bold>--certificate-fingerprint</> option is required unless <options=bold>--skip-certificate-fingerprint</> is set';
    }

    if ($checks['certificateSerialNumber'] === true && trim($certificateSerialNumber) === '') {
      $errors[] = '<options=bold>--certificate-serial-number</> option is required unless <options=bold>--skip-certificate-serial-number</> is set';
    }

    if ($checks['certificateIssuerName'] === true && trim($certificateIssuerName) === '') {
      $errors[] = '<options=bold>--certificate-issuer-name</> option is required unless <options=bold>--skip-certificate-issuer-name</> is set';
    }

    if (filter_var($domain, FILTER_VALIDATE_DOMAIN, ['flags' => FILTER_FLAG_HOSTNAME]) === false) {
      $errors[] = 'argument <options=bold>domain</> contains an invalid domain name';
    }

    if (count($errors) > 0) {
      $this->printErrors($errors, $output);

      return Command::FAILURE;
    }

    $needCertificate = (
      $checks['certificateOcspRevoked'] ||
      $checks['certificateExpirationDate'] ||
      $checks['certificateFingerprint'] ||
      $checks['certificateSerialNumber'] ||
      $checks['certificateIssuerName']
    );

    if ($needCertificate === false) {
      return Command::SUCCESS;
    }

    // required for expiration checks
    $now = $this->clock->now();

    $output->writeln(
      'Starting certificate checks',
      OutputInterface::VERBOSITY_DEBUG
    );

    try {
      $hCurl = curl_init("https://{$domain}/");
      curl_setopt($hCurl, CURLOPT_RETURNTRANSFER, false);
      curl_setopt($hCurl, CURLOPT_CUSTOMREQUEST, 'HEAD');
      curl_setopt($hCurl, CURLOPT_NOBODY, true);
      curl_setopt($hCurl, CURLOPT_CERTINFO, true);
      curl_exec($hCurl);
      if (curl_errno($hCurl) > 0) {
        $curlError = curl_error($hCurl);
        curl_close($hCurl);

        throw new RuntimeException($curlError);
      }

      $certInfo = curl_getinfo($hCurl, CURLINFO_CERTINFO);
      curl_close($hCurl);

      if ($certInfo === false || $certInfo === []) {
        throw new RuntimeException(
          sprintf(
            'Failed to retrieve the certificate for domain "%s"',
            $domain
          )
        );
      }

      $output->writeln(
        sprintf(
          'Certificate chain size: <options=bold>%d</>',
          count($certInfo)
        ),
        OutputInterface::VERBOSITY_DEBUG
      );

      // build the certificate chain to be parsed
      $certChain = array_reduce(
        array_reverse(
          array_map(
            static function (array $certificate): string {
              return $certificate['Cert'];
            },
            $certInfo
          )
        ),
        static function (Certificate|null $issuer, string $certificate): Certificate {
          if ($issuer === null) {
            return new Certificate($certificate);
          }

          return new Certificate($certificate, $issuer);
        },
        null
      );

      $parsedCertificate = $this->certParser->parse($certChain);
      if (
        $domain !== $parsedCertificate->getSubject() &&
        in_array($domain, $parsedCertificate->getSubjectAlternativeNames(), true) === false
      ) {
        $errors[] = sprintf(
          'Domain "%s" does not match the certificate subject (%s) or any of the alternative names (%s)',
          $domain,
          $parsedCertificate->getSubject(),
          implode(', ', $parsedCertificate->getSubjectAlternativeNames())
        );

        if ($failFast === true) {
          $this->printErrors($errors, $output);

          return Command::FAILURE;
        }
      }

      if ($checks['certificateExpirationDate'] === true) {
        $output->writeln(
          sprintf(
            'Certificate expiration date: <options=bold>%s</>',
            $parsedCertificate->getValidTo()->format(DateTimeInterface::ATOM),
          ),
          OutputInterface::VERBOSITY_DEBUG
        );

        $interval = $now->diff($parsedCertificate->getValidTo());
        if ($interval->days <= 0) {
          $errors[] = sprintf(
            'Certificate for domain "%s" expired %s ago',
            $domain,
            DateUtils::timeAgo($interval)
          );

          if ($failFast === true) {
            $this->printErrors($errors, $output);

            return Command::FAILURE;
          }
        }

        if ($interval->days <= $certificateExpirationThreshold) {
          $errors[] = sprintf(
            'Certificate for domain "%s" will expire in %d days (threshold: %d)',
            $domain,
            $interval->days,
            $certificateExpirationThreshold
          );

          if ($failFast === true) {
            $this->printErrors($errors, $output);

            return Command::FAILURE;
          }
        }

        $output->writeln(
          sprintf(
            'Certificate expires in: <options=bold>%d days</>',
            $interval->days
          ),
          OutputInterface::VERBOSITY_DEBUG
        );
      }

      if ($checks['certificateFingerprint'] === true) {
        $fingerprint = openssl_x509_fingerprint($certInfo[0]['Cert'], 'sha-256');
        if ($fingerprint === false) {
          $errors[] = 'Failed to calculate the Certificate\'s Fingerprint';

          if ($failFast === true) {
            $this->printErrors($errors, $output);

            return Command::FAILURE;
          }
        }

        $output->writeln(
          sprintf(
            'Certificate Fingerprint: <options=bold>%s</>',
            $fingerprint
          ),
          OutputInterface::VERBOSITY_DEBUG
        );

        if ($fingerprint !== $certificateFingerprint) {
          $errors[] = sprintf(
            'Certificate fingerprint for domain "%s" does not match the expected "%s", found: "%s"',
            $domain,
            $certificateFingerprint,
            $fingerprint
          );

          if ($failFast === true) {
            $this->printErrors($errors, $output);

            return Command::FAILURE;
          }
        }
      }

      if ($checks['certificateSerialNumber'] === true) {
        if ($parsedCertificate->getSerialNumber() === null) {
          $errors[] = 'Failed to retrieve the Certificate\'s Serial Number';

          if ($failFast === true) {
            $this->printErrors($errors, $output);

            return Command::FAILURE;
          }
        }

        $output->writeln(
          sprintf(
            'Certificate Serial Number: <options=bold>%s</>',
            $parsedCertificate->getSerialNumber()
          ),
          OutputInterface::VERBOSITY_DEBUG
        );

        if ($parsedCertificate->getSerialNumber() !== $certificateSerialNumber) {
          $errors[] = sprintf(
            'Certificate Serial Number for domain "%s" does not match the expected "%s", found: "%s"',
            $domain,
            $certificateSerialNumber,
            $parsedCertificate->getSerialNumber()
          );

          if ($failFast === true) {
            $this->printErrors($errors, $output);

            return Command::FAILURE;
          }
        }
      }

      if ($checks['certificateIssuerName'] === true) {
        if ($parsedCertificate->getIssuer() === null) {
          $errors[] = 'Failed to retrieve the Certificate\'s Issuer Name';

          if ($failFast === true) {
            $this->printErrors($errors, $output);

            return Command::FAILURE;
          }
        }

        $output->writeln(
          sprintf(
            'Certificate Issuer Name: <options=bold>%s</>',
            $parsedCertificate->getIssuer()
          ),
          OutputInterface::VERBOSITY_DEBUG
        );

        if ($parsedCertificate->getIssuer() !== $certificateIssuerName) {
          $errors[] = sprintf(
            'Certificate Issuer Name for domain "%s" does not match the expected "%s", found: "%s"',
            $domain,
            $certificateIssuerName,
            $parsedCertificate->getIssuer()
          );

          if ($failFast === true) {
            $this->printErrors($errors, $output);

            return Command::FAILURE;
          }
        }
      }

      if ($checks['certificateOcspRevoked'] === true) {
        $certificate = $this->certLoader->fromString($certInfo[0]['Cert']);
        $issuerCertificate = $this->certLoader->fromString($certInfo[1]['Cert']);
        $ocspResponderUrl = $this->certInfo->extractOcspResponderUrl($certificate);

        $requestInfo = $this->certInfo->extractRequestInfo($certificate, $issuerCertificate);
        $requestBody = $this->ocsp->buildOcspRequestBodySingle($requestInfo);

        $hCurl = curl_init();
        curl_setopt($hCurl, CURLOPT_URL, $ocspResponderUrl);
        curl_setopt($hCurl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($hCurl, CURLOPT_POST, true);
        curl_setopt($hCurl, CURLOPT_HTTPHEADER, ['Content-Type: ' . Ocsp::OCSP_REQUEST_MEDIATYPE]);
        curl_setopt($hCurl, CURLOPT_SAFE_UPLOAD, true);
        curl_setopt($hCurl, CURLOPT_POSTFIELDS, $requestBody);
        $result = curl_exec($hCurl);
        if (curl_errno($hCurl) > 0) {
          $curlError = curl_error($hCurl);
          curl_close($hCurl);

          throw new RuntimeException($curlError);
        }


        curl_close($hCurl);

        $info = curl_getinfo($hCurl);
        if ($info['http_code'] !== 200) {
            throw new \RuntimeException("Whoops, here we'd expect a 200 HTTP code");
        }
        if ($info['content_type'] !== Ocsp::OCSP_RESPONSE_MEDIATYPE) {
            throw new \RuntimeException("Whoops, the Content-Type header of the response seems wrong!");
        }

        // Decode the raw response from the OCSP Responder
        $response = $this->ocsp->decodeOcspResponseSingle($result);

        if ($response->isRevoked() === null) {
          $errors[] = sprintf(
            'Certificate for domain "%s" OCSP revocation state is unknown',
            $domain
          );

          if ($failFast === true) {
            $this->printErrors($errors, $output);

            return Command::FAILURE;
          }
        }

        if ($response->isRevoked() === true) {
          $reason = match ($response->getRevocationReason()) {
            Response::REVOCATIONREASON_UNSPECIFIED => 'unspecified',
            Response::REVOCATIONREASON_KEYCOMPROMISE => 'key compromise',
            Response::REVOCATIONREASON_CACOMPROMISE => 'CA Compromise',
            Response::REVOCATIONREASON_AFFILIATIONCHANGED => 'affiliation changed',
            Response::REVOCATIONREASON_SUPERSEDED => 'superseded',
            Response::REVOCATIONREASON_CESSATIONOFOPERATION => 'cessation of operation',
            Response::REVOCATIONREASON_CERTIFICATEHOLD => 'certificate hold',
            Response::REVOCATIONREASON_REMOVEFROMCRL => 'remove from CRL',
            Response::REVOCATIONREASON_PRIVILEGEWITHDRAWN => 'privilege withdrawn',
            Response::REVOCATIONREASON_AACOMPROMISE => 'AA compromise',
            default => 'unknown'
          };

          $errors[] = sprintf(
            'Certificate for domain "%s" was revoked on %s (reason: %s)',
            $domain,
            $response->getRevokedOn(),
            $reason
          );

          if ($failFast === true) {
            $this->printErrors($errors, $output);

            return Command::FAILURE;
          }
        }

        $interval = $now->diff($response->getThisUpdate());
        $output->writeln(
          sprintf(
            'OCSP Revocation list last update: <options=bold>%s</> (%s)',
            DateUtils::timeAgo($interval),
            $response->getThisUpdate()->format(DateTimeInterface::ATOM)
          ),
          OutputInterface::VERBOSITY_DEBUG
        );
      }
    } catch (Exception $exception) {
      $errors[] = $exception->getMessage();

      if ($failFast === true) {
        $this->printErrors($errors, $output);

        return Command::FAILURE;
      }
    }

    $output->writeln(
      'Finished certificate checks',
      OutputInterface::VERBOSITY_DEBUG
    );

    if (count($errors) > 0) {
      $this->printErrors($errors, $output);

      return Command::FAILURE;
    }

    return Command::SUCCESS;
  }

  public function __construct(
    CertificateInfo $certInfo,
    CertificateLoader $certLoader,
    CertificateParser $certParser,
    ClockInterface $clock,
    Ocsp $ocsp
  ) {
    parent::__construct();

    $this->certInfo = $certInfo;
    $this->certLoader = $certLoader;
    $this->certParser = $certParser;
    $this->clock = $clock;
    $this->ocsp = $ocsp;
  }
}
