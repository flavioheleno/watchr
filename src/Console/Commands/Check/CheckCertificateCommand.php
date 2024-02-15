<?php
declare(strict_types = 1);

namespace Watchr\Console\Commands\Check;

use AcmePhp\Ssl\Certificate;
use AcmePhp\Ssl\Parser\CertificateParser;
use DateTimeInterface;
use Exception;
use InvalidArgumentException;
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
use Watchr\Console\Traits\DateUtilsTrait;
use Watchr\Console\Traits\ErrorPrinterTrait;

#[AsCommand('check:certificate', 'Run multiple checks on a certificate chain')]
final class CheckCertificateCommand extends Command {
  use DateUtilsTrait;
  use ErrorPrinterTrait;

  private CertificateInfo $certInfo;
  private CertificateLoader $certLoader;
  private CertificateParser $certParser;
  private ClockInterface $clock;
  private Ocsp $ocsp;

  /**
   * @param string[] $haystack
   */
  private function subjectMatch(string $needle, array $haystack): bool {
    $needleParts = explode('.', $needle);
    array_shift($needleParts); // remove the host from $needle
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
        InputOption::VALUE_REQUIRED,
        'Match the certificate SHA-256 Fingerprint'
      )
      ->addOption(
        'serial-number',
        's',
        InputOption::VALUE_REQUIRED,
        'Match the certificate Serial Number'
      )
      ->addOption(
        'issuer-name',
        'i',
        InputOption::VALUE_REQUIRED,
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
    $fingerprint = (string)$input->getOption('fingerprint');
    $serialNumber = (string)$input->getOption('serial-number');
    $issuerName = (string)$input->getOption('issuer-name');

    $checks = [
      'expirationDate' => $expirationThreshold > 0,
      'fingerprint' => $fingerprint !== '',
      'serialNumber' => $serialNumber !== '',
      'issuerName' => $issuerName !== '',
      'ocspRevoked' => (bool)$input->getOption('skip-ocsp-revoked') === false
    ];

    $failFast = (bool)$input->getOption('fail-fast');
    $domain = $input->getArgument('domain');

    $errors = [];
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
                $fingerprint ?: '-'
              ],
              [
                'Serial Number',
                ($checks['serialNumber'] ? '<fg=green>enabled</>' : '<fg=red>disabled</>'),
                $serialNumber ?: '-'
              ],
              [
                'Issuer Name',
                ($checks['issuerName'] ? '<fg=green>enabled</>' : '<fg=red>disabled</>'),
                $issuerName ?: '-'
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
        OutputInterface::VERBOSITY_VERBOSE
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
      $listOfSubjects = [
        $parsedCertificate->getSubject(),
        ...$parsedCertificate->getSubjectAlternativeNames()
      ];
      if ($this->subjectMatch($domain, $listOfSubjects) === false) {
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

      if ($checks['expirationDate'] === true) {
        $output->writeln(
          sprintf(
            'Certificate expiration date: <options=bold>%s</>',
            $parsedCertificate->getValidTo()->format(DateTimeInterface::ATOM),
          ),
          OutputInterface::VERBOSITY_VERBOSE
        );

        $interval = $now->diff($parsedCertificate->getValidTo());
        if ($interval->days <= 0) {
          $errors[] = sprintf(
            'Certificate for domain "%s" expired %s ago',
            $domain,
            $this->humanReadableInterval($interval)
          );

          if ($failFast === true) {
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
        $certFingerprint = openssl_x509_fingerprint($certInfo[0]['Cert'], 'sha-256');
        if ($certFingerprint === false) {
          $errors[] = 'Failed to calculate the Certificate\'s Fingerprint';

          if ($failFast === true) {
            $this->printErrors($errors, $output);

            return Command::FAILURE;
          }
        }

        $output->writeln(
          sprintf(
            'Certificate Fingerprint: <options=bold>%s</>',
            $certFingerprint
          ),
          OutputInterface::VERBOSITY_VERBOSE
        );

        if ($fingerprint !== $certFingerprint) {
          $errors[] = sprintf(
            'Certificate fingerprint for domain "%s" does not match the expected "%s", found: "%s"',
            $domain,
            $fingerprint,
            $certFingerprint
          );

          if ($failFast === true) {
            $this->printErrors($errors, $output);

            return Command::FAILURE;
          }
        }
      }

      if ($checks['serialNumber'] === true) {
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
          OutputInterface::VERBOSITY_VERBOSE
        );

        if ($parsedCertificate->getSerialNumber() !== $serialNumber) {
          $errors[] = sprintf(
            'Certificate Serial Number for domain "%s" does not match the expected "%s", found: "%s"',
            $domain,
            $serialNumber,
            $parsedCertificate->getSerialNumber()
          );

          if ($failFast === true) {
            $this->printErrors($errors, $output);

            return Command::FAILURE;
          }
        }
      }

      if ($checks['issuerName'] === true) {
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
          OutputInterface::VERBOSITY_VERBOSE
        );

        if ($parsedCertificate->getIssuer() !== $issuerName) {
          $errors[] = sprintf(
            'Certificate Issuer Name for domain "%s" does not match the expected "%s", found: "%s"',
            $domain,
            $issuerName,
            $parsedCertificate->getIssuer()
          );

          if ($failFast === true) {
            $this->printErrors($errors, $output);

            return Command::FAILURE;
          }
        }
      }

      if ($checks['ocspRevoked'] === true) {
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
            $this->humanReadableInterval($interval),
            $response->getThisUpdate()->format(DateTimeInterface::ATOM)
          ),
          OutputInterface::VERBOSITY_VERBOSE
        );
      }
    } catch (Exception $exception) {
      $errors[] = $exception->getMessage();
      if ($output->isDebug() === true) {
        $errors[] = $exception->getTraceAsString();
      }

      $this->printErrors($errors, $output);

      return Command::FAILURE;
    }

    $output->writeln(
      'Finished certificate checks',
      OutputInterface::VERBOSITY_VERBOSE
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
