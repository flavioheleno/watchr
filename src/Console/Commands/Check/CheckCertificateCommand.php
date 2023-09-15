<?php
declare(strict_types = 1);

namespace Watchr\Console\Commands\Check;

use AcmePhp\Ssl\Certificate;
use AcmePhp\Ssl\Parser\CertificateParser;
use DateTimeInterface;
use Exception;
use InvalidArgumentException;
use League\Config\Configuration;
use Ocsp\CertificateInfo;
use Ocsp\CertificateLoader;
use Ocsp\Ocsp;
use Ocsp\Response;
use Psr\Clock\ClockInterface;
use RuntimeException;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Watchr\Console\Utils\DateUtils;

#[AsCommand('check:certificate', 'Run multiple checks on a certificate chain')]
final class CheckCertificateCommand extends Command {
  private Configuration $config;
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

    $contents = file_get_contents($configPath);
    if ($contents === false) {
      throw new RuntimeException('Failed to read configuration file contents');
    }

    $this->config->merge(json_decode($contents, true, flags: JSON_THROW_ON_ERROR));

    $subject = $this->config->get('subject');

    $output->writeln(
      sprintf(
        'Subject: <options=bold>%s</>',
        $subject
      ),
      OutputInterface::VERBOSITY_VERBOSE
    );

    if ((bool)$this->config->get('certificate.enabled') === false) {
      $output->writeln(
        'Certificate check is disabled, leaving',
        OutputInterface::VERBOSITY_VERBOSE
      );

      return Command::SUCCESS;
    }

    $checks = [
      'expirationDate' => true,
      'sha1Fingerprint' => true,
      'sha256Fingerprint' => true,
      'serialNumber' => true,
      'issuerName' => true,
      'ocspRevoked' => (bool)$this->config->get('certificate.ocspRevoked')
    ];

    $expirationThreshold = (int)$this->config->get('certificate.expirationThreshold');
    if ($expirationThreshold === -1) {
      $checks['expirationDate'] = false;
    }

    $sha1Fingerprint = (string)$this->config->get('certificate.sha1Fingerprint');
    if ($sha1Fingerprint === '') {
      $checks['sha1Fingerprint'] = false;
    }

    $sha256Fingerprint = (string)$this->config->get('certificate.sha256Fingerprint');
    if ($sha256Fingerprint === '') {
      $checks['sha256Fingerprint'] = false;
    }

    $serialNumber = (string)$this->config->get('certificate.serialNumber');
    if ($serialNumber === '') {
      $checks['serialNumber'] = false;
    }

    $issuerName = (string)$this->config->get('certificate.issuerName');
    if ($issuerName === '') {
      $checks['issuerName'] = false;
    }

    $failFast = (bool)$this->config->get('failFast');

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
              $expirationThreshold > -1 ? "{$expirationThreshold} days" : '-'
            ],
            [
              'SHA-1 Fingerprint',
              ($checks['sha1Fingerprint'] ? '<fg=green>enabled</>' : '<fg=red>disabled</>'),
              $sha1Fingerprint ?: '-'
            ],
            [
              'SHA-256 Fingerprint',
              ($checks['sha256Fingerprint'] ? '<fg=green>enabled</>' : '<fg=red>disabled</>'),
              $sha256Fingerprint ?: '-'
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
              ''
            ]
          ]
        )
        ->render();

      $output->writeln('');
    }

    $needCertificate = (
      $checks['expirationDate'] ||
      $checks['sha1Fingerprint'] ||
      $checks['sha256Fingerprint'] ||
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
      'Starting certificate check',
      OutputInterface::VERBOSITY_DEBUG
    );

    $hostnames = [
      $subject,
      ...array_map(
        static function (string $host) use ($subject): string {
          return "{$host}.{$subject}";
        },
        $this->config->get('certificate.hosts')
      )
    ];

    $returnCode = Command::SUCCESS;

    $errors = [];
    foreach ($hostnames as $hostname) {
      $output->writeln(
        sprintf(
          'Checking hostname <options=bold>%s</>',
          $hostname
        ),
        OutputInterface::VERBOSITY_VERBOSE
      );

      try {
        $hCurl = curl_init("https://{$hostname}/");
        curl_setopt($hCurl, CURLOPT_RETURNTRANSFER, false);
        curl_setopt($hCurl, CURLOPT_CUSTOMREQUEST, 'HEAD');
        curl_setopt($hCurl, CURLOPT_NOBODY, true);
        curl_setopt($hCurl, CURLOPT_CERTINFO, true);
        curl_setopt($hCurl, CURLOPT_CONNECTTIMEOUT, 30);
        curl_setopt($hCurl, CURLOPT_TIMEOUT, 120);
        curl_exec($hCurl);
        if (curl_errno($hCurl) > 0) {
          $curlError = curl_error($hCurl);
          curl_close($hCurl);

          $errors[] = $curlError;
          if ($failFast === true) {
            $this->printErrors($errors, $output);

            $errors = [];
            $returnCode = Command::FAILURE;
          }

          continue;
        }

        $certInfo = curl_getinfo($hCurl, CURLINFO_CERTINFO);
        curl_close($hCurl);

        if ($certInfo === false || $certInfo === []) {
          $errors[] = sprintf(
            'Failed to retrieve the certificate for hostname "%s"',
            $hostname
          );

          if ($failFast === true) {
            $this->printErrors($errors, $output);

            $errors = [];
            $returnCode = Command::FAILURE;
          }

          continue;
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
        $listOfSubjects = [
          $parsedCertificate->getSubject(),
          ...$parsedCertificate->getSubjectAlternativeNames()
        ];
        if ($this->subjectMatch($hostname, $listOfSubjects) === false) {
          $errors[] = sprintf(
            'Hostname "%s" does not match the certificate subject (%s) or any of the alternative names (%s)',
            $hostname,
            $parsedCertificate->getSubject(),
            implode(', ', $parsedCertificate->getSubjectAlternativeNames())
          );

          if ($failFast === true) {
            $this->printErrors($errors, $output);

            $errors = [];
            $returnCode = Command::FAILURE;

            continue;
          }
        }

        if ($checks['expirationDate'] === true) {
          $output->writeln(
            sprintf(
              'Certificate expiration date is <options=bold>%s</>',
              $parsedCertificate->getValidTo()->format(DateTimeInterface::ATOM),
            ),
            OutputInterface::VERBOSITY_DEBUG
          );

          $interval = $now->diff($parsedCertificate->getValidTo());
          if ($interval->days <= 0) {
            $errors[] = sprintf(
              'Certificate for hostname "%s" has expired %s ago',
              $hostname,
              DateUtils::timeAgo($interval)
            );

            if ($failFast === true) {
              $this->printErrors($errors, $output);

              $errors = [];
              $returnCode = Command::FAILURE;

              continue;
            }
          }

          if ($interval->days <= $expirationThreshold) {
            $errors[] = sprintf(
              'Certificate for hostname "%s" will expire in %d days (threshold: %d)',
              $hostname,
              $interval->days,
              $expirationThreshold
            );

            if ($failFast === true) {
              $this->printErrors($errors, $output);

              $errors = [];
              $returnCode = Command::FAILURE;

              continue;
            }
          }

          $output->writeln(
            sprintf(
              'Certificate expires in <options=bold>%d days</>',
              $interval->days
            ),
            OutputInterface::VERBOSITY_DEBUG
          );
        }

        if ($checks['sha1Fingerprint'] === true) {
          $fingerprint = openssl_x509_fingerprint($certInfo[0]['Cert'], 'sha-1');
          if ($fingerprint === false) {
            $errors[] = 'Failed to calculate the certificate\'s SHA-1 Fingerprint';

            if ($failFast === true) {
              $this->printErrors($errors, $output);

              $errors = [];
              $returnCode = Command::FAILURE;

              continue;
            }
          }

          $output->writeln(
            sprintf(
              'Certificate SHA-1 Fingerprint is <options=bold>%s</>',
              $fingerprint
            ),
            OutputInterface::VERBOSITY_DEBUG
          );

          if ($fingerprint !== $sha1Fingerprint) {
            $errors[] = sprintf(
              'Certificate SHA-1 Fingerprint "%s" for hostname "%s" does not match the expected fingerprint "%s"',
              $fingerprint,
              $hostname,
              $sha1Fingerprint
            );

            if ($failFast === true) {
              $this->printErrors($errors, $output);

              $errors = [];
              $returnCode = Command::FAILURE;

              continue;
            }
          }
        }

        if ($checks['sha256Fingerprint'] === true) {
          $fingerprint = openssl_x509_fingerprint($certInfo[0]['Cert'], 'sha-256');
          if ($fingerprint === false) {
            $errors[] = 'Failed to calculate the certificate\'s SHA-256 Fingerprint';

            if ($failFast === true) {
              $this->printErrors($errors, $output);

              $errors = [];
              $returnCode = Command::FAILURE;

              continue;
            }
          }

          $output->writeln(
            sprintf(
              'Certificate SHA-256 Fingerprint is <options=bold>%s</>',
              $fingerprint
            ),
            OutputInterface::VERBOSITY_DEBUG
          );

          if ($fingerprint !== $sha256Fingerprint) {
            $errors[] = sprintf(
              'Certificate SHA-256 Fingerprint "%s" for hostname "%s" does not match the expected fingerprint "%s"',
              $fingerprint,
              $hostname,
              $sha256Fingerprint
            );

            if ($failFast === true) {
              $this->printErrors($errors, $output);

              $errors = [];
              $returnCode = Command::FAILURE;

              continue;
            }
          }
        }

        if ($checks['serialNumber'] === true) {
          if ($parsedCertificate->getSerialNumber() === null) {
            $errors[] = 'Failed to retrieve the certificate\'s Serial Number';

            if ($failFast === true) {
              $this->printErrors($errors, $output);

              $errors = [];
              $returnCode = Command::FAILURE;

              continue;
            }
          }

          $output->writeln(
            sprintf(
              'Certificate Serial Number is <options=bold>%s</>',
              $parsedCertificate->getSerialNumber()
            ),
            OutputInterface::VERBOSITY_DEBUG
          );

          if ($parsedCertificate->getSerialNumber() !== $serialNumber) {
            $errors[] = sprintf(
              'Certificate Serial Number "%s" for hostname "%s" does not match the expected "%s"',
              $parsedCertificate->getSerialNumber(),
              $hostname,
              $serialNumber
            );

            if ($failFast === true) {
              $this->printErrors($errors, $output);

              $errors = [];
              $returnCode = Command::FAILURE;

              continue;
            }
          }
        }

        if ($checks['issuerName'] === true) {
          if ($parsedCertificate->getIssuer() === null) {
            $errors[] = 'Failed to retrieve the certificate\'s Issuer Name';

            if ($failFast === true) {
              $this->printErrors($errors, $output);

              $errors = [];
              $returnCode = Command::FAILURE;

              continue;
            }
          }

          $output->writeln(
            sprintf(
              'Certificate Issuer Name is <options=bold>%s</>',
              $parsedCertificate->getIssuer()
            ),
            OutputInterface::VERBOSITY_DEBUG
          );

          if ($parsedCertificate->getIssuer() !== $issuerName) {
            $errors[] = sprintf(
              'Certificate Issuer Name "%s" for hostname "%s" does not match the expected "%s"',
              $parsedCertificate->getIssuer(),
              $hostname,
              $issuerName
            );

            if ($failFast === true) {
              $this->printErrors($errors, $output);

              $errors = [];
              $returnCode = Command::FAILURE;

              continue;
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

            $errors[] = $curlError;
            if ($failFast === true) {
              $this->printErrors($errors, $output);

              $errors = [];
              $returnCode = Command::FAILURE;
            }

            continue;
          }


          curl_close($hCurl);

          $info = curl_getinfo($hCurl);
          if ($info['http_code'] !== 200) {
            $errors[] = sprintf(
              'OCSP response status code is %d',
              $info['http_code']
            );

            if ($failFast === true) {
              $this->printErrors($errors, $output);

              $errors = [];
              $returnCode = Command::FAILURE;
            }

            continue;
          }

          if ($info['content_type'] !== Ocsp::OCSP_RESPONSE_MEDIATYPE) {
            $errors[] = sprintf(
              'OCSP response content type is "%s", expected "%s"',
              $info['content_type'],
              Ocsp::OCSP_RESPONSE_MEDIATYPE
            );

            if ($failFast === true) {
              $this->printErrors($errors, $output);

              $errors = [];
              $returnCode = Command::FAILURE;
            }

            continue;
          }

          // Decode the raw response from the OCSP Responder
          $response = $this->ocsp->decodeOcspResponseSingle($result);

          if ($response->isRevoked() === null) {
            $errors[] = sprintf(
              'Certificate for hostname "%s" OCSP revocation state is unknown',
              $hostname
            );

            if ($failFast === true) {
              $this->printErrors($errors, $output);

              $errors = [];
              $returnCode = Command::FAILURE;

              continue;
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
              'Certificate for hostname "%s" was revoked on %s (reason: %s)',
              $hostname,
              $response->getRevokedOn(),
              $reason
            );

            if ($failFast === true) {
              $this->printErrors($errors, $output);

              $errors = [];
              $returnCode = Command::FAILURE;

              continue;
            }
          }

          $interval = $now->diff($response->getThisUpdate());
          $output->writeln(
            sprintf(
              'OCSP Revocation list was last updated <options=bold>%s</> (%s)',
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

          $errors = [];
          $returnCode = Command::FAILURE;
        }
      }
    }

    $output->writeln(
      'Finished certificate check',
      OutputInterface::VERBOSITY_DEBUG
    );

    if (count($errors) > 0) {
      $this->printErrors($errors, $output);

      return Command::FAILURE;
    }

    return $returnCode;
  }

  public function __construct(
    Configuration $config,
    CertificateInfo $certInfo,
    CertificateLoader $certLoader,
    CertificateParser $certParser,
    ClockInterface $clock,
    Ocsp $ocsp
  ) {
    parent::__construct();

    $this->config = $config;
    $this->certInfo = $certInfo;
    $this->certLoader = $certLoader;
    $this->certParser = $certParser;
    $this->clock = $clock;
    $this->ocsp = $ocsp;
  }
}
