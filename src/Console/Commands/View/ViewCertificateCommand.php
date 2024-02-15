<?php
declare(strict_types = 1);

namespace Watchr\Console\Commands\View;

use DateTimeInterface;
use Exception;
use InvalidArgumentException;
use Psr\Clock\ClockInterface;
use RuntimeException;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Watchr\Console\Services\CertificateService;
use Watchr\Console\Traits\DateUtilsTrait;
use Watchr\Console\Traits\ErrorPrinterTrait;

#[AsCommand('view:certificate', 'View certificate details')]
final class ViewCertificateCommand extends Command {
  use DateUtilsTrait;
  use ErrorPrinterTrait;

  private ClockInterface $clock;
  private CertificateService $certificateService;

  protected function configure(): void {
    $this
      ->addOption(
        'json',
        'j',
        InputOption::VALUE_NONE,
        'Format the output as a JSON string'
      )
      ->addArgument(
        'domain',
        InputArgument::REQUIRED,
        'Domain Name to be viewed'
      );
  }

  protected function execute(InputInterface $input, OutputInterface $output): int {
    $jsonOutput = (bool)$input->getOption('json');
    $domain = $input->getArgument('domain');
    try {
      if (
        strpos($domain, '.') === false ||
        filter_var($domain, FILTER_VALIDATE_DOMAIN, ['flags' => FILTER_FLAG_HOSTNAME]) === false
      ) {
        throw new InvalidArgumentException('argument <options=bold>domain</> contains an invalid domain name');
      }

      $chain = $this->certificateService->get($domain);

      if ($jsonOutput === true) {
        $output->write(json_encode($chain));

        return Command::SUCCESS;
      }

      $now = $this->clock->now();

      $lines = [];
      foreach ($chain as $index => $cert) {
        $lines[] = sprintf('<options=bold>Certificate #%d</>', $index + 1);
        $lines[] = ' Subject:';
        if ($cert->subjectOrganization !== null) {
          $lines[] = sprintf('  * Organization: <options=bold>%s</>', $cert->subjectOrganization);
        }

        if ($cert->subjectCommonName !== null) {
          $lines[] = sprintf('  * Common name: <options=bold>%s</>', $cert->subjectCommonName);
        }

        $lines[] = ' Issuer:';
        if ($cert->issuerOrganization !== null) {
          $lines[] = sprintf('  * Organization: <options=bold>%s</>', $cert->issuerOrganization);
        }

        if ($cert->issuerCommonName !== null) {
          $lines[] = sprintf('  * Common name: <options=bold>%s</>', $cert->issuerCommonName);
        }

        $lines[] = sprintf(
          ' Self signed: %s',
          $cert->selfSigned ? '<fg=red;options=bold>YES</>' : '<fg=green;options=bold>NO</>'
        );
        $lines[] = sprintf(
          ' Valid from: <options=bold>%s</> (%s)',
          $cert->validFrom->format(DateTimeInterface::ATOM),
          $this->humanReadableInterval($now->diff($cert->validFrom))
        );
        $lines[] = sprintf(
          ' Valid to: <options=bold>%s</> (%s)',
          $cert->validTo->format(DateTimeInterface::ATOM),
          $this->humanReadableInterval($now->diff($cert->validTo))
        );
        $lines[] = ' Fingerprint:';
        $lines[] = sprintf('  * SHA-1: <options=bold>%s</>', $cert->sha1Fingerprint);
        $lines[] = sprintf('  * SHA-256: <options=bold>%s</>', $cert->sha256Fingerprint);
        $lines[] = sprintf(' Serial Number: <options=bold>%s</>', $cert->serialNumber);
        if (count($cert->subjectAlternativeNames) > 0) {
          $lines[] = ' Alternative Names:';
          foreach ($cert->subjectAlternativeNames as $name) {
            $lines[] = sprintf('  * <options=bold>%s</>', $name);
          }
        }

        $lines[] = sprintf(' Certificate Authority: <options=bold>%s</>', $cert->certificateAuthority ? 'YES' : 'NO');
        $lines[] = ' Usage:';
        $lines[] = sprintf(
          '  * Digital Signature: %s',
          $cert->digitalSignature ? '<fg=green;options=bold>YES</>' : '<fg=red;options=bold>NO</>'
        );
        $lines[] = sprintf(
          '  * Non-Repudiation: %s',
          $cert->nonRepudiation ? '<fg=green;options=bold>YES</>' : '<fg=red;options=bold>NO</>'
        );
        $lines[] = sprintf(
          '  * Key Encipherment: %s',
          $cert->keyEncipherment ? '<fg=green;options=bold>YES</>' : '<fg=red;options=bold>NO</>'
        );
        $lines[] = sprintf(
          '  * Data Encipherment: %s',
          $cert->dataEncipherment ? '<fg=green;options=bold>YES</>' : '<fg=red;options=bold>NO</>'
        );
        $lines[] = sprintf(
          '  * Key Agreement: %s',
          $cert->keyAgreement ? '<fg=green;options=bold>YES</>' : '<fg=red;options=bold>NO</>'
        );
        $lines[] = sprintf(
          '  * Key Certificate Sign: %s',
          $cert->keyCertSign ? '<fg=green;options=bold>YES</>' : '<fg=red;options=bold>NO</>'
        );
        $lines[] = sprintf(
          '  * CRL Sign: %s',
          $cert->cRLSign ? '<fg=green;options=bold>YES</>' : '<fg=red;options=bold>NO</>'
        );
        $lines[] = sprintf(
          '  * Encipher Only: %s',
          $cert->encipherOnly ? '<fg=green;options=bold>YES</>' : '<fg=red;options=bold>NO</>'
        );
        $lines[] = sprintf(
          '  * Decipher Only: %s',
          $cert->decipherOnly ? '<fg=green;options=bold>YES</>' : '<fg=red;options=bold>NO</>'
        );
        $lines[] = sprintf(
          '  * Server Auth: %s',
          $cert->serverAuth ? '<fg=green;options=bold>YES</>' : '<fg=red;options=bold>NO</>'
        );
        $lines[] = sprintf(
          '  * Client Auth: %s',
          $cert->clientAuth ? '<fg=green;options=bold>YES</>' : '<fg=red;options=bold>NO</>'
        );
        $lines[] = sprintf(
          '  * Code Signing: %s',
          $cert->codeSigning ? '<fg=green;options=bold>YES</>' : '<fg=red;options=bold>NO</>'
        );
        $lines[] = sprintf(
          '  * E-mail Protection: %s',
          $cert->emailProtection ? '<fg=green;options=bold>YES</>' : '<fg=red;options=bold>NO</>'
        );
        $lines[] = sprintf(
          '  * TimeStamping: %s',
          $cert->timeStamping ? '<fg=green;options=bold>YES</>' : '<fg=red;options=bold>NO</>'
        );
        $lines[] = sprintf(
          '  * OCSP Signing: %s',
          $cert->OCSPSigning ? '<fg=green;options=bold>YES</>' : '<fg=red;options=bold>NO</>'
        );

        $lines[] = '';
      }

      $output->writeln($lines);

      return Command::SUCCESS;
    } catch (Exception $exception) {
      if ($jsonOutput === true) {
        $out = ['error' => $exception->getMessage()];
        if ($output->isDebug() === true) {
          $out['trace'] = $exception->getTrace();
        }

        $output->write(json_encode($out));

        return Command::FAILURE;
      }

      $errors = [$exception->getMessage()];
      if ($output->isDebug() === true) {
        $errors[] = $exception->getTraceAsString();
      }

      $this->printErrors($errors, $output);

      return Command::FAILURE;
    }
  }

  public function __construct(
    ClockInterface $clock,
    CertificateService $certificateService
  ) {
    parent::__construct();

    $this->clock = $clock;
    $this->certificateService = $certificateService;
  }
}

