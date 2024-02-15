<?php
declare(strict_types = 1);

namespace Watchr\Console\DataObjects\Certificate;

use DateTimeImmutable;
use DateTimeInterface;
use JsonSerializable;
use Psr\Clock\ClockInterface;
use RuntimeException;

final class Certificate implements JsonSerializable {
  public readonly string $pem;
  public readonly string|null $subjectCountry;
  public readonly string|null $subjectOrganization;
  public readonly string|null $subjectCommonName;
  public readonly string|null $issuerCountry;
  public readonly string|null $issuerOrganization;
  public readonly string|null $issuerCommonName;
  public readonly bool $selfSigned;
  public readonly string $signatureTypeShortName;
  public readonly string $signatureTypeLongName;
  public readonly int $signatureTypeId;
  public readonly DateTimeImmutable $validFrom;
  public readonly DateTimeImmutable $validTo;
  public readonly string $sha1Fingerprint;
  public readonly string $sha256Fingerprint;
  public readonly string|null $serialNumber;
  /**
   * @var string[]
   */
  public readonly array $subjectAlternativeNames;
  public readonly bool $certificateAuthority;
  public readonly bool $digitalSignature;
  public readonly bool $nonRepudiation;
  public readonly bool $keyEncipherment;
  public readonly bool $dataEncipherment;
  public readonly bool $keyAgreement;
  public readonly bool $keyCertSign;
  public readonly bool $cRLSign;
  public readonly bool $encipherOnly;
  public readonly bool $decipherOnly;
  public readonly bool $serverAuth;
  public readonly bool $clientAuth;
  public readonly bool $codeSigning;
  public readonly bool $emailProtection;
  public readonly bool $timeStamping;
  public readonly bool $OCSPSigning;

  public static function fromPEM(string $pem): self {
    $certificate = openssl_x509_parse($pem);
    if ($certificate === false) {
      throw new RuntimeException('Failed to parse certificate');
    }

    $sha1Fingerprint = openssl_x509_fingerprint($pem, 'sha1', false);
    if ($sha1Fingerprint === false) {
      throw new RuntimeException('Failed to calculate Certificate SHA-1 Fingerprint');
    }

    $sha256Fingerprint = openssl_x509_fingerprint($pem, 'sha256', false);
    if ($sha256Fingerprint === false) {
      throw new RuntimeException('Failed to calculate Certificate SHA-256 Fingerprint');
    }

    $subjectAlternativeNames = array_map(
      static function (string $item): string {
        return explode(':', trim($item), 2)[1];
      },
      array_filter(
        explode(
          ',',
          $certificate['extensions']['subjectAltName'] ?? ''
        ),
        static function (string $item): bool {
          return strpos($item, ':') !== false;
        }
      )
    );

    $keyUsage = array_filter(
      array_merge(
        explode(
          ', ',
          $certificate['extensions']['keyUsage'] ?? ''
        ),
        explode(
          ', ',
          $certificate['extensions']['extendedKeyUsage'] ?? ''
        )
      )
    );

    return new Certificate(
      $pem,
      $certificate['subject']['C'] ?? null,
      $certificate['subject']['O'] ?? null,
      $certificate['subject']['CN'] ?? null,
      $certificate['issuer']['C'] ?? null,
      $certificate['issuer']['O'] ?? null,
      $certificate['issuer']['CN'] ?? null,
      $certificate['subject'] === $certificate['issuer'],
      $certificate['signatureTypeSN'],
      $certificate['signatureTypeLN'],
      $certificate['signatureTypeNID'],
      new DateTimeImmutable("@{$certificate['validFrom_time_t']}"),
      new DateTimeImmutable("@{$certificate['validTo_time_t']}"),
      $sha1Fingerprint,
      $sha256Fingerprint,
      $certificate['serialNumber'],
      $subjectAlternativeNames,
      preg_match('/\bCA:TRUE\b/', $certificate['extensions']['basicConstraints'] ?? '') === 1,
      in_array('Digital Signature', $keyUsage, true),
      in_array('Non-Repudiation', $keyUsage, true),
      in_array('Key Encipherment', $keyUsage, true),
      in_array('Data Encipherment', $keyUsage, true),
      in_array('Key Agreement', $keyUsage, true),
      in_array('Certificate Sign', $keyUsage, true),
      in_array('CRL Sign', $keyUsage, true),
      in_array('Encipher Only', $keyUsage, true),
      in_array('Decipher Only', $keyUsage, true),
      in_array('TLS Web Server Authentication', $keyUsage, true),
      in_array('TLS Web Client Authentication', $keyUsage, true),
      in_array('Code Signing', $keyUsage, true),
      in_array('E-mail Protection', $keyUsage, true),
      in_array('Timestamping', $keyUsage, true),
      in_array('OCSP Signing', $keyUsage, true)
    );
  }

  public function __construct(
    string $pem,
    string|null $subjectCountry,
    string|null $subjectOrganization,
    string|null $subjectCommonName,
    string|null $issuerCountry,
    string|null $issuerOrganization,
    string|null $issuerCommonName,
    bool $selfSigned,
    string $signatureTypeShortName,
    string $signatureTypeLongName,
    int $signatureTypeId,
    DateTimeImmutable $validFrom,
    DateTimeImmutable $validTo,
    string $sha1Fingerprint,
    string $sha256Fingerprint,
    string $serialNumber,
    array $subjectAlternativeNames,
    bool $certificateAuthority,
    bool $digitalSignature,
    bool $nonRepudiation,
    bool $keyEncipherment,
    bool $dataEncipherment,
    bool $keyAgreement,
    bool $keyCertSign,
    bool $cRLSign,
    bool $encipherOnly,
    bool $decipherOnly,
    bool $serverAuth,
    bool $clientAuth,
    bool $codeSigning,
    bool $emailProtection,
    bool $timeStamping,
    bool $OCSPSigning
  ) {
    $this->pem = $pem;
    $this->subjectCountry = $subjectCountry;
    $this->subjectOrganization = $subjectOrganization;
    $this->subjectCommonName = $subjectCommonName;
    $this->issuerCountry = $issuerCountry;
    $this->issuerOrganization = $issuerOrganization;
    $this->issuerCommonName = $issuerCommonName;
    $this->selfSigned = $selfSigned;
    $this->signatureTypeShortName = $signatureTypeShortName;
    $this->signatureTypeLongName = $signatureTypeLongName;
    $this->signatureTypeId = $signatureTypeId;
    $this->validFrom = $validFrom;
    $this->validTo = $validTo;
    $this->sha1Fingerprint = $sha1Fingerprint;
    $this->sha256Fingerprint = $sha256Fingerprint;
    $this->serialNumber = $serialNumber;
    $this->subjectAlternativeNames = $subjectAlternativeNames;
    $this->certificateAuthority = $certificateAuthority;
    $this->digitalSignature = $digitalSignature;
    $this->nonRepudiation = $nonRepudiation;
    $this->keyEncipherment = $keyEncipherment;
    $this->dataEncipherment = $dataEncipherment;
    $this->keyAgreement = $keyAgreement;
    $this->keyCertSign = $keyCertSign;
    $this->cRLSign = $cRLSign;
    $this->encipherOnly = $encipherOnly;
    $this->decipherOnly = $decipherOnly;
    $this->serverAuth = $serverAuth;
    $this->clientAuth = $clientAuth;
    $this->codeSigning = $codeSigning;
    $this->emailProtection = $emailProtection;
    $this->timeStamping = $timeStamping;
    $this->OCSPSigning = $OCSPSigning;
  }

  public function isExpired(ClockInterface $clock): bool {
    return $this->validTo < $clock->now();
  }

  public function jsonSerialize(): mixed {
    return [
      'pem' => $this->pem,
      'subjectCountry' => $this->subjectCountry,
      'subjectOrganization' => $this->subjectOrganization,
      'subjectCommonName' => $this->subjectCommonName,
      'issuerCountry' => $this->issuerCountry,
      'issuerOrganization' => $this->issuerOrganization,
      'issuerCommonName' => $this->issuerCommonName,
      'selfSigned' => $this->selfSigned,
      'signatureTypeShortName' => $this->signatureTypeShortName,
      'signatureTypeLongName' => $this->signatureTypeLongName,
      'signatureTypeId' => $this->signatureTypeId,
      'validFrom' => $this->validFrom->format(DateTimeInterface::ATOM),
      'validTo' => $this->validTo->format(DateTimeInterface::ATOM),
      'sha1Fingerprint' => $this->sha1Fingerprint,
      'sha256Fingerprint' => $this->sha256Fingerprint,
      'serialNumber' => $this->serialNumber,
      'subjectAlternativeNames' => $this->subjectAlternativeNames,
      'certificateAuthority' => $this->certificateAuthority,
      'digitalSignature' => $this->digitalSignature,
      'nonRepudiation' => $this->nonRepudiation,
      'keyEncipherment' => $this->keyEncipherment,
      'dataEncipherment' => $this->dataEncipherment,
      'keyAgreement' => $this->keyAgreement,
      'keyCertSign' => $this->keyCertSign,
      'cRLSign' => $this->cRLSign,
      'encipherOnly' => $this->encipherOnly,
      'decipherOnly' => $this->decipherOnly,
      'serverAuth' => $this->serverAuth,
      'clientAuth' => $this->clientAuth,
      'codeSigning' => $this->codeSigning,
      'emailProtection' => $this->emailProtection,
      'timeStamping' => $this->timeStamping,
      'OCSPSigning' => $this->OCSPSigning
    ];
  }
}
