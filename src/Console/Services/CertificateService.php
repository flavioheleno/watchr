<?php
declare(strict_types = 1);

namespace Watchr\Console\Services;

use InvalidArgumentException;
use Ocsp\CertificateInfo;
use Ocsp\CertificateLoader;
use Ocsp\Ocsp;
use Ocsp\Response;
use RuntimeException;
use Watchr\Console\DataObjects\Certificate\Certificate;
use Watchr\Console\DataObjects\Certificate\CertificateChain;
use Watchr\Console\DataObjects\Certificate\CertificateStatus;

final class CertificateService {
  /**
   * @var array<int,bool|string|int>
   */
  private array $stdOpts;
  private CertificateInfo $certInfo;
  private CertificateLoader $certLoader;
  private Ocsp $ocsp;

  public function __construct(
    int $connectTimeout,
    int $timeout,
    string $userAgent,
    CertificateInfo $certInfo,
    CertificateLoader $certLoader,
    Ocsp $ocsp
  ) {
    $this->stdOpts = [
      CURLOPT_AUTOREFERER => true,
      CURLOPT_CERTINFO => true,
      CURLOPT_CONNECTTIMEOUT => $connectTimeout,
      CURLOPT_COOKIEFILE => '',
      CURLOPT_COOKIELIST => 'RELOAD',
      CURLOPT_COOKIESESSION => true,
      CURLOPT_CUSTOMREQUEST => 'HEAD',
      CURLOPT_DISALLOW_USERNAME_IN_URL => true,
      CURLOPT_DNS_SHUFFLE_ADDRESSES => true,
      CURLOPT_DNS_USE_GLOBAL_CACHE => false,
      CURLOPT_ENCODING => '',
      CURLOPT_FAILONERROR => false,
      CURLOPT_FILETIME => true,
      CURLOPT_FOLLOWLOCATION => false,
      CURLOPT_FORBID_REUSE => true,
      CURLOPT_FRESH_CONNECT => true,
      CURLOPT_HEADER => false,
      CURLOPT_HTTP_CONTENT_DECODING => false,
      CURLOPT_NOBODY => true,
      CURLOPT_PROXY_SSL_VERIFYPEER => false,
      CURLOPT_RETURNTRANSFER => false,
      CURLOPT_SSL_VERIFYPEER => false,
      CURLOPT_SSL_VERIFYSTATUS => false,
      CURLOPT_TCP_FASTOPEN => true,
      CURLOPT_TCP_NODELAY => true,
      CURLOPT_TIMEOUT => $timeout,
      CURLOPT_USERAGENT => $userAgent
    ];

    $this->certInfo = $certInfo;
    $this->certLoader = $certLoader;
    $this->ocsp = $ocsp;
  }

  public function get(string $domain): CertificateChain {
    if (filter_var($domain, FILTER_VALIDATE_DOMAIN) === false) {
      throw new InvalidArgumentException('Invalid domain argument');
    }

    $hCurl = curl_init("https://{$domain}/");
    if (curl_setopt_array($hCurl, $this->stdOpts) === false) {
      throw new RuntimeException('Failed to set curl options');
    }

    curl_exec($hCurl);
    if (curl_errno($hCurl) > 0) {
      $curlError = curl_error($hCurl);
      curl_close($hCurl);

      throw new RuntimeException($curlError);
    }

    $certInfo = curl_getinfo($hCurl, CURLINFO_CERTINFO);
    curl_close($hCurl);

    if ($certInfo === false || $certInfo === []) {
      throw new RuntimeException('Failed to retrieve the certificate');
    }

    $certChain = [];
    foreach ($certInfo as $cert) {
      $certChain[] = Certificate::fromPem($cert['Cert']);
    }


    return new CertificateChain(...$certChain);
  }

  public function status(CertificateChain $chain): CertificateStatus {
    $certificate = $this->certLoader->fromString($chain->at(0)->pem);
    $issuerCertificate = $this->certLoader->fromString($chain->at(1)->pem);
    $ocspResponderUrl = $this->certInfo->extractOcspResponderUrl($certificate);

    $requestInfo = $this->certInfo->extractRequestInfo($certificate, $issuerCertificate);
    $requestBody = $this->ocsp->buildOcspRequestBodySingle($requestInfo);
    $opts = [
      CURLOPT_CUSTOMREQUEST => null,
      CURLOPT_HTTPHEADER => ['Content-Type: ' . Ocsp::OCSP_REQUEST_MEDIATYPE],
      CURLOPT_NOBODY => false,
      CURLOPT_POST => true,
      CURLOPT_POSTFIELDS => $requestBody,
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_SAFE_UPLOAD => true,
    ];

    $hCurl = curl_init($ocspResponderUrl);
    if (curl_setopt_array($hCurl, $opts + $this->stdOpts + $opts) === false) {
      throw new RuntimeException('Failed to set curl options');
    }

    $response = curl_exec($hCurl);
    if (curl_errno($hCurl) > 0) {
      $curlError = curl_error($hCurl);
      curl_close($hCurl);

      throw new RuntimeException($curlError);
    }

    $info = curl_getinfo($hCurl);
    curl_close($hCurl);

    if ($info['http_code'] !== 200) {
      var_dump($info, $response);
      throw new RuntimeException("OCSP Responder returned {$info['http_code']}");
    }
    if ($info['content_type'] !== Ocsp::OCSP_RESPONSE_MEDIATYPE) {
      throw new RuntimeException('OCSP Responder returned an invalid Content-Type header');
    }

    // Decode the raw response from the OCSP Responder
    $ocspResponse = $this->ocsp->decodeOcspResponseSingle($response);

    if ($ocspResponse->isRevoked() === null) {
      throw new RuntimeException('OCSP revocation state is unknown');
    }

    $reason = null;
    if ($ocspResponse->isRevoked() === true) {
      $reason = match ($ocspResponse->getRevocationReason()) {
        Response::REVOCATIONREASON_UNSPECIFIED => 'Unspecified',
        Response::REVOCATIONREASON_KEYCOMPROMISE => 'Key compromise',
        Response::REVOCATIONREASON_CACOMPROMISE => 'CA Compromise',
        Response::REVOCATIONREASON_AFFILIATIONCHANGED => 'Affiliation changed',
        Response::REVOCATIONREASON_SUPERSEDED => 'Superseded',
        Response::REVOCATIONREASON_CESSATIONOFOPERATION => 'Cessation of operation',
        Response::REVOCATIONREASON_CERTIFICATEHOLD => 'Certificate hold',
        Response::REVOCATIONREASON_REMOVEFROMCRL => 'Remove from CRL',
        Response::REVOCATIONREASON_PRIVILEGEWITHDRAWN => 'Privilege withdrawn',
        Response::REVOCATIONREASON_AACOMPROMISE => 'AA compromise',
        default => 'Unknown'
      };

    }

    return new CertificateStatus(
      $ocspResponse->getThisUpdate(),
      $ocspResponse->getRevokedOn(),
      $reason,
      $ocspResponse->getNextUpdate()
    );
  }
}
