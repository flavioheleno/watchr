<?php
declare(strict_types = 1);

namespace Watchr\Application\Services\HTTP;

use RuntimeException;
use Watchr\Application\Contracts\HTTP\HttpRequestMethodEnum;
use Watchr\Application\DataObjects\HTTP\BasicAuthentication;
use Watchr\Application\DataObjects\HTTP\BearerTokenAuthentication;
use Watchr\Application\DataObjects\HTTP\CookieAuthentication;
use Watchr\Application\DataObjects\HTTP\DigestAuthentication;
use Watchr\Application\DataObjects\HTTP\HeaderAuthentication;
use Watchr\Application\DataObjects\HTTP\HttpConfiguration;
use Watchr\Application\DataObjects\HTTP\HttpResponse;

final class HttpCheckService {
  /**
   * @var array<int,bool|string|int>
   */
  private array $stdOpts;

  private function parseHeaders(string $response): array {
    $headers = [];

    $lines = explode("\r\n", $response);
    foreach ($lines as $line) {
      $split = strpos($line, ': ');
      if ($split === false) {
        // ignore lines that don't follow the expected format (<name>: <value>)
        continue;
      }

      $name = trim(substr($line, 0, $split));
      $value = trim(substr($line, $split + 2));
      $headers[$name] = $value;
    }

    return $headers;
  }


  public function __construct(
    int $connectTimeout,
    int $timeout,
    string $userAgent
  ) {
    $this->stdOpts = [
      CURLOPT_AUTOREFERER => true,
      CURLOPT_COOKIESESSION => true,
      CURLOPT_CERTINFO => true,
      CURLOPT_FAILONERROR => false,
      CURLOPT_DNS_SHUFFLE_ADDRESSES => true,
      CURLOPT_DNS_USE_GLOBAL_CACHE => false,
      CURLOPT_FOLLOWLOCATION => false,
      CURLOPT_FORBID_REUSE => true,
      CURLOPT_FRESH_CONNECT => true,
      CURLOPT_TCP_NODELAY => true,
      CURLOPT_HEADER => true,
      CURLOPT_HTTP_CONTENT_DECODING => true,
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_TCP_FASTOPEN => true,
      CURLOPT_CONNECTTIMEOUT => $connectTimeout,
      CURLOPT_ENCODING => '',
      CURLOPT_TIMEOUT => $timeout,
      CURLOPT_USERAGENT => $userAgent
    ];
  }

  public function check(
    string $url,
    HttpRequestMethodEnum $requestMethod = HttpRequestMethodEnum::GET,
    HttpConfiguration $configuration = null
  ): HttpResponse {
    $opts = [
      CURLOPT_NOBODY => $requestMethod === HttpRequestMethodEnum::HEAD,
      CURLOPT_RETURNTRANSFER => $requestMethod !== HttpRequestMethodEnum::HEAD,
      CURLOPT_CUSTOMREQUEST => $requestMethod->value,
    ];

    if ($configuration !== null) {
      $headers = [];
      if ($configuration->authentication !== null) {
        if ($configuration->authentication instanceof BasicAuthentication) {
          $opts += [
            CURLOPT_HTTPAUTH => CURLAUTH_BASIC,
            CURLOPT_USERNAME => $configuration->authentication->username,
            CURLOPT_PASSWORD => $configuration->authentication->password
          ];
        } else if ($configuration->authentication instanceof BearerTokenAuthentication) {
          $opts += [
            CURLOPT_HTTPAUTH => CURLAUTH_BEARER,
            CURLOPT_XOAUTH2_BEARER => $configuration->authentication->token
          ];
        } else if ($configuration->authentication instanceof CookieAuthentication) {
          $opts[CURLOPT_COOKIE] = sprintf(
            '%s=%s',
            $configuration->authentication->name,
            $configuration->authentication->value
          );
        } else if ($configuration->authentication instanceof DigestAuthentication) {
          $opts += [
            CURLOPT_HTTPAUTH => CURLAUTH_DIGEST,
            CURLOPT_USERNAME => $configuration->authentication->username,
            CURLOPT_PASSWORD => $configuration->authentication->password
          ];
        } else if ($configuration->authentication instanceof HeaderAuthentication) {
          $headers[$configuration->authentication->name] = $configuration->authentication->value;
        }
      }

      if ($configuration->body !== null) {
        $opts[CURLOPT_POSTFIELDS] = $configuration->body;
      }

      $opts[CURLOPT_HTTPHEADER] = array_merge($configuration->headers, $headers);
    }

    $hCurl = curl_init($url);
    if (curl_setopt_array($hCurl, $this->stdOpts + $opts) === false) {
      throw new RuntimeException('Failed to set curl options');
    }

    $response = curl_exec($hCurl);
    if (curl_errno($hCurl) > 0) {
      $curlError = curl_error($hCurl);
      curl_close($hCurl);

      throw new RuntimeException($curlError);
    }

    $split = strpos($response, "\r\n\r\n");
    if ($split === false) {
      throw new RuntimeException('Invalid HTTP Response format');
    }

    $responseHeaders = $this->parseHeaders(substr($response, 0, $split));
    $responseBody = substr($response, $split + 4);

    $response = new HttpResponse(
      curl_getinfo($hCurl, CURLINFO_APPCONNECT_TIME_T),
      $responseBody,
      curl_getinfo($hCurl, CURLINFO_CERTINFO),
      curl_getinfo($hCurl, CURLINFO_CONNECT_TIME_T),
      curl_getinfo($hCurl, CURLINFO_CONTENT_TYPE),
      $responseHeaders,
      curl_getinfo($hCurl, CURLINFO_HTTP_VERSION),
      curl_getinfo($hCurl, CURLINFO_NAMELOOKUP_TIME_T),
      curl_getinfo($hCurl, CURLINFO_PRETRANSFER_TIME_T),
      curl_getinfo($hCurl, CURLINFO_PRIMARY_IP),
      curl_getinfo($hCurl, CURLINFO_PRIMARY_PORT),
      curl_getinfo($hCurl, CURLINFO_RESPONSE_CODE),
      curl_getinfo($hCurl, CURLINFO_STARTTRANSFER_TIME_T),
      curl_getinfo($hCurl, CURLINFO_TOTAL_TIME_T),
    );

    curl_close($hCurl);

    return $response;
  }
}
