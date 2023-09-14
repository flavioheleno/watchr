<?php
declare(strict_types = 1);

namespace Watchr\Application\Services\HTTP;

use CurlHandle;
use RuntimeException;
use Watchr\Application\Contracts\HTTP\HttpRequestMethodEnum;
use Watchr\Application\DataObjects\HTTP\BasicAuthentication;
use Watchr\Application\DataObjects\HTTP\BearerTokenAuthentication;
use Watchr\Application\DataObjects\HTTP\CookieAuthentication;
use Watchr\Application\DataObjects\HTTP\DigestAuthentication;
use Watchr\Application\DataObjects\HTTP\HeaderAuthentication;
use Watchr\Application\DataObjects\HTTP\HttpConfiguration;
use Watchr\Application\DataObjects\HTTP\HttpResponse;
use Watchr\Application\Streams\NullStream;
use Watchr\Application\Streams\Stream;

final class HttpCheckService {
  /**
   * @var array<int,bool|string|int>
   */
  private array $stdOpts;

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
      CURLOPT_HEADER => false,
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
      CURLOPT_RETURNTRANSFER => false,
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

    $responseHeaders = [];
    $opts[CURLOPT_HEADERFUNCTION] = static function (CurlHandle $hCurl, string $data) use (&$responseHeaders): int {
      $split = strpos($data, ': ');
      if ($split === false) {
        // ignore header lines that don't follow the expected format (<name>: <value>)
        return strlen($data);
      }

      $name = trim(substr($data, 0, $split));
      $value = trim(substr($data, $split + 2));
      $responseHeaders[$name] = $value;

      return strlen($data);
    };

    if ($requestMethod === HttpRequestMethodEnum::HEAD) {
      $responseBody = new NullStream();
    } else {
      $responseBody = new Stream(fopen('php://temp', 'w+b'));
      $opts[CURLOPT_WRITEFUNCTION] = static function (CurlHandle $hCurl, string $data) use ($responseBody): int {
        return $responseBody->write($data);
      };
    }

    $hCurl = curl_init($url);
    if (curl_setopt_array($hCurl, $this->stdOpts + $opts) === false) {
      throw new RuntimeException('Failed to set curl options');
    }

    curl_exec($hCurl);
    if (curl_errno($hCurl) > 0) {
      $curlError = curl_error($hCurl);
      curl_close($hCurl);

      throw new RuntimeException($curlError);
    }

    $responseBody->readOnly();

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
