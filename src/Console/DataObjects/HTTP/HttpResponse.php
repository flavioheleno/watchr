<?php
declare(strict_types = 1);

namespace Watchr\Console\DataObjects\HTTP;

use JsonSerializable;
use Watchr\Console\Contracts\Streams\StreamInterface;

final class HttpResponse implements JsonSerializable {
  /**
   * Time, in microseconds, it took from the start until the SSL connect/handshake to the remote host was completed.
   */
  public readonly int $appConnectTime;
  public readonly StreamInterface $body;
  /**
   * The TLS certificate chain.
   *
   * @var array<int, array<string, string>>
   */
  public readonly array $certChain;
  /**
   * Time in microseconds it took to establish the connection.
   */
  public readonly int $connectTime;
  /**
   * Content length of download, read from "Content-Length" header
   */
  public readonly int $contentLength;
  /**
   * The "Content-Type" of the requested document.
   * Note: NULL indicates server did not send valid "Content-Type" header.
   */
  public readonly string|null $contentType;
  /**
   * @var array<string, string>
   */
  public readonly array $headers;
  /**
   * The version used in the last HTTP connection or 0 if the version can't be determined.
   */
  public readonly string $httpVersion;
  /**
   * Time in microseconds until name resolving was complete.
   */
  public readonly int $namelookupTime;
  /**
   * Time in microseconds from start until just before file transfer begins.
   */
  public readonly int $preTransferTime;
  /**
   * IP address of the most recent connection.
   */
  public readonly string $primaryIp;
  /**
   * Destination port of the most recent connection.
   */
  public readonly int $primaryPort;
  /**
   * The last response code.
   */
  public readonly int $responseCode;
  /**
   * Time in microseconds until the first byte is about to be transferred.
   */
  public readonly int $startTransferTime;
  /**
   * Total transaction time in microseconds for last transfer.
   */
  public readonly int $totalTime;
  /**
   * The redirect URL found in the last transaction.
   */
  public readonly string $redirectUrl;
  /**
   * Last effective URL.
   */
  public readonly string $url;

  /**
   * @param array<int, array<string, string>> $certChain
   * @param array<string, string> $headers
   */
  public function __construct(
    int $appConnectTime,
    StreamInterface $body,
    array $certChain,
    int $connectTime,
    int $contentLength,
    string|null $contentType,
    array $headers,
    string $httpVersion,
    int $namelookupTime,
    int $preTransferTime,
    string $primaryIp,
    int $primaryPort,
    int $responseCode,
    int $startTransferTime,
    int $totalTime,
    string $redirectUrl,
    string $url
  ) {
    $this->appConnectTime = $appConnectTime;
    $this->body = $body;
    $this->certChain = $certChain;
    $this->connectTime = $connectTime;
    $this->contentLength = $contentLength;
    $this->contentType = $contentType;
    $this->headers = $headers;
    $this->httpVersion = $httpVersion;
    $this->namelookupTime = $namelookupTime;
    $this->preTransferTime = $preTransferTime;
    $this->primaryIp = $primaryIp;
    $this->primaryPort = $primaryPort;
    $this->responseCode = $responseCode;
    $this->startTransferTime = $startTransferTime;
    $this->totalTime = $totalTime;
    $this->redirectUrl = $redirectUrl;
    $this->url = $url;
  }

  public function jsonSerialize(): mixed {
    return [
      'appConnectTime' => $this->appConnectTime,
      'body' => (string)$this->body,
      'certChain' => $this->certChain,
      'connectTime' => $this->connectTime,
      'contentLength' => $this->contentLength,
      'contentType' => $this->contentType,
      'headers' => $this->headers,
      'httpVersion' => $this->httpVersion,
      'namelookupTime' => $this->namelookupTime,
      'preTransferTime' => $this->preTransferTime,
      'primaryIp' => $this->primaryIp,
      'primaryPort' => $this->primaryPort,
      'responseCode' => $this->responseCode,
      'startTransferTime' => $this->startTransferTime,
      'totalTime' => $this->totalTime,
      'redirectUrl' => $this->redirectUrl,
      'url' => $this->url
    ];
  }
}
