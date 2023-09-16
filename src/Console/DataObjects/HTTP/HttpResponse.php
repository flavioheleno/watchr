<?php
declare(strict_types = 1);

namespace Watchr\Console\DataObjects\HTTP;

use Watchr\Console\Contracts\Streams\StreamInterface;

final class HttpResponse {
  public readonly int $appConnectTime;
  public readonly StreamInterface $body;
  /**
   * @var array<int, array<string, string>>
   */
  public readonly array $certChain;
  public readonly int $connectTime;
  public readonly string $contentType;
  /**
   * @var array<string, string>
   */
  public readonly array $headers;
  public readonly int $httpVersion;
  public readonly int $namelookupTime;
  public readonly int $preTransferTime;
  public readonly string $primaryIp;
  public readonly int $primaryPort;
  public readonly int $responseCode;
  public readonly int $startTransferTime;
  public readonly int $totalTime;

  /**
   * @param array<int, array<string, string>> $certChain
   * @param array<string, string> $headers
   */
  public function __construct(
    int $appConnectTime,
    StreamInterface $body,
    array $certChain,
    int $connectTime,
    string $contentType,
    array $headers,
    int $httpVersion,
    int $namelookupTime,
    int $preTransferTime,
    string $primaryIp,
    int $primaryPort,
    int $responseCode,
    int $startTransferTime,
    int $totalTime
  ) {
    $this->appConnectTime = $appConnectTime;
    $this->body = $body;
    $this->certChain = $certChain;
    $this->connectTime = $connectTime;
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
  }
}
