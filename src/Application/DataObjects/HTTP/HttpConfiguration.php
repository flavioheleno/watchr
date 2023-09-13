<?php
declare(strict_types = 1);

namespace Watchr\Application\DataObjects\HTTP;

use Watchr\Application\Contracts\HTTP\HttpAuthenticationInterface;

final class HttpConfiguration {
  public readonly HttpAuthenticationInterface|null $authentication;
  public readonly string|null $body;
  /**
   * @var array<string, string>
   */
  public readonly array $headers;

  /**
   * @param array<string, string> $headers
   */
  public function __construct(
    HttpAuthenticationInterface|null $authentication = null,
    string|null $body = null,
    array $headers = []
  ) {
    $this->authentication = $authentication;
    $this->body = $body;
    $this->headers = array_map(
      static function (mixed $value): string {
        if (is_array($value)) {
          return implode($value);
        }

        return (string)$value;
      },
      $headers
    );
  }
}
