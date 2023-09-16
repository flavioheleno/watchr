<?php
declare(strict_types = 1);

namespace Watchr\Console\DataObjects\HTTP;

use Watchr\Console\Contracts\HTTP\HttpAuthenticationInterface;

final class CookieAuthentication implements HttpAuthenticationInterface {
  public readonly string $name;
  public readonly string $value;

  public function __construct(string $name, string $value) {
    $this->name = $name;
    $this->value = $value;
  }
}
