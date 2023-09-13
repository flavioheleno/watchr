<?php
declare(strict_types = 1);

namespace Watchr\Application\DataObjects\HTTP;

use Watchr\Application\Contracts\HTTP\HttpAuthenticationInterface;

final class HeaderAuthentication implements HttpAuthenticationInterface {
  public readonly string $name;
  public readonly string $value;

  public function __construct(string $name, string $value) {
    $this->name = $name;
    $this->value = $value;
  }
}
