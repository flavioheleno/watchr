<?php
declare(strict_types = 1);

namespace Watchr\Console\DataObjects\HTTP;

use Watchr\Console\Contracts\HTTP\HttpAuthenticationInterface;

final class BasicAuthentication implements HttpAuthenticationInterface {
  public readonly string $username;
  public readonly string $password;

  public function __construct(
    string $username,
    string $password
  ) {
    $this->username = $username;
    $this->password = $password;
  }
}
