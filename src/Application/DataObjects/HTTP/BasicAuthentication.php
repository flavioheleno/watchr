<?php
declare(strict_types = 1);

namespace Watchr\Application\DataObjects\HTTP;

use Watchr\Application\Contracts\HTTP\HttpAuthenticationInterface;
use Watchr\Application\Contracts\HTTP\HttpAuthenticationLocationEnum;

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
