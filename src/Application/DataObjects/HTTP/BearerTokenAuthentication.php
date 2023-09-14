<?php
declare(strict_types = 1);

namespace Watchr\Application\DataObjects\HTTP;

use Watchr\Application\Contracts\HTTP\HttpAuthenticationInterface;

final class BearerTokenAuthentication implements HttpAuthenticationInterface {
  public readonly string $token;

  public function __construct(string $token) {
    $this->token = $token;
  }
}
