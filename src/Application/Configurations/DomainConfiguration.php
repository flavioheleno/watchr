<?php
declare(strict_types = 1);

namespace Watchr\Application\Configurations;

use Nette\Schema\Expect;
use Nette\Schema\Schema;
use Watchr\Application\Contracts\Configuration\ConfigurationInterface;

final class DomainConfiguration implements ConfigurationInterface {
  public static function getSchema(): Schema {
    return Expect::structure(
      [
        'enabled' => Expect::bool(false),
        // expiration threshold in days, default 5 days
        'expirationThreshold' => Expect::int(5)->min(-1),
        'registrarName' => Expect::string(),
        // domain status flags (eg. clientTransferProhibited)
        'statusFlags' => Expect::arrayOf('string')
      ]
    )->required(false);
  }
}
