<?php
declare(strict_types = 1);

namespace Watchr\Application\Contracts\Configuration;

use Nette\Schema\Schema;

interface ConfigurationInterface {
  public static function getSchema(): Schema;
}
