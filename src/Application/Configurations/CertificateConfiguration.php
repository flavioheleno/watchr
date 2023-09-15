<?php
declare(strict_types = 1);

namespace Watchr\Application\Configurations;

use Nette\Schema\Expect;
use Nette\Schema\Schema;
use Watchr\Application\Contracts\Configuration\ConfigurationInterface;

final class CertificateConfiguration implements ConfigurationInterface {
  public static function getSchema(): Schema {
    return Expect::structure(
      [
        'enabled' => Expect::bool(false),
        // expiration threshold in days, default 5 days
        'expirationThreshold' => Expect::int(5)->min(-1),
        // sha-1, hex encoded string
        'sha1Fingerprint' => Expect::string()->pattern('[0-9a-fA-F]{40}'),
          // sha-256, hex encoded string
        'sha256Fingerprint' => Expect::string()->pattern('[0-9a-fA-F]{64}'),
        // certificate serial number, hex encoded string
        'serialNumber' => Expect::string()->pattern('(0x)?[0-9a-fA-F]+'),
        'issuerName' => Expect::string(),
        // ocsp revocation list
        'ocspRevoked' => Expect::bool(false),
        // additional hosts (subdomains) to perform certificate check
        'hosts' => Expect::listOf('string')
      ]
    )->required(false);
  }
}
