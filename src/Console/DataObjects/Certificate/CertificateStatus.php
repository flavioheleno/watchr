<?php
declare(strict_types = 1);

namespace Watchr\Console\DataObjects\Certificate;

use DateTimeImmutable;
use DateTimeInterface;
use JsonSerializable;

final class CertificateStatus implements JsonSerializable {
  public readonly DateTimeImmutable $lastUpdate;
  public readonly DateTimeImmutable|null $revokedOn;
  public readonly string|null $revocationReason;
  public readonly DateTimeImmutable|null $nextUpdate;

  public function __construct(
    DateTimeImmutable $lastUpdate,
    DateTimeImmutable|null $revokedOn,
    string|null $revocationReason,
    DateTimeImmutable|null $nextUpdate
  ) {
    $this->lastUpdate = $lastUpdate;
    $this->revokedOn = $revokedOn;
    $this->revocationReason = $revocationReason;
    $this->nextUpdate = $nextUpdate;
  }

  public function isRevoked(): bool {
    return $this->revokedOn !== null;
  }

  public function jsonSerialize(): mixed {
    return [
      'lastUpdate' => $this->lastUpdate->format(DateTimeInterface::ATOM),
      'revokedOn' => $this->revokedOn?->format(DateTimeInterface::ATOM),
      'revocationReason' => $this->revocationReason,
      'nextUpdate' => $this->nextUpdate?->format(DateTimeInterface::ATOM)
    ];
  }
}
