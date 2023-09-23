<?php
declare(strict_types = 1);

namespace Watchr\Console\DataObjects\Domain;

final class DnsSec {
  public readonly int|null $keyTag;
  public readonly int|null $algorithm;
  public readonly int|null $digestType;
  public readonly string|null $digest;

  public function __construct(
    int|null $keyTag = null,
    int|null $algorithm = null,
    int|null $digestType = null,
    string|null $digest = null
  ) {
    $this->keyTag = $keyTag;
    $this->algorithm = $algorithm;
    $this->digestType = $digestType;
    $this->digest = $digest;
  }
}
