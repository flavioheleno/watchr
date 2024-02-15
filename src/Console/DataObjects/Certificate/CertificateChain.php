<?php
declare(strict_types = 1);

namespace Watchr\Console\DataObjects\Certificate;

use Countable;
use Iterator;
use JsonSerializable;
use OutOfBoundsException;

final class CertificateChain implements Countable, Iterator, JsonSerializable {
  /**
   * @var \Watchr\Console\DataObjects\Certificate[]
   */
  private array $certificates;
  private int $index;
  private int $count;

  public function __construct(Certificate ...$certificates) {
    $this->certificates = $certificates;
    $this->index = 0;
    $this->count = count($certificates);
  }

  public function at(int $index): Certificate {
    if (isset($this->certificates[$index]) === false) {
      throw new OutOfBoundsException("Certificate at index {$index} not found");
    }

    return $this->certificates[$index];
  }

  public function count(): int {
    return $this->count;
  }

  public function current(): Certificate {
    return $this->certificates[$this->index];
  }

  public function key(): int {
    return $this->index;
  }

  public function next(): void {
    $this->index++;
  }

  public function rewind(): void {
    $this->index = 0;
  }

  public function valid(): bool {
    return isset($this->certificates[$this->index]);
  }

  public function jsonSerialize(): mixed {
    return $this->certificates;
  }
}
