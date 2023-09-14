<?php
declare(strict_types = 1);

namespace Watchr\Application\Streams;

use Watchr\Application\Contracts\Streams\StreamInterface;

/**
* Does not store any data written to it.
*
* @link https://github.com/guzzle/streams/blob/master/src/NullStream.php
*/
class NullStream implements StreamInterface {
  public function __toString(): string {
    return '';
  }

  public function getContents(): string {
    return '';
  }

  public function close(): void {}

  public function detach(): mixed {
    return null;
  }

  public function attach($stream): void {
    throw new RuntimeException('Cannot attach stream');
  }

  public function getSize(): int|null {
    return 0;
  }

  public function isReadable(): bool {
    return true;
  }

  public function isWritable(): bool {
    return true;
  }

  public function isSeekable(): bool {
    return true;
  }

  public function eof(): bool {
    return true;
  }

  public function tell(): int {
    return 0;
  }

  public function seek(int $offset, int $whence = SEEK_SET): bool {
    return false;
  }

  public function read(int $length): string {
    throw new RuntimeException('Failed to read stream');
  }

  public function write(string $data): int {
    return strlen($data);
  }

  public function getMetadata(string $key = null): mixed {
    return $key === null ? null : [];
  }

  public function readOnly(): void {}
}
