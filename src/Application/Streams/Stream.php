<?php
declare(strict_types = 1);

namespace Watchr\Application\Streams;

use InvalidArgumentException;
use RuntimeException;
use Watchr\Application\Contracts\Streams\StreamInterface;

/**
 * PHP stream implementation
 *
 * @link https://github.com/guzzle/streams/blob/master/src/Stream.php
 */
class Stream implements StreamInterface {
  private $stream;
  private int|null $size = null;
  private bool $seekable = false;
  private bool $readable = false;
  private bool $writable = false;
  private string|null $uri = null;
  private array $customMetadata = [];

  /** @var array Hash of readable and writable stream types */
  private static $readWriteHash = [
    'read' => [
      'r' => true, 'w+' => true, 'r+' => true, 'x+' => true, 'c+' => true,
      'rb' => true, 'w+b' => true, 'r+b' => true, 'x+b' => true,
      'c+b' => true, 'rt' => true, 'w+t' => true, 'r+t' => true,
      'x+t' => true, 'c+t' => true, 'a+' => true
    ],
    'write' => [
      'w' => true, 'w+' => true, 'rw' => true, 'r+' => true, 'x+' => true,
      'c+' => true, 'wb' => true, 'w+b' => true, 'r+b' => true,
      'x+b' => true, 'c+b' => true, 'w+t' => true, 'r+t' => true,
      'x+t' => true, 'c+t' => true, 'a' => true, 'a+' => true
    ]
  ];

  public function __construct($stream, int $size = null, array $metadata = []) {
    if (is_resource($stream) === false) {
      throw new InvalidArgumentException('Stream must be a resource');
    }

    if ($size !== null) {
      $this->size = $size;
    }

    $this->customMetadata = $metadata;

    $this->attach($stream);
  }

  /**
   * Closes the stream when the destructed
   */
  public function __destruct() {
    $this->close();
  }

  public function __toString(): string {
    if ($this->stream === null) {
      return '';
    }

    $this->seek(0);

    return (string)stream_get_contents($this->stream);
  }

  public function close(): void {
    if (is_resource($this->stream)) {
      fclose($this->stream);
    }

    $this->detach();
  }

  public function detach(): mixed {
    $result = $this->stream;
    $this->stream = $this->size = $this->uri = null;
    $this->readable = $this->writable = $this->seekable = false;

    return $result;
  }

  public function attach($stream): void {
    $this->stream = $stream;
    $meta = stream_get_meta_data($this->stream);
    $this->seekable = $meta['seekable'];
    $this->readable = isset(self::$readWriteHash['read'][$meta['mode']]);
    $this->writable = isset(self::$readWriteHash['write'][$meta['mode']]);
    $this->uri = $this->getMetadata('uri');
  }

  public function getSize(): int|null {
    if ($this->size !== null) {
      return $this->size;
    }

    if ($this->stream === null) {
      return null;
    }

    // Clear the stat cache if the stream has a URI
    if ($this->uri !== null) {
      clearstatcache(true, $this->uri);
    }

    $stats = fstat($this->stream);
    if (isset($stats['size'])) {
      $this->size = $stats['size'];

      return $this->size;
    }

    return null;
  }

  public function tell(): int {
    if ($this->stream === null) {
      throw new RuntimeException('Invalid stream state');
    }

    return ftell($this->stream);
  }

  public function eof(): bool {
    return $this->stream === null || feof($this->stream);
  }

  public function isSeekable(): bool {
    return $this->seekable;
  }

  public function seek(int $offset, int $whence = SEEK_SET): bool {
    if ($this->seekable === false) {
      throw new RuntimeException('Stream is not seekable');
    }

    return fseek($this->stream, $offset, $whence) === 0;
  }

  public function isWritable(): bool {
    return $this->writable;
  }

  public function write(string $data): int {
    if ($this->writable === false) {
      throw new RuntimeException('Stream is not writable');
    }

    // We can't know the size after writing anything
    $this->size = null;

    return fwrite($this->stream, $data);
  }

  public function isReadable(): bool {
    return $this->readable;
  }

  public function read(int $length): string {
    if ($this->readable === false) {
      throw new RuntimeException('Stream is not readable');
    }

    return fread($this->stream, $length);
  }

  public function getContents(): string {
    return $this->stream ? stream_get_contents($this->stream) : '';
  }

  public function getMetadata(string $key = null): mixed {
    if ($this->stream === null) {
      return $key === null ? null : [];
    } elseif ($key === null) {
      return $this->customMetadata + stream_get_meta_data($this->stream);
    } elseif (isset($this->customMetadata[$key])) {
        return $this->customMetadata[$key];
    }

    $meta = stream_get_meta_data($this->stream);

    return $meta[$key] ?? null;
  }

  public function readOnly(): void {
    $this->writable = false;
  }
}
