<?php
declare(strict_types = 1);

namespace Watchr\Application\Contracts\Streams;

use Stringable;

/**
 * Describes a stream instance.
 *
 * @link https://github.com/guzzle/streams/blob/master/src/StreamInterface.php
 */
interface StreamInterface extends Stringable {
  /**
   * Attempts to seek to the beginning of the stream and reads all data into
   * a string until the end of the stream is reached.
   *
   * Warning: This could attempt to load a large amount of data into memory.
   */
  public function __toString(): string;

  /**
   * Closes the stream and any underlying resources.
   */
  public function close(): void;

  /**
   * Separates any underlying resources from the stream.
   *
   * After the underlying resource has been detached, the stream object is in
   * an unusable state. If you wish to use a Stream object as a PHP stream
   * but keep the Stream object in a consistent state, use
   * {@see GuzzleHttp\Stream\GuzzleStreamWrapper::getResource}.
   *
   * @return resource|null Returns the underlying PHP stream resource or null
   *                       if the Stream object did not utilize an underlying
   *                       stream resource.
   */
  public function detach(): mixed;

  /**
   * Replaces the underlying stream resource with the provided stream.
   *
   * Use this method to replace the underlying stream with another; as an
   * example, in server-side code, if you decide to return a file, you
   * would replace the original content-oriented stream with the file
   * stream.
   *
   * Any internal state such as caching of cursor position should be reset
   * when attach() is called, as the stream has changed.
   *
   * @param resource $stream
   */
  public function attach($stream): void;

  /**
   * Get the size of the stream if known, or null if unknown
   */
  public function getSize(): int|null;

  /**
   * Returns the current position of the file read/write pointer
   *
   * @throws RuntimeException
   */
  public function tell(): int;

  /**
   * Returns true if the stream is at the end of the stream.
   */
  public function eof(): bool;

  /**
   * Returns whether or not the stream is seekable
   */
  public function isSeekable(): bool;

  /**
   * Seek to a position in the stream
   * Returns true on success or false on failure
   *
   * @param int $offset Stream offset
   * @param int $whence Specifies how the cursor position will be calculated
   *                    based on the seek offset. Valid values are identical
   *                    to the built-in PHP $whence values for `fseek()`.
   *                    SEEK_SET: Set position equal to offset bytes
   *                    SEEK_CUR: Set position to current location plus offset
   *                    SEEK_END: Set position to end-of-stream plus offset
   *
   * @link   http://www.php.net/manual/en/function.fseek.php
   */
  public function seek(int $offset, int $whence = SEEK_SET): bool;

  /**
   * Returns whether or not the stream is writable
   */
  public function isWritable(): bool;

  /**
   * Write data to the stream
   *
   * @param string $string The string that is to be written.
   *
   * @throws RuntimeException
   *
   * @return int Returns the number of bytes written to the stream
   */
  public function write(string $string): int;

  /**
   * Returns whether or not the stream is readable
   */
  public function isReadable(): bool;

  /**
   * Read data from the stream
   *
   * @param int $length Read up to $length bytes from the object and return
   *                    them. Fewer than $length bytes may be returned if
   *                    underlying stream call returns fewer bytes.
   */
  public function read(int $length): string;

  /**
   * Returns the remaining contents of the stream as a string.
   *
   * Note: this could potentially load a large amount of data into memory.
   */
  public function getContents(): string;

  /**
   * Get stream metadata as an associative array or retrieve a specific key.
   *
   * The keys returned are identical to the keys returned from PHP's
   * stream_get_meta_data() function.
   *
   * @param string $key Specific metadata to retrieve.
   *
   * @return array|mixed|null Returns an associative array if no key is
   *                          no key is provided. Returns a specific key
   *                          value if a key is provided and the value is
   *                          found, or null if the key is not found.
   * @see http://php.net/manual/en/function.stream-get-meta-data.php
   */
  public function getMetadata(string $key = null): mixed;

  public function readOnly(): void;
}
