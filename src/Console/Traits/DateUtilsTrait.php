<?php
declare(strict_types = 1);

namespace Watchr\Console\Traits;

use DateInterval;

trait DateUtilsTrait {
  private function humanReadableInterval(DateInterval $interval): string {
    $format = '%d %s ago';
    if ($interval->invert === 0) {
      $format = 'in %d %s';
    }

    if ($interval->y > 0) {
      return sprintf(
        $format,
        $interval->y,
        $interval->y === 1 ? 'year' : 'years'
      );
    }

    if ($interval->m > 0) {
      return sprintf(
        $format,
        $interval->m,
        $interval->m === 1 ? 'month' : 'months'
      );
    }

    if ($interval->d > 0) {
      return sprintf(
        $format,
        $interval->d,
        $interval->d === 1 ? 'day' : 'days'
      );
    }

    if ($interval->h > 0) {
      return sprintf(
        $format,
        $interval->h,
        $interval->h === 1 ? 'hour' : 'hours'
      );
    }

    if ($interval->i > 0) {
      return sprintf(
        $format,
        $interval->i,
        $interval->i === 1 ? 'minute' : 'minutes'
      );
      return $interval->i === 1 ? '1 minute ago' : $interval->i . ' minutes ago';
    }

    if ($interval->s > 30) {
      return sprintf(
        $format,
        $interval->s,
        'seconds'
      );
    }

    return 'just now';
  }

  private function fromMicroseconds(int $microseconds): string {
    if ($microseconds < 1000) {
      return "{$microseconds}us";
    }

    return sprintf(
      '%s %s',
      $this->fromMilliseconds(intdiv($microseconds, 1000)),
      $this->fromMicroseconds($microseconds % 1000)
    );
  }

  private function fromMilliseconds(int $milliseconds): string {
    if ($milliseconds < 1000) {
      return "{$milliseconds}ms";
    }

    return sprintf(
      '%s %s',
      $this->fromSeconds(intdiv($milliseconds, 1000)),
      $this->fromMilliseconds($milliseconds % 1000)
    );
  }

  private function fromSeconds(int $seconds): string {
    if ($seconds < 60) {
      return "{$seconds}s";
    }

    return sprintf(
      '%s %s',
      $this->fromMinutes(intdiv($seconds, 60)),
      $this->fromSeconds($seconds % 60)
    );
  }

  private function fromMinutes(int $minutes): string {
    if ($minutes < 60) {
      return "{$minutes}m";
    }

    return sprintf(
      '%s %s',
      $this->fromHours(intdiv($minutes, 60)),
      $this->fromMinutes($minutes % 60)
    );
  }

  private function fromHours(int $hours): string {
    if ($hours < 24) {
      return "{$hours}h";
    }

    return sprintf(
      '%s %s',
      $this->fromDays(intdiv($hours, 24)),
      $this->fromHours($hours % 24)
    );
  }

  private function fromDays(int $days): string {
    if ($days < 365) {
      return "{$days}d";
    }

    return sprintf(
      '%dy %s',
      intdiv($days, 365),
      $this->fromDays($days % 365)
    );
  }
}
