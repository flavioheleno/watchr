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
}
