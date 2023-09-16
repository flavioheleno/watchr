<?php
declare(strict_types = 1);

namespace Watchr\Console\Traits;

use DateInterval;

trait DateUtilsTrait {
  private function timeAgo(DateInterval $interval): string {
    if ($interval->y > 0) {
      return $interval->y === 1 ? '1 year ago' : $interval->y . ' years ago';
    }

    if ($interval->m > 0) {
      return $interval->m === 1 ? '1 month ago' : $interval->m . ' months ago';
    }

    if ($interval->d > 0) {
      return $interval->d === 1 ? '1 day ago' : $interval->d . ' days ago';
    }

    if ($interval->h > 0) {
      return $interval->h === 1 ? '1 hour ago' : $interval->h . ' hours ago';
    }

    if ($interval->i > 0) {
      return $interval->i === 1 ? '1 minute ago' : $interval->i . ' minutes ago';
    }

    if ($interval->s > 30) {
      return $interval->s . ' seconds ago';
    }

    return 'just now';
  }
}
