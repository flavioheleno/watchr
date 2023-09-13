<?php
declare(strict_types = 1);

namespace Watchr\Application\Contracts\HTTP;

enum HttpRequestMethodEnum: string {
  case GET = 'GET';
  case HEAD = 'HEAD';
  case POST = 'POST';
  case PUT = 'PUT';
  case DELETE = 'DELETE';
  case CONNECT = 'CONNECT';
  case OPTIONS = 'OPTIONS';
  case TRACE = 'TRACE';
  case PATCH = 'PATCH';
}
