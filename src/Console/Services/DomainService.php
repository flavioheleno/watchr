<?php
declare(strict_types = 1);

namespace Watchr\Console\Services;

use DateTimeImmutable;
use Exception;
use InvalidArgumentException;
use Iodev\Whois\Whois;
use Juanparati\RDAPLib\RDAPClient;
use RuntimeException;
use Watchr\Console\DataObjects\Domain\DnsSec;
use Watchr\Console\DataObjects\Domain\DomainInfo;

class DomainService {
  private RDAPClient $rdapClient;
  private Whois $whois;


  /**
    string $whoisServer,
    array $nameServers,
    DateTimeInterface $creationDate,
    DateTimeInterface $expirationDate,
    DateTimeInterface $updatedDate,
    array $states,
    string $owner,
    string $registrar,
    DnsSec|null $dnssec

    int $keyTag,
    int $algorithm,
    int $digestType,
    string $digest
  */

  private function rdapLookup(string $domain): DomainInfo|null {
    try {
      $info = $this->rdapClient->domainLookup($domain, RDAPClient::ARRAY_OUTPUT);
      if ($info === null) {
        return null;
      }

      $dnsSec = null;
      if ($info['secureDNS']['delegationSigned'] === true) {
        $dnsSec = new DnsSec(
          $info['secureDNS']['dsData'][0]['keyTag'] ??
            $info['secureDNS']['dsData'][0]['keytag'] ??
            null,
          $info['secureDNS']['dsData'][0]['algorithm'] ?? null,
          $info['secureDNS']['dsData'][0]['digestType'] ??
            $info['secureDNS']['dsData'][0]['digesttype'] ??
            null,
          $info['secureDNS']['dsData'][0]['digest'] ?? null
        );
      }

      $events = array_reduce(
        $info['events'],
        static function (array $carry, array $entry): array {
          $carry[$entry['eventAction']] = new DateTimeImmutable($entry['eventDate']);

          return $carry;
        },
        []
      );

      $registrar = array_filter(
        $info['entities'],
        static function (array $entry): bool {
          return in_array('registrar', $entry['roles'], true);
        }
      );

      $registrar = $registrar[0]['vcardArray'][1][1][3] ?? '';

      return new DomainInfo(
        $domain,
        'https://rdap.org/domain/',
        array_reduce(
          array_filter(
            $info['nameservers'],
            static function (array $entry): bool {
              return $entry['objectClassName'] === 'nameserver';
            }
          ),
          static function (array $carry, array $entry): array {
            $carry[] = strtolower($entry['ldhName']);

            return $carry;
          },
          []
        ),
        $events['registration'],
        $events['expiration'],
        $events['last changed'],
        array_map(
          static function (string $entry): string {
            return str_replace(' ', '', $entry);
          },
          $info['status']
        ),
        '',
        $registrar,
        $dnsSec
      );
    } catch (Exception $exception) {
      // TODO: add $exception to logging
      return null;
    }
  }

  private function whoisLookup(string $domain): DomainInfo|null {
    $info = $this->whois->loadDomainInfo($domain);
    if ($info === null) {
      return null;
    }

    return new DomainInfo(
      $domain,
      $info->whoisServer,
      $info->nameServers,
      (new DateTimeImmutable())->setTimestamp($info->creationDate),
      (new DateTimeImmutable())->setTimestamp($info->expirationDate),
      (new DateTimeImmutable())->setTimestamp($info->updatedDate),
      $info->states,
      $info->owner,
      $info->registrar,
      $info->dnssec === 'signedDelegation' ? new DnsSec() : null
    );
  }

  public function __construct(RDAPClient $rdapClient, Whois $whois) {
    $this->rdapClient = $rdapClient;
    $this->whois = $whois;
  }

  public function lookup(string $domain): DomainInfo {
    if (filter_var($domain, FILTER_VALIDATE_DOMAIN) === false) {
      throw new InvalidArgumentException('Invalid domain argument');
    }

    $domainInfo = $this->rdapLookup($domain);
    if ($domainInfo === null) {
      $domainInfo = $this->whoisLookup($domain);
    }

    if ($domainInfo === null) {
      throw new RuntimeException('Failed to lookup domain');
    }

    return $domainInfo;
  }
}
