<?php
declare(strict_types = 1);

namespace Watchr\Console\DataObjects\Domain;

use DateTimeInterface;

final class DomainInfo {
  public readonly string $domainName;
  public readonly string $whoisServer;
  /**
   * @var string[]
   */
  public readonly array $nameServers;
  public readonly DateTimeInterface|null $creationDate;
  public readonly DateTimeInterface|null $expirationDate;
  public readonly DateTimeInterface|null $updatedDate;
  /**
   * @var string[]
   */
  public readonly array $states;
  public readonly string $owner;
  public readonly string $registrar;
  public readonly DnsSec|null $dnssec;

  /**
   * @param string[] $nameServers
   * @param string[] $states
   */
  public function __construct(
    string $domainName,
    string $whoisServer,
    array $nameServers,
    DateTimeInterface|null $creationDate,
    DateTimeInterface|null $expirationDate,
    DateTimeInterface|null $updatedDate,
    array $states,
    string $owner,
    string $registrar,
    DnsSec|null $dnssec
  ) {
    $this->domainName = $domainName;
    $this->whoisServer = $whoisServer;
    $this->nameServers = $nameServers;
    $this->creationDate = $creationDate;
    $this->expirationDate = $expirationDate;
    $this->updatedDate = $updatedDate;
    $this->states = $states;
    $this->owner = $owner;
    $this->registrar = $registrar;
    $this->dnssec = $dnssec;
  }
}
