<?php
declare(strict_types = 1);

use DI\ContainerBuilder;
use GuzzleHttp\Client;
use Iodev\Whois\Factory;
use Juanparati\RDAPLib\RDAPClient;
use Ocsp\CertificateInfo;
use Ocsp\CertificateLoader;
use Ocsp\Ocsp;
use Psr\Clock\ClockInterface;
use Psr\Container\ContainerInterface;
use Symfony\Component\Clock\NativeClock;
use Watchr\Console\Services\CertificateService;
use Watchr\Console\Services\DomainService;
use Watchr\Console\Services\HttpService;

return static function (ContainerBuilder $builder): void {
  $builder->addDefinitions(
    [
      CertificateService::class => static function (ContainerInterface $container): CertificateService {
        return new CertificateService(
          30,
          120,
          sprintf('watchr (PHP %s; %s)', PHP_VERSION, PHP_OS_FAMILY),
          new CertificateInfo(),
          new CertificateLoader(),
          new Ocsp()
        );
      },
      DomainService::class => static function (ContainerInterface $container): DomainService {
        return new DomainService(
          new RDAPClient(
            ['domain' => 'https://rdap.org/domain/'],
            new Client()
          ),
          Factory::get()->createWhois()
        );
      },
      ClockInterface::class => static function (ContainerInterface $container): ClockInterface {
        return new NativeClock();
      },
      HttpService::class => static function (ContainerInterface $container): HttpService {
        return new HttpService(
          30,
          120,
          sprintf('watchr (PHP %s; %s)', PHP_VERSION, PHP_OS_FAMILY)
        );
      }
    ]
  );
};
