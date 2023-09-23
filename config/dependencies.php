<?php
declare(strict_types = 1);

use AcmePhp\Ssl\Parser\CertificateParser;
use DI\ContainerBuilder;
use Iodev\Whois\Factory;
use Iodev\Whois\Whois;
use Juanparati\RDAPLib\RDAPClient;
use Ocsp\CertificateInfo;
use Ocsp\CertificateLoader;
use Ocsp\Ocsp;
use Psr\Clock\ClockInterface;
use Psr\Container\ContainerInterface;
use Symfony\Component\Clock\NativeClock;

return static function (ContainerBuilder $builder): void {
  $builder->addDefinitions(
    [
      CertificateInfo::class => static function (ContainerInterface $container): CertificateInfo {
        return new CertificateInfo();
      },
      CertificateLoader::class => static function (ContainerInterface $container): CertificateLoader {
        return new CertificateLoader();
      },
      CertificateParser::class => static function (ContainerInterface $container): CertificateParser {
        return new CertificateParser();
      },
      ClockInterface::class => static function (ContainerInterface $container): ClockInterface {
        return new NativeClock();
      },
      Ocsp::class => static function (ContainerInterface $container): Ocsp {
        return new Ocsp();
      },
      RDAPClient::class => static function (ContainerInterface $container): RDAPClient {
        return new RDAPClient(['domain' => 'https://rdap.org/domain/']);
      },
      Whois::class => static function (ContainerInterface $container): Whois {
        return Factory::get()->createWhois();
      }
    ]
  );
};
