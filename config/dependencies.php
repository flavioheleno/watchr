<?php
declare(strict_types = 1);

use AcmePhp\Ssl\Parser\CertificateParser;
use DI\ContainerBuilder;
use Iodev\Whois\Factory;
use Iodev\Whois\Whois;
use League\Config\Configuration;
use Nette\Schema\Expect;
use Ocsp\CertificateInfo;
use Ocsp\CertificateLoader;
use Ocsp\Ocsp;
use Psr\Clock\ClockInterface;
use Psr\Container\ContainerInterface;
use Symfony\Component\Clock\NativeClock;
use Watchr\Application\Configurations\CertificateConfiguration;
use Watchr\Application\Configurations\DomainConfiguration;

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
      Configuration::class => static function (ContainerInterface $container): Configuration {
        return new Configuration(
          [
            'subject' => Expect::string()->required(),
            'failFast' => Expect::bool(false),
            'certificate' => CertificateConfiguration::getSchema(),
            'domain' => DomainConfiguration::getSchema()
          ]
        );
      },
      Ocsp::class => static function (ContainerInterface $container): Ocsp {
        return new Ocsp();
      },
      Whois::class => static function (ContainerInterface $container): Whois {
        return Factory::get()->createWhois();
      }
    ]
  );
};
