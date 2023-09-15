# watchr

**Watchr** is a command-line utility to check for Domain Name and TLS Certificates expiration dates.

## Configuration file

> Note: Only json-encoded files are currently supported.

### Global options

Entries at **root** level. [Reference](config/dependencies.php).

 Name      | Description                                                        | Type     | Required | Default value
-----------|--------------------------------------------------------------------|----------|----------|---------------
`subject`  | The subject name (aka. domain name) to be checked                  | `string` | `yes`    | `empty`
`failFast` | Exits immediately when a check fails instead of running all checks | `bool`   | `no`     | `false`

### Certificate options

Entries under the **certificate** key. [Reference](src/Application/Configurations/CertificateConfiguration.php).

 Name                 | Description                                                                      | Type       | Required | Default value
----------------------|----------------------------------------------------------------------------------|------------|----------|---------------
`enabled`             | Control certificate check                                                        | `bool`     | `no`     | `false`
`expirationThreshold` | The maximum number of days until certificate expiration                          | `int`      | `no`     | `5`
`sha1Fingerprint`     | Certificate's SHA-1 Fingerprint                                                  | `string`   | `no`     | `empty`
`sha256Fingerprint`   | Certificate's SHA-256 Fingerprint                                                | `string`   | `no`     | `empty`
`serialNumber`        | Certificate's serial number                                                      | `string`   | `no`     | `empty`
`issuerName`          | Issuer's common name                                                             | `string`   | `no`     | `empty`
`ocspRevoked`         | Check if the certificate is revoked using the Online Certificate Status Protocol | `bool`     | `no`     | `false`
`hosts`               | List of hosts to be verified (`<host>.<subject>`)                                | `string[]` | `no`     | `empty`

> Note: Settings values are shared by all combined hosts, ie. all certificates will be verified using the same
> `expirationThreshold`, `sha1Fingerprint`... etc.

### Domain options

Entries under the **domain** key. [Reference](src/Application/Configurations/DomainConfiguration.php).

 Name                 | Description                                                                | Type       | Required | Default value
----------------------|----------------------------------------------------------------------------|------------|----------|---------------
`enabled`             | Control domain check                                                       | `bool`     | `no`     | `false`
`expirationThreshold` | The maximum number of days until domain expiration                         | `int`      | `no`     | `5`
`registrarName`       | Registrar's name                                                           | `string`   | `no`     | `empty`
`statusFlags`         | List of Extensible Provisioning Protocol (EPP) status codes to be verified | `string[]` | `no`     | `empty`

### Example file

```json
{
  "subject": "github.com",
  "failFast": false,
  "certificate": {
    "enabled": true,
    "sha1Fingerprint": "a3b59e5fe884ee1f34d98eef858e3fb662ac104a",
    "sha256Fingerprint": "92a37fbd5e21a53a95c716e1144f442f582b94d0fafc673eb6717a4eb51a88a7",
    "serialNumber": "17034156255497985825694118641198758684",
    "issuerName": "DigiCert TLS Hybrid ECC SHA384 2020 CA1",
    "ocspRevoked": true,
    "hosts": [
      "gist"
    ]
  },
  "domain": {
    "enabled": true,
    "registrarName": "MarkMonitor, Inc.",
    "statusFlags": ["clientTransferProhibited", "clientUpdateProhibited", "clientDeleteProhibited"]
  }
}
```

### Example output

```shell
$ ./bin/console.php check:all -vvv --config ./github.json
Subject: github.com

+-----------------+---------+--------------------------------------------------------------------------+
| Verification    | Status  | Value                                                                    |
+-----------------+---------+--------------------------------------------------------------------------+
| Expiration Date | enabled | 5 days                                                                   |
| Registrar Name  | enabled | MarkMonitor, Inc.                                                        |
| Status Flags    | enabled | clientTransferProhibited, clientUpdateProhibited, clientDeleteProhibited |
+-----------------+---------+--------------------------------------------------------------------------+

Starting domain check
Domain expiration date is 2024-10-09T00:00:00+00:00 (1728432000)
Domain expires in 389 days
Registrar name MarkMonitor, Inc.
Active status flags clientupdateprohibited, clienttransferprohibited, clientdeleteprohibited
Finished domain check

Subject: github.com

+---------------------+---------+------------------------------------------------------------------+
| Verification        | Status  | Value                                                            |
+---------------------+---------+------------------------------------------------------------------+
| Expiration Date     | enabled | 5 days                                                           |
| SHA-1 Fingerprint   | enabled | a3b59e5fe884ee1f34d98eef858e3fb662ac104a                         |
| SHA-256 Fingerprint | enabled | 92a37fbd5e21a53a95c716e1144f442f582b94d0fafc673eb6717a4eb51a88a7 |
| Serial Number       | enabled | 17034156255497985825694118641198758684                           |
| Issuer Name         | enabled | DigiCert TLS Hybrid ECC SHA384 2020 CA1                          |
| OCSP Revoked        | enabled |                                                                  |
+---------------------+---------+------------------------------------------------------------------+

Starting certificate check
Checking hostname github.com
Certificate chain size: 2
Certificate expiration date is 2024-03-14T23:59:59+00:00
Certificate expires in 181 days
Certificate SHA-1 Fingerprint is a3b59e5fe884ee1f34d98eef858e3fb662ac104a
Certificate SHA-256 Fingerprint is 92a37fbd5e21a53a95c716e1144f442f582b94d0fafc673eb6717a4eb51a88a7
Certificate Serial Number is 17034156255497985825694118641198758684
Certificate Issuer Name is DigiCert TLS Hybrid ECC SHA384 2020 CA1
OCSP Revocation list was last updated 2 hours ago (2023-09-15T00:39:01+00:00)

Checking hostname gist.github.com
Certificate chain size: 2
Certificate expiration date is 2024-03-15T23:59:59+00:00
Certificate expires in 182 days
Certificate SHA-1 Fingerprint is 2d796c902dad8a2e4fd1e299ede891293640f858
Certificate SHA-256 Fingerprint is b6174d4c3ec5ae768610ad705544b4600e514a55718a94c636563cbaa4dd664c
Certificate Serial Number is 15332958398536206813459919731602041253
Certificate Issuer Name is DigiCert TLS Hybrid ECC SHA384 2020 CA1
OCSP Revocation list was last updated 5 hours ago (2023-09-14T22:33:01+00:00)
Finished certificate check

Found 3 errors:
  Certificate SHA-1 Fingerprint "2d796c902dad8a2e4fd1e299ede891293640f858" for hostname "gist.github.com" does not match the expected fingerprint "a3b59e5fe884ee1f34d98eef858e3fb662ac104a"
  Certificate SHA-256 Fingerprint "b6174d4c3ec5ae768610ad705544b4600e514a55718a94c636563cbaa4dd664c" for hostname "gist.github.com" does not match the expected fingerprint "92a37fbd5e21a53a95c716e1144f442f582b94d0fafc673eb6717a4eb51a88a7"
  Certificate Serial Number "15332958398536206813459919731602041253" for hostname "gist.github.com" does not match the expected "17034156255497985825694118641198758684"
```

## License

This project is licensed under the [MIT License](LICENSE).
