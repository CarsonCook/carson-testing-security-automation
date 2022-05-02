# Development

Fix and verify within the nightly.

The catalog of known exploits is here: https://www.cisa.gov/known-exploited-vulnerabilities-catalog 

# Process

Under what circumstance we ship the release? What do we do?

# 2.0

## New - To be approved (In 2.0)

| CVE            | Module                | Severity | CVSS | Vector | Description   | Issue |
|----------------|:---------------------:|---------:|-----:|-------:|--------------:|------:|

## Approved (In 2.0)

| CVE            | Module                | Severity | CVSS | Vector | Description   | Issue |
|----------------|:---------------------:|---------:|-----:|-------:|--------------:|------:|
| BDSA-2019-3199 (CVE-2019-17495) | apiml | HIGH | 7.9 | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C | https://nvd.nist.gov/vuln/detail/CVE-2019-17495 | https://github.com/zowe/security-reports/issues/92 |
| BDSA-2021-3401 (CVE-2021-3401) | apiml | MEDIUM | 4.2 | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N/E:U/RL:O/RC:C | https://nvd.nist.gov/vuln/detail/CVE-2021-3401 | https://github.com/zowe/security-reports/issues/71 |
| CVE-2016-1000027 | apiml, jobs, datasets | CRITICAL | 9.8 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | https://nvd.nist.gov/vuln/detail/CVE-2016-1000027 | https://github.com/zowe/security-reports/issues/157 |
| CVE-2021-42550 (BDSA-2021-3818) | apiml | MEDIUM | 6.6 | CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H | https://nvd.nist.gov/vuln/detail/CVE-2021-42550 | https://github.com/zowe/security-reports/issues/125 |


# 1.28

## New - To be approved (In 1.28)

| CVE            | Module                | Severity | CVSS | Vector | Description   | Issue |
|----------------|:---------------------:|---------:|-----:|-------:|--------------:|------:|
| BDSA-2020-4373 (CVE-2020-7598) | zlux | MEDIUM | 5.6 | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L | https://nvd.nist.gov/vuln/detail/CVE-2020-7598 | https://github.com/zowe/security-reports/issues/145 |
| BDSA-2022-0771 (CVE-2021-44906) | zlux, explorers, cli, vscode explorer | CRITICAL | 9.8 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C | https://nvd.nist.gov/vuln/detail/CVE-2021-44906 | https://github.com/zowe/security-reports/issues/146 |
| BDSA-2022-0847 | apiml, jobs, datasets | HIGH | 7.1 | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C | Software systems using Spring Framework may be vulnerable to remote code execution (RCE) if they employ unsafe use of certain provided deserialization functionality. A remote attacker could potentially execute arbitrary code on a vulnerable endpoint by passing a maliciously crafted serialized object to that endpoint.  **Note** that this issue only affects software that has been written to leverage specific deserialization functionality provided by the Spring Framework without sanitization.
 | https://github.com/zowe/security-reports/issues/155 |
| CVE-2021-44907 | zlux | HIGH | 7.5 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H | https://nvd.nist.gov/vuln/detail/CVE-2021-44907 | https://github.com/zowe/security-reports/issues/148 |
| CVE-2022-24771 | zlux, systems | HIGH | 7.5 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N | https://nvd.nist.gov/vuln/detail/CVE-2022-24771 | https://github.com/zowe/security-reports/issues/151 |
| CVE-2022-24772 | zlux, systems | HIGH | 7.5 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N | https://nvd.nist.gov/vuln/detail/CVE-2022-24772 | https://github.com/zowe/security-reports/issues/151 |
| CVE-2022-24773 | zlux, systems | MEDIUM | 5.3 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N | https://nvd.nist.gov/vuln/detail/CVE-2022-24773 | https://github.com/zowe/security-reports/issues/151 |
## Approved (In 1.28)

| CVE            | Module                | Severity | CVSS | Vector | Description   | Issue |
|----------------|:---------------------:|---------:|-----:|-------:|--------------:|------:|
| BDSA-2019-3199 (CVE-2019-17495) | apiml | HIGH | 7.9 | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C | https://nvd.nist.gov/vuln/detail/CVE-2019-17495 | https://github.com/zowe/security-reports/issues/92 |
| BDSA-2021-3401 (CVE-2021-3401) | apiml | MEDIUM | 4.2 | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N/E:U/RL:O/RC:C | https://nvd.nist.gov/vuln/detail/CVE-2021-3401 | https://github.com/zowe/security-reports/issues/71 |
| CVE-2020-36518 (BDSA-2020-4752) | apiml, jobs, datasets | MEDIUM | 6.3 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:U/RL:U/RC:U | https://nvd.nist.gov/vuln/detail/CVE-2020-36518 | https://github.com/zowe/security-reports/issues/139 |
| CVE-2021-42550 (BDSA-2021-3818) | apiml | MEDIUM | 6.6 | CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H | https://nvd.nist.gov/vuln/detail/CVE-2021-42550 | https://github.com/zowe/security-reports/issues/125 |

## Fixed (Since 1.27 in 1.28)

- CVE-2021-23566 (BDSA-2022-0242)
- CVE-2020-28500 (BDSA-2021-0375)
- BDSA-2022-0820
- BDSA-2012-0001 (CVE-2012-0001)
- BDSA-2020-3798 (CVE-2020-15366)
- BDSA-2021-2621 (CVE-2021-3749)
- BDSA-2022-0111
- CVE-2018-10237 (BDSA-2018-1358)
- CVE-2020-5412 (BDSA-2020-4340)
- CVE-2020-7774 (BDSA-2020-3620)
- CVE-2020-8908 (BDSA-2020-3736)
- CVE-2021-3918
- CVE-2021-22119 (BDSA-2021-2310)
- CVE-2021-22053
- CVE-2021-22060
- CVE-2021-22096 (BDSA-2021-3236)
- CVE-2021-23337 (BDSA-2021-0392)
- CVE-2021-33037 (BDSA-2021-2072)
- CVE-2021-42340 (BDSA-2021-3085)
- CVE-2021-43859 (BDSA-2022-0291)
- CVE-2021-43466
- CVE-2021-43797 (BDSA-2021-3741)
- CVE-2022-0122 (BDSA-2022-0112)
- CVE-2022-0155 (BDSA-2022-0139)
- CVE-2022-0536 (BDSA-2022-0558)
- CVE-2022-23181 (BDSA-2022-0275)
- CVE-2022-23647 (BDSA-2022-0578)

# 1.27

## Approved (In 1.27)

| CVE            | Module                | Severity | CVSS | Vector | Description   | Issue |
|----------------|:---------------------:|---------:|-----:|-------:|--------------:|------:|
| BDSA-2012-0001 (CVE-2012-0001) |  apiml, job, datasets | MEDIUM   | 4.6 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N/E:U/RL:O/RC:C | https://nvd.nist.gov/vuln/detail/CVE-2012-0001 | https://github.com/zowe/security-reports/issues/91 |
| BDSA-2019-3199 (CVE-2019-17495) | apiml | High | 7.9 | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C | https://nvd.nist.gov/vuln/detail/CVE-2019-17495 | https://github.com/zowe/security-reports/issues/92 |
| BDSA-2020-3798 (CVE-2020-15366) | explorers | High | 7.1 | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C | https://nvd.nist.gov/vuln/detail/CVE-2020-15366 | https://github.com/zowe/security-reports/issues/93 |
| BDSA-2021-2621 (CVE-2021-3749) | zlux | MEDIUM | 4.8 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L/E:P/RL:O/RC:C | https://nvd.nist.gov/vuln/detail/CVE-2021-3749 | https://github.com/zowe/security-reports/issues/95 |
| BDSA-2021-3236 (CVE-2021-22096) | jobs, apiml, data-sets | MEDIUM | 4.7 | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L/E:U/RL:O/RC:C | https://nvd.nist.gov/vuln/detail/CVE-2021-22096 | https://github.com/zowe/security-reports/issues/70 |
| BDSA-2021-3401 (CVE-2021-3401) | apiml | MEDIUM | 4.2 | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N/E:U/RL:O/RC:C | https://nvd.nist.gov/vuln/detail/CVE-2021-3401 | https://github.com/zowe/security-reports/issues/71 |
| CVE-2018-10237 (BDSA-2018-1358) | apiml | MEDIUM | 5.9 | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H | https://nvd.nist.gov/vuln/detail/CVE-2018-10237 | https://github.com/zowe/security-reports/issues/112 |
| CVE-2020-5412 (BDSA-2020-4340) | apiml | Medium | 6.5 | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | https://nvd.nist.gov/vuln/detail/CVE-2020-5412 | https://github.com/zowe/security-reports/issues/109 |
| CVE-2020-8908 (BDSA-2020-3736) |  | LOW | 3.3 | CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N | https://nvd.nist.gov/vuln/detail/CVE-2020-8908 |  |
| CVE-2020-28500 (BDSA-2021-0375) | zlux | Medium | 5.3 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L | https://nvd.nist.gov/vuln/detail/CVE-2020-28500 | https://github.com/zowe/security-reports/issues/96 |
| CVE-2021-3918 | zlux,apiml | CRITICAL | 9.8 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | https://nvd.nist.gov/vuln/detail/CVE-2021-3918 | https://github.com/zowe/security-reports/issues/80 |
| CVE-2021-22053 | apiml | High | 8.8 | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | https://nvd.nist.gov/vuln/detail/CVE-2021-22053 | https://github.com/zowe/security-reports/issues/107 |
| CVE-2021-22060 (BDSA-2022-011) | apiml | MEDIUM | 4.3 | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N | https://nvd.nist.gov/vuln/detail/CVE-2021-22060 | https://github.com/zowe/security-reports/issues/113 |
| CVE-2021-23337 (BDSA-2021-0392) | zlux | High | 7.2 | CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H | https://nvd.nist.gov/vuln/detail/CVE-2021-23337 | https://github.com/zowe/security-reports/issues/97 |
| CVE-2021-42550 (BDSA-2021-3818) |  | MEDIUM | 6.6 |  | https://nvd.nist.gov/vuln/detail/CVE-2021-42550 | https://github.com/zowe/security-reports/issues/ |
| CVE-2021-43466 | apiml | CRITICAL | 9.8 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | https://nvd.nist.gov/vuln/detail/CVE-2021-43466 | https://github.com/zowe/security-reports/issues/90 |
| CVE-2021-43797 (BDSA-2021-3741) | apiml | MEDIUM | 6.5 | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N | https://nvd.nist.gov/vuln/detail/CVE-2021-43797 | https://github.com/zowe/security-reports/issues/115 |
| CVE-2022-0122 (BDSA-2022-0112) | zlux | MEDIUM | 5.3 | CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N | https://nvd.nist.gov/vuln/detail/CVE-2022-0122 | https://github.com/zowe/security-reports/issues/114 |

## Fixed (Since 1.26 in 1.27)

- CVE-2019-10172 (BDSA-2019-4644)
- CVE-2021-34429 (BDSA-2021-2098)
- CVE-2021-41720
- CVE-2021-42340 (BDSA-2021-3085)
- CVE-2021-44228

# 1.26

## Approved (In 1.26)

| CVE            | Module                | Severity | CVSS | Vector | Description   | Issue |
|----------------|:---------------------:|---------:|-----:|-------:|--------------:|------:|
| BDSA-2012-0001 |  apiml, job, datasets | Medium   | 4.6 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N/E:U/RL:O/RC:C | Apache Commons contains a flaw that is due to the Base32 codec decoding  invalid strings instead of rejecting them. This may allow a remote attacker to tunnel  additional information via a base 32 string that seems valid. | https://github.com/zowe/security-reports/issues/91 |
| BDSA-2019-3199 | apiml | High | 7.9 | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C | Swagger UI is vulnerable to CSS injection allowing an attacker to steal a user's cross-site request forgery (CSRF) tokens. A victim must be tricked into visiting a page on which untrusted JSON can be embedded.  This issue also affects Springfox via the springfox-swagger-ui component. | https://github.com/zowe/security-reports/issues/92 |
| BDSA-2020-3798 | explorers | High | 7.1 | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C | nodejs-ajv is vulnerable to a prototype pollution flaw. A remote attacker could leverage this to execute arbitrary code. | https://github.com/zowe/security-reports/issues/93 |
| BDSA-2021-2621 | zlux | Medium | 4.8 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L/E:P/RL:O/RC:C | Axios contains a denial-of-service (DoS) vulnerability. An attacker can exploit this using crafted regular expressions to exhaust system resources and cause a system crash. | https://github.com/zowe/security-reports/issues/95 |
| BDSA-2021-3236 | jobs, apiml, data-sets | MEDIUM | 4.7 | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L/E:U/RL:O/RC:C | Spring Framework is vulnerable to log file injection due to the insufficient validation of user input in an undisclosed component. An attacker could leverage this issue in order to add arbitrary entries to a log file which could impact both the integrity issues and performance issues. | https://github.com/zowe/security-reports/issues/70 |
| BDSA-2021-3401 | apiml | MEDIUM | 4.2 | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N/E:U/RL:O/RC:C | logback does not verify the SSL hostname as part of the certificate verification process. A remote attacker could leverage this to perform man-in-the-middle (MitM) attacks against applications using logback. | https://github.com/zowe/security-reports/issues/71 |
| CVE-2019-10172 (BDSA-2019-4644) | apiml | Medium | 5.9 | CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N | https://nvd.nist.gov/vuln/detail/CVE-2019-10172 | https://github.com/zowe/security-reports/issues/108 |
| CVE-2020-5412 (BDSA-2020-4340) | apiml | Medium | 6.5 | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | https://nvd.nist.gov/vuln/detail/CVE-2020-5412 | https://github.com/zowe/security-reports/issues/109 |
| CVE-2020-28500 (BDSA-2021-0375) | zlux | Medium | 5.3 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L | https://nvd.nist.gov/vuln/detail/CVE-2020-28500 | https://github.com/zowe/security-reports/issues/96 |
| CVE-2021-3918 | zlux,apiml | CRITICAL | 9.8 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | https://nvd.nist.gov/vuln/detail/CVE-2021-3918 | https://github.com/zowe/security-reports/issues/80 |
| CVE-2021-22053 | apiml | High | 8.8 | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | https://nvd.nist.gov/vuln/detail/CVE-2021-22053 | https://github.com/zowe/security-reports/issues/107 |
| CVE-2021-23337 (BDSA-2021-0392) | zlux | High | 7.2 | CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H | https://nvd.nist.gov/vuln/detail/CVE-2021-23337 | https://github.com/zowe/security-reports/issues/97 |
| CVE-2021-34429 (BDSA-2021-2098) | apiml | Medium | 5.3 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | https://nvd.nist.gov/vuln/detail/CVE-2021-34429 | https://github.com/zowe/security-reports/issues/88 |
| CVE-2021-41720 | zlux | Critical (Disputed by authors) | 9.8 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | https://nvd.nist.gov/vuln/detail/CVE-2021-41720 | https://github.com/zowe/security-reports/issues/100 |
| CVE-2021-42340 (BDSA-2021-3085) | jobs, data-sets | High | 7.5 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H | https://nvd.nist.gov/vuln/detail/CVE-2021-42340 | https://github.com/zowe/security-reports/issues/101 |
| CVE-2021-43466 | apiml | CRITICAL | 9.8 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | https://nvd.nist.gov/vuln/detail/CVE-2021-43466 | https://github.com/zowe/security-reports/issues/90 |
| CVE-2021-43797 (BDSA-2021-3741) | apiml | MEDIUM | 6.5 | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N | https://nvd.nist.gov/vuln/detail/CVE-2021-43797 |  |
| CVE-2021-44228 | apiml | CRITICAL | 9.8 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | https://nvd.nist.gov/vuln/detail/CVE-2021-44228 |  |

## Fixed (Since 1.25 in 1.26)

- CVE-2012-5783
- CVE-2014-3577
- CVE-2012-6153
- CVE-2015-5262
- CVE-2020-13956
- CVE-2021-23337 (BDSA-2021-0392)
- BDSA-2018-5235
- CVE-2021-34429
- CVE-2021-37136
- CVE-2021-37137
- CVE-2018-10237
- CVE-2021-30640 (BDSA-2021-2071)
- CVE-2021-33037 (BDSA-2021-2072)

# 1.25

## Approved (In 1.25)

| CVE            | Module                | Severity | CVSS | Vector | Description |
|----------------|:---------------------:|---------:|-----:|-------:|--------------:|
| BDSA-2012-0001 |  apiml, job, datasets | Medium   | 4.6 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N/E:U/RL:O/RC:C | Apache Commons contains a flaw that is due to the Base32 codec decoding  invalid strings instead of rejecting them. This may allow a remote attacker to tunnel  additional information via a base 32 string that seems valid. |
| CVE-2012-5783 (BDSA-2012-0025) | apiml | Medium | 5.8 | CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N/E:U/RL:O/RC:C | https://nvd.nist.gov/vuln/detail/CVE-2012-5783 |
| CVE-2014-3577 (BDSA-2014-0126) | apiml | Medium | 5.8 | CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N/E:P/RL:O/RC:C | https://nvd.nist.gov/vuln/detail/CVE-2014-3577 |
| CVE-2012-6153 (BDSA-2014-0112) | apiml | Medium | 4.3 |  | https://nvd.nist.gov/vuln/detail/CVE-2012-6153 |
| CVE-2015-5262 | apiml | Medium | 4.3 | (AV:N/AC:M/Au:N/C:N/I:P/A:N) | https://nvd.nist.gov/vuln/detail/CVE-2015-5262 |
| CVE-2020-13956 (BDSA-2020-2701) | apiml | Medium | 5.3 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N | https://nvd.nist.gov/vuln/detail/CVE-2020-13956 |
| CVE-2021-22119 (BDSA-2021-2310) | jobs, data-sets | High | https://nvd.nist.gov/vuln/detail/CVE-2021-22119 |
| CVE-2021-30640 (BDSA-2021-2071) | apiml | Medium | 6.5 | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N | https://nvd.nist.gov/vuln/detail/CVE-2021-30640 |
| CVE-2021-33037 (BDSA-2021-2072) | apiml | Medium | 5.3 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N | https://nvd.nist.gov/vuln/detail/CVE-2021-33037 |
| CVE-2021-42340 (BDSA-2021-3085) | apiml | High | 7.5 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H | https://nvd.nist.gov/vuln/detail/CVE-2021-42340 |
| BDSA-2018-5235 | apiml | Low | 3.7 | CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N/E:F/RL:O/RC:C | Bouncy Castle contains a weak key-hash message authentication code (*HMAC*) that is only 16 bits long which can result in hash collisions. This is due to an error within the BKS version `1` keystore (*BKS-V1*) files and could lead to an attacker being able to affect the integrity of these files.  **Note:** This issue issue occurs due to functionality that was re-introduced following the fix for **CVE-2018-5382** (**BDSA-2018-1190**). |
| CVE-2020-15522 (BDSA-2021-1516) | apiml | Medium | 5.9 | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N | https://nvd.nist.gov/vuln/detail/CVE-2020-15522 |
| CVE-2021-29425 (BDSA-2021-0922) | apiml | Medium | 5.3 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | https://nvd.nist.gov/vuln/detail/CVE-2021-29425 |
| CVE-2018-10237 (BDSA-2018-1358) | apiml | Medium | 5.9 | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H | https://nvd.nist.gov/vuln/detail/CVE-2018-10237 |
| BDSA-2021-2110 | data-sets, jobs | High | 8.8 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C | Jakarta Expression Language is vulnerable to remote code execution (RCE) due to a bug that enables invalid expressions to be evaluated as if they were valid. Applications that evaluate user-supplied expressions in error messages are vulnerable to arbitrary code execution. |
| CVE-2021-34429 (BDSA-2021-2098) | apiml | Medium | 5.3 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | https://nvd.nist.gov/vuln/detail/CVE-2021-34429 |
| CVE-2020-28500 (BDSA-2021-0375) | zlux | Medium | 5.3 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L | https://nvd.nist.gov/vuln/detail/CVE-2020-28500 |
| CVE-2021-23337 (BDSA-2021-0392) | zlux | High | 7.2 | CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H | https://nvd.nist.gov/vuln/detail/CVE-2021-23337 |
| CVE-2021-41720 | zlux | Critical (Disputed by authors) | 9.8 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | https://nvd.nist.gov/vuln/detail/CVE-2021-41720 |
| CVE-2021-37136 (BDSA-2021-2832) | apiml | High | 7.5 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H | https://nvd.nist.gov/vuln/detail/CVE-2021-37136 |
| CVE-2021-37137 (BDSA-2021-2831) | apiml | High | 7.5 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:U/RL:O/RC:C | https://nvd.nist.gov/vuln/detail/CVE-2021-37137 |
| BDSA-2019-3199 | apiml | High | 7.9 | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C | Swagger UI is vulnerable to CSS injection allowing an attacker to steal a user's cross-site request forgery (CSRF) tokens. A victim must be tricked into visiting a page on which untrusted JSON can be embedded.  This issue also affects Springfox via the springfox-swagger-ui component. |
| BDSA-2020-3798 | explorers | High | 7.1 | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C | nodejs-ajv is vulnerable to a prototype pollution flaw. A remote attacker could leverage this to execute arbitrary code. |
| BDSA-2021-2621 | zlux | Medium | 4.8 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L/E:P/RL:O/RC:C | Axios contains a denial-of-service (DoS) vulnerability. An attacker can exploit this using crafted regular expressions to exhaust system resources and cause a system crash. |

## Fixed (Since 1.24 in 1.25)

- CVE-2020-8908 (BDSA-2020-3736)
- BDSA-2021-1588
- CVE-2021-23424
- CVE-2021-23364 (BDSA-2021-2282)
- CVE-2021-33587 (BDSA-2021-1962)
- CVE-2020-28469
- CVE-2021-23346 (BDSA-2021-1508)
- CVE-2021-23436
- CVE-2021-3757

# 1.24

## Approved (In 1.24)

| CVE            | Module                | Severity | Description |
|----------------|:---------------------:|---------:|--------------:|
| BDSA-2012-0001 |  apiml, job, datasets | Medium   | Apache Commons contains a flaw that is due to the Base32 codec decoding  invalid strings instead of rejecting them. This may allow a remote attacker to tunnel  additional information via a base 32 string that seems valid. |
| CVE-2012-5783 (BDSA-2012-0025) | apiml | Medium | https://nvd.nist.gov/vuln/detail/CVE-2021-5783 |
| CVE-2014-3577 (BDSA-2014-0126) | apiml | Medium | https://nvd.nist.gov/vuln/detail/CVE-2021-3577 |
| CVE-2012-6153 (BDSA-2014-0112) | apiml | Medium | https://nvd.nist.gov/vuln/detail/CVE-2021-6153 |
| CVE-2015-5262 | apiml | Medium | https://nvd.nist.gov/vuln/detail/CVE-2015-5262 |
| CVE-2020-13956 (BDSA-2020-2701) | apiml | Medium | https://nvd.nist.gov/vuln/detail/CVE-2021-13956 |
| CVE-2021-30640 (BDSA-2021-2071) | apiml | Medium | https://nvd.nist.gov/vuln/detail/CVE-2021-30640 |
| CVE-2021-33037 (BDSA-2021-2072) | apiml | Medium | https://nvd.nist.gov/vuln/detail/CVE-2021-33037 |
| BDSA-2018-5235 | apiml | Low | Bouncy Castle contains a weak key-hash message authentication code (*HMAC*) that is only 16 bits long which can result in hash collisions. This is due to an error within the BKS version `1` keystore (*BKS-V1*) files and could lead to an attacker being able to affect the integrity of these files.  **Note:** This issue issue occurs due to functionality that was re-introduced following the fix for **CVE-2018-5382** (**BDSA-2018-1190**). |
| CVE-2020-15522 (BDSA-2021-1516) | apiml | Medium | https://nvd.nist.gov/vuln/detail/CVE-2020-15522 |
| CVE-2021-29425 (BDSA-2021-0922) | apiml | Medium | https://nvd.nist.gov/vuln/detail/CVE-2021-29425 |
| BDSA-2021-2110 | data-sets, jobs | High | Jakarta Expression Language is vulnerable to remote code execution (RCE) due to a bug that enables invalid expressions to be evaluated as if they were valid. Applications that evaluate user-supplied expressions in error messages are vulnerable to arbitrary code execution. |
| CVE-2018-10237 (BDSA-2018-1358) | apiml | Medium | https://nvd.nist.gov/vuln/detail/CVE-2018-10237 |
| CVE-2020-8908 (BDSA-2020-3736) | apiml | Low | https://nvd.nist.gov/vuln/detail/CVE-2020-8908 |
| CVE-2021-34429 (BDSA-2021-2098) | apiml | Medium | https://nvd.nist.gov/vuln/detail/CVE-2021-34429 |
| CVE-2020-28500 (BDSA-2021-0375) | zlux | Medium | https://nvd.nist.gov/vuln/detail/CVE-2020-28500 |
| CVE-2021-23337 (BDSA-2021-0392) | zlux | High | https://nvd.nist.gov/vuln/detail/CVE-2021-23337 |
| BDSA-2021-1588 | jobs, data-sets | Medium | Spring Framework is vulnerable to privilege escalation due to the creation of unsafe temporary directories by the WebFlux component. A local authenticated attacker could modify arbitrary files via maliciously crafted `multipart` requests.   This vulnerability does not affect Spring MVC applications, or applications that do not handle `multipart` file requests. |
| CVE-2021-22119 (BDSA-2021-2310) | jobs, data-sets | High | https://nvd.nist.gov/vuln/detail/CVE-2021-22119 |
| BDSA-2019-3199 | apiml | High | Swagger UI is vulnerable to CSS injection allowing an attacker to steal a user's cross-site request forgery (CSRF) tokens. A victim must be tricked into visiting a page on which untrusted JSON can be embedded.  This issue also affects Springfox via the springfox-swagger-ui component. |
| BDSA-2020-3798 | explorers | High | nodejs-ajv is vulnerable to a prototype pollution flaw. A remote attacker could leverage this to execute arbitrary code. |
| CVE-2021-23424 | zlux | High | https://nvd.nist.gov/vuln/detail/CVE-2021-23424 |
| CVE-2021-3749 (BDSA-2021-2621) | zlux | High | https://nvd.nist.gov/vuln/detail/CVE-2021-3749 |
| CVE-2021-23364 (BDSA-2021-2282) | zlux | Medium | https://nvd.nist.gov/vuln/detail/CVE-2021-23364 |
| CVE-2021-33587 (BDSA-2021-1962) | zlux | High | https://nvd.nist.gov/vuln/detail/CVE-2021-33587 |
| CVE-2020-28469 | zlux | High | https://nvd.nist.gov/vuln/detail/CVE-2020-28469 |
| CVE-2021-23346 (BDSA-2021-1508) | zlux | Medium | https://nvd.nist.gov/vuln/detail/CVE-2021-23346 |
| CVE-2021-23436 | zlux | Critical | https://nvd.nist.gov/vuln/detail/CVE-2021-23436 |
| CVE-2021-3757 | zlux | Critical | https://nvd.nist.gov/vuln/detail/CVE-2021-3757 |
| CVE-2021-33502 (BDSA-2021-1893) | zlux | High | https://nvd.nist.gov/vuln/detail/CVE-2021-33502 |
| BDSA-2021-2300 | zlux | Medium | ssri is vulnerable to regular expression denial of service (ReDoS) via `index.js`. An attacker could exploit this vulnerability by supplying a maliciously crafted SRI in order to consume resources, thus resulting in a denial-of-service (DoS) condition occurring.  **Note:** This issue only affects consumers using the strict option. |
