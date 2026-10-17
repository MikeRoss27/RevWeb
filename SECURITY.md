# Security policy

## Reporting a vulnerability in Webrev

Please report vulnerabilities privately through GitHub: **Security → Report a
vulnerability** on this repository. Do not open a public issue for them.

Of particular interest, because they break what the tool promises:

- a request sent outside the configured scope (including redirects, DNS answers,
  WebSockets and browser sub-resources);
- a default-on action that changes state on a target;
- credentials, tokens or URL userinfo leaking into logs, errors or reports
  (detected-secret plaintext is shown on purpose and is not a leak);
- a scan reported complete or clean while some checks were refused or skipped.

## Supported versions

Only the latest commit on `main` and the latest tagged release are supported.

## Using Webrev

Webrev is meant for systems you own or are explicitly authorised to test.
Active checks and the browser are opt-in. Respect each programme's rules.
