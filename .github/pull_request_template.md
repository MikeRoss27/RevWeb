## What and why

<!-- One paragraph: the problem, and the change. -->

## Safety checklist

- [ ] Nothing can send a request outside the configured scope (HTTP, redirects, DNS, WebSocket, browser sub-resources).
- [ ] Nothing state-changing is sent or clicked by default; any new active behaviour is opt-in and recorded as a coverage result.
- [ ] Credentials, tokens and URL userinfo do not reach logs, errors or `Debug` output (detected-secret plaintext is the deliberate exception).
- [ ] Incomplete coverage can never read as "secure".

## Measurements

<!-- If this changes detection, state the corpus, its size, who labelled it, and
     what it cannot show. Do not present a small maintainer-written set as accuracy. -->

## Verification

- [ ] `scripts/ci-local.sh` passes
- [ ] Tests added for the new behaviour, including a negative case
- [ ] `goal.md` is only updated with evidence; no criterion ticked without it
