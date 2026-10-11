# Product positioning and brand assets

**webrev — web security toolkit**

**Inspect. Probe. Investigate.**

The public description covers application security assessment, reverse
engineering and penetration testing through three modes:

- Static inspection of application code, resources, configuration and source maps.
- Dynamic browser investigation, interaction attribution and HTTP/WebSocket capture.
- Active security probes for access control, CORS, redirects, headers/cookies,
  sensitive-file exposure and XSS/SQLi signals.

Use `STATIC / DYNAMIC / ACTIVE / CLI / TUI` on banners. Describe findings with
their evidence and confidence; XSS/SQLi/IDOR signals are not validated exploits.
RCE detection and WebSocket frame replay are not implemented. The default CLI
scan runs static analysis; the operator selects additional modes.

The existing symbol, wordmark and orange/ink/cream palette are retained. The
README hero, social preview and workflow diagram use outlined text, so consumers
need no fonts. The terminal caption lives in `webrev_tui::brand::TAGLINE` and is
shared by the CLI banner. The README's CI badge links to the workflow; its label
does not claim a remote pass/fail status.

## Regeneration

From a source checkout, install FontTools in your development environment and supply local
[Inter](https://rsms.me/inter/) and JetBrains Mono font files:

```sh
python scripts/update_brand_assets.py --inter /path/to/InterVariable.ttf \
  --mono /path/to/JetBrainsMono-Regular.ttf
```

The script preserves the existing hero lockup and regenerates `hero.svg`,
`social-preview.svg` and `pipeline.svg`. Inspect their renderings at README and
social-preview sizes after changing copy. Fonts and FontTools are only generation
tools, not runtime or installation dependencies.
