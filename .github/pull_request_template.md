## Summary

<!-- What changed and why? -->

## Verification

- [ ] `bash -n dns-sni-unlock.sh tests/test.sh`
- [ ] `shellcheck -x dns-sni-unlock.sh tests/test.sh`
- [ ] `./tests/test.sh`

## Safety and compatibility

<!-- Describe firewall, configuration, platform, upgrade, and rollback impact. -->

- [ ] No global firewall chain is flushed or default policy changed.
- [ ] New inputs are validated before use.
- [ ] User-visible changes are documented.
- [ ] No secrets or real infrastructure addresses are included.
