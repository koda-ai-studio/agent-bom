# Changelog fragments

Pull requests do not edit `CHANGELOG.md`. Every open PR used to append to its
`## [Unreleased]` section, so any two of them conflicted. Add one file here
instead, named after your branch or change:

```text
changelog.d/fix-login-limiter.md
```

A fragment holds one or more `### <Section>` headings, each followed by the
entries for it, written the way they should read in the release notes:

```markdown
### Fixed
- The login limiter keys on the client address the trusted proxy reports, so one client can no longer lock out everyone behind the same proxy (#1234).
```

Sections, in the order a release lists them: `Highlights`, `Upgrade notes`,
`Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`,
`Performance`, `Docs`, `CI`. Any other heading, text before the first heading,
or a heading with no entries fails CI (`python scripts/assemble_changelog.py --check`).

At release time the maintainer runs

```bash
python scripts/assemble_changelog.py --version X.Y.Z
```

which writes `## [X.Y.Z] - <date>` under `## [Unreleased]`, keeps anything
already written under Unreleased first, advances the compare links and deletes
the fragments. This README is never assembled.
