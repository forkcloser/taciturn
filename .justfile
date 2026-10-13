# This file is the project's own. Keep the import: it mounts every shared
# limen task under `just do ...`.
import '.limen/just/main.just'

# The agent is cgo against Security.framework: every Go task knows it
# (book/recipes.md, GO_CGO).
export GO_CGO := '1'

# The FIRST recipe defined here becomes `just`'s default.
lint: do::lint::go::default do::lint::go::deadcode do::lint::default
fix: do::fix::go::default do::fix::default
test: do::test::go::unit do::test::go::race
# The security workflow runs `just security`.
security: do::security::default
