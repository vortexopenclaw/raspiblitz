#!/usr/bin/env bats

setup() {
  export TRUST_LOG="$BATS_TEST_TMPDIR/commands"
  export MOCK_BIN="$BATS_TEST_TMPDIR/bin"
  mkdir -p "$MOCK_BIN"
  export PATH="$MOCK_BIN:$PATH"
  export NODE_STATUS="install ok installed"
  export FAIL_STEP=""
  export SCRIPT="$BATS_TEST_DIRNAME/../home.admin/config.scripts/blitz.trust.sh"
  printf '#!/bin/bash\nexec "$@"\n' > "$MOCK_BIN/sudo"
  printf '#!/bin/bash\nprintf "%%s" "$NODE_STATUS"\n' > "$MOCK_BIN/dpkg-query"
  cat > "$MOCK_BIN/apt-get" <<'MOCK'
#!/bin/bash
printf 'apt-get %s\n' "$*" >> "$TRUST_LOG"
if [[ "$*" == *update ]] && [ "$FAIL_STEP" = update ]; then exit 100; fi
if [ "$1" = install ] && [ "$FAIL_STEP" = install ]; then exit 100; fi
MOCK
  cat > "$MOCK_BIN/update-ca-certificates" <<'MOCK'
#!/bin/bash
printf 'update-ca-certificates %s\n' "$*" >> "$TRUST_LOG"
[ "$FAIL_STEP" != refresh ]
MOCK
  chmod +x "$MOCK_BIN/"*
}

@test "refreshes OS and installed Node package without installing unrelated packages" {
  run bash "$SCRIPT" update
  [ "$status" -eq 0 ]
  expected=$(printf '%s\n' 'apt-get -o APT::Update::Error-Mode=any update' 'apt-get install --only-upgrade -y ca-certificates nodejs' 'update-ca-certificates --fresh')
  [ "$(< "$TRUST_LOG")" = "$expected" ]
}

@test "does not install Node on a minimal image" {
  export NODE_STATUS="unknown ok not-installed"
  run bash "$SCRIPT" update
  [ "$status" -eq 0 ]
  ! grep -q nodejs "$TRUST_LOG"
}

@test "does not treat residual Node configuration as an installed package" {
  export NODE_STATUS="deinstall ok config-files"
  run bash "$SCRIPT" update
  [ "$status" -eq 0 ]
  ! grep -q nodejs "$TRUST_LOG"
}

@test "failed index refresh stops before package changes" {
  export FAIL_STEP=update
  run bash "$SCRIPT" update
  [ "$status" -ne 0 ]
  [ "$(wc -l < "$TRUST_LOG" | tr -d ' ')" -eq 1 ]
}

@test "failed package update stops before trust refresh" {
  export FAIL_STEP=install
  run bash "$SCRIPT" update
  [ "$status" -ne 0 ]
  ! grep -q update-ca-certificates "$TRUST_LOG"
}

@test "failed trust refresh is not reported as success" {
  export FAIL_STEP=refresh
  run bash "$SCRIPT" update
  [ "$status" -ne 0 ]
  [[ "$output" != *"Vendor trust packages refreshed"* ]]
}

@test "invalid invocation makes no package changes" {
  run bash "$SCRIPT" invalid
  [ "$status" -ne 0 ]
  [ ! -e "$TRUST_LOG" ]
  run bash "$SCRIPT"
  [ "$status" -ne 0 ]
  [ ! -e "$TRUST_LOG" ]
}

@test "repeated refreshes use the same scoped vendor operations" {
  run bash "$SCRIPT" update
  [ "$status" -eq 0 ]
  first=$(< "$TRUST_LOG")
  : > "$TRUST_LOG"
  run bash "$SCRIPT" update
  [ "$status" -eq 0 ]
  [ "$(< "$TRUST_LOG")" = "$first" ]
}

@test "image, release and data-update entry points fail if trust refresh fails" {
  for file in build_sdcard.sh home.admin/config.scripts/blitz.release.sh home.admin/_provision.update.sh; do
    run grep -E '^ */home/admin/config.scripts/blitz.trust.sh update.*\|\| exit 1$' "$BATS_TEST_DIRNAME/../$file"
    [ "$status" -eq 0 ]
  done
}
