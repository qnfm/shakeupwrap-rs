#!/usr/bin/env bats

setup() {
    SUW_BIN="${SUW_BIN:-./bin/x86-64/ShakeUpWrap}"
    TEST_TMPDIR="$(mktemp -d "${BATS_TMPDIR:-/tmp}/suw-basic.XXXXXX")"

    MB=$((1024 * 1024))

    if [[ ! -x "$SUW_BIN" ]]; then
        echo "ShakeUpWrap binary not found or not executable: $SUW_BIN" >&2
        return 1
    fi
}

teardown() {
    rm -rf "$TEST_TMPDIR"
}

make_file() {
    local path="$1"
    local size="$2"

    rm -f "$path"

    local full_mb=$((size / MB))
    local rem=$((size % MB))

    if (( full_mb > 0 )); then
        dd if=/dev/urandom of="$path" bs="$MB" count="$full_mb" status=none
    else
        : > "$path"
    fi

    if (( rem > 0 )); then
        dd if=/dev/urandom of="$path" bs=1 count="$rem" oflag=append conv=notrunc status=none
    fi

    [[ "$(stat -c '%s' "$path")" -eq "$size" ]]
}

roundtrip_file() {
    local name="$1"
    local size="$2"

    local pt="$TEST_TMPDIR/$name.pt"
    local key="$TEST_TMPDIR/$name.key"
    local ct="$TEST_TMPDIR/$name.suw"
    local out="$TEST_TMPDIR/$name.out"

    make_file "$pt" "$size"

    run "$SUW_BIN" -e -k "$key" -o "$ct" < "$pt"
    [ "$status" -eq 0 ]

    [ -f "$key" ]
    [ "$(stat -c '%s' "$key")" -eq 64 ]

    run "$SUW_BIN" -d -k "$key" -o "$out" < "$ct"
    [ "$status" -eq 0 ]

    cmp "$pt" "$out"
}

@test "help exits successfully" {
    run "$SUW_BIN" --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage:"* ]]
}

@test "missing mode fails" {
    run "$SUW_BIN" -k "$TEST_TMPDIR/key.bin"
    [ "$status" -ne 0 ]
    [[ "$output" == *"Missing required mode"* ]]
}

@test "missing key fails" {
    run "$SUW_BIN" -e
    [ "$status" -ne 0 ]
    [[ "$output" == *"Missing required key path"* ]]
}

@test "multiple modes fail" {
    run "$SUW_BIN" -e -d -k "$TEST_TMPDIR/key.bin"
    [ "$status" -ne 0 ]
    [[ "$output" == *"exactly one"* ]]
}

@test "positional argument fails" {
    run "$SUW_BIN" -e -k "$TEST_TMPDIR/key.bin" input.dat
    [ "$status" -ne 0 ]
    [[ "$output" == *"Unexpected positional argument"* ]]
}

@test "roundtrip empty file" {
    roundtrip_file "empty" 0
}

@test "roundtrip one byte" {
    roundtrip_file "one_byte" 1
}

@test "roundtrip one MiB" {
    roundtrip_file "one_mib" "$MB"
}

@test "stdout encryption and decryption roundtrip" {
    local pt="$TEST_TMPDIR/pt"
    local key="$TEST_TMPDIR/key"
    local ct="$TEST_TMPDIR/ct"
    local out="$TEST_TMPDIR/out"

    printf 'hello ShakeUpWrap\n' > "$pt"

    run "$SUW_BIN" -e -k "$key" < "$pt"
    [ "$status" -eq 0 ]
    printf '%s' "$output" > "$ct"

    # Bats command substitution is text-oriented and can corrupt binary NULs.
    # Re-run with normal shell redirection for a reliable binary stdout path test.
    "$SUW_BIN" -e -k "$TEST_TMPDIR/key2" < "$pt" > "$ct"
    "$SUW_BIN" -d -k "$TEST_TMPDIR/key2" < "$ct" > "$out"

    cmp "$pt" "$out"
}

@test "encryption refuses existing key file" {
    local pt="$TEST_TMPDIR/pt"
    local key="$TEST_TMPDIR/key"
    local ct="$TEST_TMPDIR/ct"

    printf 'hello' > "$pt"
    printf 'existing' > "$key"

    run "$SUW_BIN" -e -k "$key" -o "$ct" < "$pt"
    [ "$status" -ne 0 ]
    [[ "$output" == *"Key file already exists"* ]]
}

@test "decryption refuses missing key file" {
    local ct="$TEST_TMPDIR/ct"
    local key="$TEST_TMPDIR/missing.key"
    local out="$TEST_TMPDIR/out"

    printf 'not real ciphertext' > "$ct"

    run "$SUW_BIN" -d -k "$key" -o "$out" < "$ct"
    [ "$status" -ne 0 ]
    [[ "$output" == *"Key file does not exist"* ]]
}

@test "decryption refuses key file with invalid size" {
    local pt="$TEST_TMPDIR/pt"
    local key="$TEST_TMPDIR/key"
    local out="$TEST_TMPDIR/out"

    printf 'not real ciphertext' > "$pt"
    printf 'too short' > "$key"

    run "$SUW_BIN" -d -k "$key" -o "$out" < "$pt"
    [ "$status" -ne 0 ]
    [[ "$output" == *"Invalid key file size"* ]]
}

@test "output file is not overwritten" {
    local pt="$TEST_TMPDIR/pt"
    local key="$TEST_TMPDIR/key"
    local ct="$TEST_TMPDIR/ct"

    printf 'hello' > "$pt"
    printf 'existing output' > "$ct"

    run "$SUW_BIN" -e -k "$key" -o "$ct" < "$pt"
    [ "$status" -ne 0 ]
    [[ "$output" == *"Output file already exists"* ]]
    [[ "$(cat "$ct")" == "existing output" ]]
}

@test "truncated small ciphertext is rejected and -o output is not left behind" {
    local pt="$TEST_TMPDIR/pt"
    local key="$TEST_TMPDIR/key"
    local ct="$TEST_TMPDIR/ct"
    local bad="$TEST_TMPDIR/bad"
    local out="$TEST_TMPDIR/out"

    make_file "$pt" "$MB"

    run "$SUW_BIN" -e -k "$key" -o "$ct" < "$pt"
    [ "$status" -eq 0 ]

    local ct_size
    ct_size="$(stat -c '%s' "$ct")"
    head -c $((ct_size - 1)) "$ct" > "$bad"

    run "$SUW_BIN" -d -k "$key" -o "$out" < "$bad"
    [ "$status" -ne 0 ]
    [ ! -e "$out" ]
}

@test "modified small ciphertext is rejected and -o output is not left behind" {
    local pt="$TEST_TMPDIR/pt"
    local key="$TEST_TMPDIR/key"
    local ct="$TEST_TMPDIR/ct"
    local bad="$TEST_TMPDIR/bad"
    local out="$TEST_TMPDIR/out"

    make_file "$pt" "$MB"

    run "$SUW_BIN" -e -k "$key" -o "$ct" < "$pt"
    [ "$status" -eq 0 ]

    cp "$ct" "$bad"

    local ct_size
    ct_size="$(stat -c '%s' "$bad")"
    local offset=$((ct_size / 2))

    printf '\x00' | dd of="$bad" bs=1 seek="$offset" count=1 conv=notrunc status=none

    run "$SUW_BIN" -d -k "$key" -o "$out" < "$bad"
    [ "$status" -ne 0 ]
    [ ! -e "$out" ]
}
