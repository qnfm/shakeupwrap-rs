#!/usr/bin/env bats

setup() {
    SUW_BIN="${SUW_BIN:-./bin/x86-64/ShakeUpWrap}"
    TEST_TMPDIR="$(mktemp -d "${BATS_TMPDIR:-/tmp}/suw-large.XXXXXX")"

    CHUNK_SIZE=$((256 * 1024 * 1024))
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

@test "roundtrip chunk minus one byte" {
    roundtrip_file "chunk_minus_1_byte" $((CHUNK_SIZE - 1))
}

@test "roundtrip chunk minus one MiB" {
    roundtrip_file "chunk_minus_1_mib" $((CHUNK_SIZE - MB))
}

@test "roundtrip exact chunk" {
    roundtrip_file "chunk_exact" "$CHUNK_SIZE"
}

@test "roundtrip chunk plus one byte" {
    roundtrip_file "chunk_plus_1_byte" $((CHUNK_SIZE + 1))
}

@test "roundtrip chunk plus one MiB" {
    roundtrip_file "chunk_plus_1_mib" $((CHUNK_SIZE + MB))
}

@test "roundtrip two chunks minus one byte" {
    roundtrip_file "two_chunks_minus_1_byte" $((2 * CHUNK_SIZE - 1))
}

@test "roundtrip two exact chunks" {
    roundtrip_file "two_chunks_exact" $((2 * CHUNK_SIZE))
}

@test "roundtrip two chunks plus one byte" {
    roundtrip_file "two_chunks_plus_1_byte" $((2 * CHUNK_SIZE + 1))
}

@test "truncated exact-chunk ciphertext is rejected and -o output is not left behind" {
    local pt="$TEST_TMPDIR/pt"
    local key="$TEST_TMPDIR/key"
    local ct="$TEST_TMPDIR/ct"
    local bad="$TEST_TMPDIR/bad"
    local out="$TEST_TMPDIR/out"

    make_file "$pt" "$CHUNK_SIZE"

    run "$SUW_BIN" -e -k "$key" -o "$ct" < "$pt"
    [ "$status" -eq 0 ]

    local ct_size
    ct_size="$(stat -c '%s' "$ct")"
    head -c $((ct_size - 1)) "$ct" > "$bad"

    run "$SUW_BIN" -d -k "$key" -o "$out" < "$bad"
    [ "$status" -ne 0 ]
    [ ! -e "$out" ]
}

@test "modified exact-chunk ciphertext is rejected and -o output is not left behind" {
    local pt="$TEST_TMPDIR/pt"
    local key="$TEST_TMPDIR/key"
    local ct="$TEST_TMPDIR/ct"
    local bad="$TEST_TMPDIR/bad"
    local out="$TEST_TMPDIR/out"

    make_file "$pt" "$CHUNK_SIZE"

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

@test "removing the final chunk from two-chunk ciphertext is rejected" {
    local pt="$TEST_TMPDIR/pt"
    local key="$TEST_TMPDIR/key"
    local ct="$TEST_TMPDIR/ct"
    local bad="$TEST_TMPDIR/bad"
    local out="$TEST_TMPDIR/out"

    make_file "$pt" $((2 * CHUNK_SIZE))

    run "$SUW_BIN" -e -k "$key" -o "$ct" < "$pt"
    [ "$status" -eq 0 ]

    # age-style exact-multiple rule emits two full encrypted chunks:
    # each chunk is CHUNK_SIZE + SUW_TAGLEN, and the second one is final.
    # Remove the second chunk entirely. The remaining first chunk will be
    # treated as final by the decryptor but was authenticated as non-final.
    local enc_chunk_size=$((CHUNK_SIZE + 64))
    head -c "$enc_chunk_size" "$ct" > "$bad"

    run "$SUW_BIN" -d -k "$key" -o "$out" < "$bad"
    [ "$status" -ne 0 ]
    [ ! -e "$out" ]
}
