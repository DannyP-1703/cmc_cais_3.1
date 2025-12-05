#!/bin/bash

fail=0

for i in $(seq 1 5); do
    id=$(printf "%02d" "$i")
    json="PublicTests/${id}.json"
    out="tests/${id}.dot"
    expect="tests/${id}-ref.dot"

    echo "=== Test $id ==="
    echo "Running: uv run restore_cfg.py $json $out"
    if ! uv run restore_cfg.py "$json" "$out"; then
        echo "ERROR: uv run failed for $json"
        fail=1
        continue
    fi

    if [ ! -f "$out" ]; then
        echo "ERROR: output file $out not found"
        fail=1
        continue
    fi

    if [ ! -f "$expect" ]; then
        echo "ERROR: expected file $expect not found"
        fail=1
        continue
    fi

    if diff <(sort "$out") <(sort "$expect") >/dev/null 2>&1; then
        echo "PASS"
    else
        echo "FAIL: differences found between sorted $out and $expect"
        echo "Showing diff:"
        diff <(sort "$out") <(sort "$expect")
        fail=1
    fi
done

if [ "$fail" -eq 0 ]; then
    echo "All tests passed."
    exit 0
else
    echo "Some tests failed."
    exit 1
fi

