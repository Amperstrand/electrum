#!/bin/bash
#
# Run the ordered user story lifecycle test suite against a physical Satochip card
# Stories execute in dependency order: Factory Reset → Wallet Setup → PIN Block → PUK Recovery
#
# Usage:
#   ./scripts/run_user_stories.sh                    # Full suite with GUI observer
#   ./scripts/run_user_stories.sh --headless          # Full suite without GUI
#   ./scripts/run_user_stories.sh --story 2           # Run only Story 2
#   ./scripts/run_user_stories.sh --no-reset          # Skip factory reset (Story 0)
#   ./scripts/run_user_stories.sh --help              # Show this help
#
# Prerequisites:
#   - SSH tunnel to remote pcscd (auto-setup if not present)
#   - pytest-order installed
#   - Physical Satochip card in reader

# Don't use set -e — pytest exit codes are meaningful:
#   0=all passed, 1=some failed, 2=interrupted, 5=no tests collected

# ─── Parse CLI arguments ────────────────────────────────────────────────────

headless=0
story_filter=()
no_reset=0
extra_args=()

show_help() {
    cat <<'EOF'
Usage: ./scripts/run_user_stories.sh [OPTIONS] [EXTRA_PYTEST_ARGS...]

Run the ordered Satochip user story lifecycle test suite against a physical card.

Stories run in dependency order:
  Story 0 — TestStory0FactoryReset        (destructive: wipes card)
  Story 1 — TestStory1WalletSetupAndSign  (seeds wallet, signs tx)
  Story 2 — TestStory2WrongPinUntilBlock  (exhausts PIN attempts)
  Story 3 — TestStory3PukRecoveryAndVerify (PUK recovery, verify PIN restored)

Options:
  --headless      Run without GUI observer. Automatically skips Story 0 (factory
                  reset requires physical card interaction with GUI prompts).
                  Use without --headless to include Story 0.
  --story N       Run only Story N (e.g. --story 2 runs TestStory2...)
  --no-reset      Skip Story 0 (factory reset). Implies card is already set up.
                  If both --story and --no-reset are given, --story takes precedence.
  --help          Show this help and exit

Note: Story 0 (Factory Reset) requires GUI mode for physical card removal/reinsertion
      prompts. When --headless is used without --story 0, Story 0 is automatically skipped.

Extra args are passed directly to pytest (e.g. --tb=short, -x, etc.)

Prerequisites:
  - SSH tunnel to remote pcscd (auto-setup via scripts/setup_remote_pcscd.sh)
  - pytest-order installed (pip install pytest-order)
  - Physical Satochip card in reader

Examples:
  ./scripts/run_user_stories.sh
  ./scripts/run_user_stories.sh --headless
  ./scripts/run_user_stories.sh --story 2
  ./scripts/run_user_stories.sh --no-reset --headless
  ./scripts/run_user_stories.sh --story 1 --tb=short
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h)
            show_help
            exit 0
            ;;
        --headless)
            headless=1
            shift
            ;;
        --story)
            if [[ -z "$2" || ! "$2" =~ ^[0-9]+$ ]]; then
                echo "ERROR: --story requires a numeric argument (e.g. --story 2)" >&2
                exit 1
            fi
            story_filter=(-k "TestStory${2}")
            shift 2
            ;;
        --no-reset)
            no_reset=1
            shift
            ;;
        *)
            extra_args+=("$1")
            shift
            ;;
    esac
done

# --story takes precedence over --no-reset
if [[ ${#story_filter[@]} -gt 0 && $no_reset -eq 1 ]]; then
    echo "INFO: --story and --no-reset both specified; --story takes precedence, ignoring --no-reset"
    no_reset=0
fi

# --headless implies --no-reset when Story 0 would run (needs GUI for physical card interaction)
if [[ $headless -eq 1 && $no_reset -eq 0 && ${#story_filter[@]} -eq 0 ]]; then
    echo "WARNING: Story 0 requires GUI mode (physical card interaction)."
    echo "         Skipping factory reset (--no-reset implied)."
    echo "         Use without --headless to include Story 0."
    no_reset=1
fi

# If --no-reset and no --story, add exclusion filter
if [[ $no_reset -eq 1 ]]; then
    story_filter=(-k "not TestStory0FactoryReset")
fi

# ─── Banner ─────────────────────────────────────────────────────────────────

echo "=========================================="
echo "Satochip User Story Test Suite"
echo "=========================================="
echo ""

# ─── Check/setup SSH tunnel ──────────────────────────────────────────────────

local_socket="/tmp/pcscd-remote.comm"

if [[ -n "$PCSCLITE_CSOCK_NAME" ]]; then
    echo "[1/3] Using PCSCLITE_CSOCK_NAME from environment: $PCSCLITE_CSOCK_NAME"
    local_socket="$PCSCLITE_CSOCK_NAME"
elif [[ -S "$local_socket" ]]; then
    echo "[1/3] Found existing socket: $local_socket"
else
    echo "[1/3] No socket found — running setup_remote_pcscd.sh..."
    if [[ -f "./scripts/setup_remote_pcscd.sh" ]]; then
        bash ./scripts/setup_remote_pcscd.sh
    else
        echo "ERROR: scripts/setup_remote_pcscd.sh not found" >&2
        exit 1
    fi
    # Re-check after setup
    if [[ ! -S "$local_socket" ]]; then
        echo "ERROR: Socket still not found after setup: $local_socket" >&2
        echo "       Check SSH tunnel and remote pcscd are running." >&2
        exit 1
    fi
fi

# ─── Set environment variables ───────────────────────────────────────────────

echo ""
echo "[2/3] Setting environment variables..."

export PCSCLITE_CSOCK_NAME="$local_socket"
export DYLD_LIBRARY_PATH="/tmp:$DYLD_LIBRARY_PATH"

if [[ $headless -eq 0 ]]; then
    export SATOCHIP_OBSERVE_GUI=1
    echo "  SATOCHIP_OBSERVE_GUI=1 (GUI observer enabled)"
else
    unset SATOCHIP_OBSERVE_GUI
    echo "  SATOCHIP_OBSERVE_GUI unset (headless mode)"
fi

echo "  PCSCLITE_CSOCK_NAME=$PCSCLITE_CSOCK_NAME"
echo "  DYLD_LIBRARY_PATH=$DYLD_LIBRARY_PATH"

# Copy library if not already present
if [[ ! -f "/tmp/libpcsclite_real.so.1" ]]; then
    echo ""
    echo "  Copying pcsc-lite library to /tmp..."
    cp /usr/local/opt/pcsc-lite/lib/libpcsclite_real.1.dylib /tmp/libpcsclite_real.so.1
    echo "  Library ready: /tmp/libpcsclite_real.so.1"
else
    echo "  Library already present: /tmp/libpcsclite_real.so.1"
fi

# ─── Run pytest ──────────────────────────────────────────────────────────────

echo ""
echo "[3/3] Running user story tests..."
echo ""

# Touch a sentinel file to track artifacts created during this run
touch /tmp/.run_user_stories_start

test_file="electrum/plugins/satochip/tests/test_satochip_user_stories.py"

echo "pytest command:"
echo "  python3 -m pytest -v \\"
echo "    $test_file \\"
echo "    --run-user-stories --allow-destructive-card-tests -s \\"
if [[ ${#story_filter[@]} -gt 0 ]]; then
    echo "    ${story_filter[*]} \\"
fi
if [[ ${#extra_args[@]} -gt 0 ]]; then
    echo "    ${extra_args[*]}"
fi
echo ""

python3 -m pytest -v \
    "$test_file" \
    --run-user-stories --allow-destructive-card-tests -s \
    "${story_filter[@]}" \
    "${extra_args[@]}"

pytest_exit_code=$?

# ─── Artifact summary ────────────────────────────────────────────────────────

echo ""
echo "=========================================="
echo "Run Summary"
echo "=========================================="
echo ""

# Find JSONL logs created during this run
echo "JSONL event logs:"
jsonl_count=0
while IFS= read -r log_file; do
    echo "  $log_file"
    jsonl_count=$((jsonl_count + 1))
done < <(find /tmp -name "story-*.jsonl" -newer /tmp/.run_user_stories_start 2>/dev/null | sort)

if [[ $jsonl_count -eq 0 ]]; then
    echo "  (none found)"
fi

echo ""
echo "Screenshots:"
screenshot_total=0
while IFS= read -r story_dir; do
    dir_name=$(basename "$story_dir")
    count=$(find "$story_dir/screenshots" -name "*.png" 2>/dev/null | wc -l | tr -d ' ')
    screenshot_total=$((screenshot_total + count))
    echo "  $dir_name: $count screenshot(s)"
done < <(find /tmp -type d -name "story-*" -newer /tmp/.run_user_stories_start 2>/dev/null | sort)

if [[ $screenshot_total -eq 0 ]]; then
    echo "  (none found)"
fi

echo ""
echo "pytest exit code: $pytest_exit_code"
case $pytest_exit_code in
    0) echo "Result: ALL TESTS PASSED" ;;
    1) echo "Result: SOME TESTS FAILED" ;;
    2) echo "Result: TEST RUN INTERRUPTED" ;;
    3) echo "Result: INTERNAL ERROR" ;;
    4) echo "Result: COMMAND LINE USAGE ERROR" ;;
    5) echo "Result: NO TESTS COLLECTED" ;;
    *) echo "Result: UNKNOWN EXIT CODE" ;;
esac
echo ""

exit $pytest_exit_code
