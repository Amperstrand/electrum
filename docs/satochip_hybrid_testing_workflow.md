# Satochip Hybrid Testing Workflow

This workflow combines fast headless coverage with GUI-observable hardware checks.

## Layers

1. Headless logic tests
   - `tests/test_wizard.py`
   - `electrum/plugins/satochip/tests/test_satochip_plugin.py`
2. Hardware integration tests
   - `electrum/plugins/satochip/tests/test_satochip_integration.py`
3. Destructive hardware tests (opt-in)
   - `TestPinBlockWorkflow` in `test_satochip_integration.py`

## Safety Gates

- Destructive tests are marked `@pytest.mark.destructive_card`.
- They are skipped by default.
- Enable explicitly with `--allow-destructive-card-tests`.

## Commands

Run non-destructive hardware integration tests:

```bash
python3 -m pytest -v electrum/plugins/satochip/tests/test_satochip_integration.py -m integration
```

Run wrong-PIN-until-block workflow (destructive):

```bash
python3 -m pytest -v electrum/plugins/satochip/tests/test_satochip_integration.py::TestPinBlockWorkflow --allow-destructive-card-tests -s
```

Watch a simple live status window during destructive workflow:

```bash
SATOCHIP_OBSERVE_GUI=1 python3 -m pytest -v electrum/plugins/satochip/tests/test_satochip_integration.py::TestPinBlockWorkflow --allow-destructive-card-tests -s
```

## Artifacts

`TestPinBlockWorkflow` writes per-run artifacts to pytest `tmp_path`:

- `pin_block_workflow.jsonl` attempt-by-attempt event log
- `screenshots/*.png` when `SATOCHIP_OBSERVE_GUI=1`

## Recovery Assumption

The destructive workflow uses `TESTPUK` from the integration suite for automatic unblock.
Use only with a dedicated resettable test card.
