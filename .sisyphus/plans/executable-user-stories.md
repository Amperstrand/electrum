# Executable User Stories Framework — pytest-bdd + Allure

## TL;DR

> **Quick Summary**: Build an executable user story framework using pytest-bdd (Gherkin `.feature` files) + Allure reporting, proving it with Story 0 (Factory Reset). The `.feature` files serve as human-readable documentation, automated test scripts, and visual evidence sources — a single source of truth.
> 
> **Deliverables**:
> - `pytest-bdd` and `allure-pytest` installed and verified on Python 3.14
> - `features/story_0_factory_reset.feature` — Gherkin story file
> - `test_bdd_user_stories.py` — Step definitions wrapping existing `story_helpers.py`
> - `features/conftest.py` — BDD-specific fixtures and Allure screenshot hooks
> - Allure screenshot attachments at each Gherkin step
> - Documentation for running BDD tests
> 
> **Estimated Effort**: Medium
> **Parallel Execution**: YES — 3 waves
> **Critical Path**: Task 1 (deps) → Task 3 (feature file) → Task 4 (step defs) → Task 5 (integration verify)

---

## Context

### Original Request
User wants a "single source of truth" for user stories that can be:
1. **Graphed/visualized** — human-readable Gherkin scenarios
2. **Read as documentation** — natural-language Given/When/Then
3. **Executed as automated GUI tests** — pytest-bdd runs them with real card hardware
4. **Screenshot-evidenced** — Allure captures visual proof at each step

Inspired by Tails OS and Krux projects which use Cucumber/Gherkin for executable user stories.

### Interview Summary
**Key Discussions**:
- Framework choice: pytest-bdd + Allure (recommended over AltWalker, SikuliX, Squish, custom YAML)
- UI driving: Logic layer + observer screenshots (not real Qt mouse clicks — too timing-sensitive for CI)
- Initial scope: Story 0 (Factory Reset) only — proves the framework before expanding to Stories 1-3
- Feature files: `electrum/plugins/satochip/tests/features/` subfolder
- Allure: Always-on via `allure-pytest` (zero overhead when not generating reports)

**Research Findings**:
- Tails OS: Cucumber/Gherkin + Sikuli/OpenCV + KVM VMs — heavyweight, not suitable for our scope
- 5 approaches compared: BDD, image-based, Qt-native (Squish), state-machine (AltWalker), hybrid YAML
- pytest-bdd + Allure is the sweet spot: low complexity, builds on existing infra, readable output

### Metis Review
**Identified Gaps** (addressed):
- BDD tests must NOT create separate `cc_session` or `story_artifact_root` fixtures — reuse existing ones
- Step definitions must import from `story_helpers.py`, not reimplement logic
- BDD tests should use existing `@pytest.mark.user_story` marker
- Need explicit handling of `SATOCHIP_OBSERVE_GUI=1` requirement (skip if headless)
- Allure screenshots should use existing `set_status()` screenshot paths, not create a parallel capture system
- pytest-bdd + Python 3.14 compatibility must be verified before proceeding
- New `--run-bdd-stories` flag or reuse `--run-user-stories` — decided: use existing `--run-user-stories`
- Concurrent BDD + existing tests: document that they share same card and cannot run in parallel

---

## Work Objectives

### Core Objective
Create a pytest-bdd framework where Gherkin `.feature` files are the single source of truth for Satochip user stories — readable as documentation, executable as tests, and evidenced with Allure screenshots.

### Concrete Deliverables
- `electrum/plugins/satochip/tests/features/story_0_factory_reset.feature` — Gherkin feature file
- `electrum/plugins/satochip/tests/features/__init__.py` — Package init
- `electrum/plugins/satochip/tests/features/conftest.py` — BDD-specific fixtures and Allure hooks
- `electrum/plugins/satochip/tests/test_bdd_user_stories.py` — Step definitions + scenario binding
- `contrib/requirements/requirements-bdd.txt` — BDD dependencies

### Definition of Done
- [ ] `python3 -m pytest --co -q electrum/plugins/satochip/tests/test_bdd_user_stories.py` collects the scenario (deselected without `--run-user-stories`)
- [ ] `python3 -m pytest electrum/plugins/satochip/tests/test_bdd_user_stories.py --run-user-stories --alluredir=/tmp/allure-results -v` passes with real card + SSH tunnel + SATOCHIP_OBSERVE_GUI=1
- [ ] Allure results directory contains step attachments (screenshots) after run
- [ ] Existing `test_satochip_user_stories.py` still passes unchanged
- [ ] `.feature` file is readable as plain-English documentation

### Must Have
- Gherkin `.feature` file with Given/When/Then steps matching Story 0 flow
- Step definitions that import and call `story_helpers.py` functions (not reimplement)
- Allure screenshot attachment at each step via `allure.attach.file()`
- Existing `--run-user-stories` flag gates BDD test execution
- `@pytest.mark.user_story` marker on BDD test

### Must NOT Have (Guardrails)
- **DO NOT modify** `test_satochip_user_stories.py`, `story_helpers.py`, `test_satochip_plugin.py`, or parent `conftest.py`
- **DO NOT create** a second `cc_session` fixture or `story_artifact_root` fixture — reuse existing session-scoped ones
- **DO NOT reimplement** factory reset logic — step definitions must call `apdu_factory_reset()` from `story_helpers`
- **DO NOT add** Stories 1-3 feature files (Phase 2, not this plan)
- **DO NOT add** Mermaid diagram generation (future enhancement, not this plan)
- **DO NOT add** real Qt mouse-click testing — logic layer + observer screenshots only
- **DO NOT add** CI pipeline for BDD tests (requires real card + SSH tunnel)
- **DO NOT create** new pytest markers — use existing `@pytest.mark.user_story`
- **DO NOT create** a parallel screenshot capture system — hook into existing `set_status()` screenshots and attach via Allure
- **DO NOT over-abstract** — no shared BDD step library for all plugins, Satochip-specific only
- **DO NOT add** parametrized scenarios for different card states (single happy path only)

---

## Verification Strategy

> **ZERO HUMAN INTERVENTION** — ALL verification is agent-executed. No exceptions.

### Test Decision
- **Infrastructure exists**: YES (pytest-qt, qtbot already in use)
- **Automated tests**: YES (Tests-after — the BDD framework IS the test)
- **Framework**: pytest-bdd + allure-pytest (new additions to existing pytest stack)

### QA Policy
Every task MUST include agent-executed QA scenarios.
Evidence saved to `.sisyphus/evidence/task-{N}-{scenario-slug}.{ext}`.

- **CLI verification**: Use Bash — run pytest commands, check output
- **File verification**: Use Bash — grep for expected content in files
- **Integration verification**: Use Bash — run full BDD test with real card

---

## Execution Strategy

### Parallel Execution Waves

```
Wave 1 (Start Immediately — infrastructure + scaffolding):
├── Task 1: Install pytest-bdd + allure-pytest, verify Python 3.14 compat [quick]
├── Task 2: Create features/ directory + __init__.py [quick]
└── Task 3: Create requirements-bdd.txt [quick]

Wave 2 (After Wave 1 — core implementation):
├── Task 4: Create story_0_factory_reset.feature Gherkin file [quick]
├── Task 5: Create features/conftest.py with BDD fixtures + Allure hooks [deep]
└── Task 6: Create test_bdd_user_stories.py with step definitions [deep]

Wave 3 (After Wave 2 — verification + docs):
├── Task 7: Verify BDD test collection, skip behavior, and marker [quick]
├── Task 8: Run full BDD test with real card + verify Allure output [deep]
└── Task 9: Update ui_workflows/README.md with BDD run instructions [quick]

Wave FINAL (After ALL tasks — independent review):
├── Task F1: Plan compliance audit (oracle)
├── Task F2: Code quality review (unspecified-high)
├── Task F3: Real QA — run BDD test end-to-end (unspecified-high)
└── Task F4: Scope fidelity check (deep)

Critical Path: Task 1 → Task 4 → Task 6 → Task 8 → F1-F4
Parallel Speedup: ~50% faster than sequential
Max Concurrent: 3 (Waves 1 & 2)
```

### Dependency Matrix

| Task | Depends On | Blocks | Wave |
|------|-----------|--------|------|
| 1 | — | 4, 5, 6 | 1 |
| 2 | — | 4, 5, 6 | 1 |
| 3 | — | — | 1 |
| 4 | 1, 2 | 6 | 2 |
| 5 | 1, 2 | 6 | 2 |
| 6 | 4, 5 | 7, 8 | 2 |
| 7 | 6 | — | 3 |
| 8 | 6 | — | 3 |
| 9 | 6 | — | 3 |
| F1-F4 | ALL | — | FINAL |

### Agent Dispatch Summary

- **Wave 1**: 3 tasks — T1 → `quick`, T2 → `quick`, T3 → `quick`
- **Wave 2**: 3 tasks — T4 → `quick`, T5 → `deep`, T6 → `deep`
- **Wave 3**: 3 tasks — T7 → `quick`, T8 → `deep`, T9 → `quick`
- **FINAL**: 4 tasks — F1 → `oracle`, F2 → `unspecified-high`, F3 → `unspecified-high`, F4 → `deep`

---

## TODOs


- [x] 1. Install pytest-bdd + allure-pytest and verify Python 3.14 compatibility

  **What to do**:
  - Run `python3 -m pip install pytest-bdd allure-pytest`
  - Verify installation: `python3 -c "import pytest_bdd; import allure; print('OK')"`
  - Verify pytest-bdd version is >= 7.0 (needed for modern Gherkin parser)
  - Verify no conflicts with existing pytest-qt, pytest-order

  **Must NOT do**:
  - Do NOT install system-wide - use the same Python 3.14 venv as existing tests
  - Do NOT downgrade any existing packages

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1 (with Tasks 2, 3)
  - **Blocks**: Tasks 4, 5, 6
  - **Blocked By**: None

  **References**:
  - `electrum/plugins/satochip/tests/conftest.py` - existing test infrastructure using pytest
  - `electrum/plugins/satochip/tests/ui_workflows/conftest.py` - pytest-qt fixtures already in use

  **Acceptance Criteria**:
  - [ ] `python3 -c "import pytest_bdd; print(pytest_bdd.__version__)"` prints version >= 7.0
  - [ ] `python3 -c "import allure; print('allure-pytest OK')"` succeeds
  - [ ] Existing tests still collected (no regression)

  **QA Scenarios:**
  ```
  Scenario: Verify pytest-bdd installed correctly
    Tool: Bash
    Steps:
      1. Run: python3 -m pip install pytest-bdd allure-pytest
      2. Run: python3 -c "import pytest_bdd; print(pytest_bdd.__version__)"
      3. Assert output contains a version string (e.g. 7.x.x)
    Expected Result: Both packages installed without errors
    Evidence: .sisyphus/evidence/task-1-install-verify.txt

  Scenario: No regression on existing tests
    Tool: Bash
    Steps:
      1. Run: python3 -m pytest --co -q electrum/plugins/satochip/tests/test_satochip_user_stories.py --run-user-stories 2>&1
      2. Assert output shows tests collected (Stories 0-3 still present)
    Expected Result: Existing tests still collected normally
    Evidence: .sisyphus/evidence/task-1-no-regression.txt
  ```

  **Commit**: YES (groups with Tasks 2, 3)
  - Message: `chore(satochip): add pytest-bdd and allure-pytest dependencies`

- [x] 2. Create features/ directory with __init__.py

  **What to do**:
  - Create directory: `electrum/plugins/satochip/tests/features/`
  - Create empty `__init__.py` in the new directory

  **Must NOT do**:
  - Do NOT create any `.feature` files yet (that is Task 4)
  - Do NOT modify parent `__init__.py` files

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1 (with Tasks 1, 3)
  - **Blocks**: Tasks 4, 5, 6
  - **Blocked By**: None

  **References**:
  - `electrum/plugins/satochip/tests/ui_workflows/__init__.py` - existing test subpackage pattern

  **Acceptance Criteria**:
  - [ ] Directory exists: `electrum/plugins/satochip/tests/features/`
  - [ ] `__init__.py` exists in the directory

  **QA Scenarios:**
  ```
  Scenario: Features directory exists as Python package
    Tool: Bash
    Steps:
      1. Run: ls -la electrum/plugins/satochip/tests/features/
      2. Assert output includes __init__.py
    Expected Result: Directory exists with __init__.py
    Evidence: .sisyphus/evidence/task-2-dir-exists.txt
  ```

  **Commit**: YES (groups with Tasks 1, 3)

- [x] 3. Create requirements-bdd.txt

  **What to do**:
  - Create `contrib/requirements/requirements-bdd.txt` with:
    ```
    pytest-bdd>=7.0.0
    allure-pytest>=2.13.0
    ```
  - Follow existing requirements file patterns in `contrib/requirements/`

  **Must NOT do**:
  - Do NOT modify existing requirements files

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1 (with Tasks 1, 2)
  - **Blocks**: None
  - **Blocked By**: None

  **References**:
  - `contrib/requirements/` - check existing files for naming convention

  **Acceptance Criteria**:
  - [ ] File contains `pytest-bdd>=7.0.0` and `allure-pytest>=2.13.0`

  **QA Scenarios:**
  ```
  Scenario: Requirements file correct
    Tool: Bash
    Steps:
      1. Run: cat contrib/requirements/requirements-bdd.txt
      2. Assert output contains pytest-bdd and allure-pytest
    Expected Result: File exists with both dependencies
    Evidence: .sisyphus/evidence/task-3-requirements.txt
  ```

  **Commit**: YES (groups with Tasks 1, 2)

- [x] 4. Create story_0_factory_reset.feature Gherkin file

  **What to do**:
  - Create `electrum/plugins/satochip/tests/features/story_0_factory_reset.feature`
  - Write Gherkin scenario matching the existing Story 0 flow:
    ```gherkin
    Feature: Story 0 - Factory Reset
      As a Satochip user
      I want to factory-reset my card
      So that it returns to a blank state ready for fresh setup

      Background:
        Given a real Satochip card is connected via remote reader
        And the GUI observer is active

      Scenario: Factory reset returns card to blank state
        Given the card status is recorded before reset
        When the APDU factory reset flow is initiated
        And the user removes and reinserts the card as prompted
        Then the APDU reset flow completes successfully
        When the card is removed for final verification
        And the card is reinserted for status check
        Then the card status shows setup_done is False
        And the card is in factory-reset state
        And the factory reset event log is complete
    ```
  - Steps should map 1:1 to the phases in `TestStory0FactoryReset.test_factory_reset_card`
  - Use descriptive step names that read as natural English documentation

  **Must NOT do**:
  - Do NOT add scenarios for Stories 1-3
  - Do NOT add parametrized scenarios or scenario outlines
  - Do NOT add Background steps that modify card state

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES (with Task 5 in Wave 2)
  - **Parallel Group**: Wave 2 (with Task 5)
  - **Blocks**: Task 6
  - **Blocked By**: Tasks 1, 2

  **References**:
  - `electrum/plugins/satochip/tests/test_satochip_user_stories.py:162-301` - Story 0 implementation with exact step sequence: start -> APDU reset flow (card remove/reinsert cycles) -> verify card is blank (setup_done=False)
  - `electrum/plugins/satochip/tests/story_helpers.py:293-399` - `apdu_factory_reset()` function showing the card interaction protocol (set_mode_factory_reset, card remove, reinsert, card_reset_factory_signal loop)
  - `electrum/plugins/satochip/tests/story_helpers.py:192-229` - `require_card_state()` for card status checking
  - `electrum/plugins/satochip/tests/story_helpers.py:266-291` - `wait_for_card_present()` and `wait_for_card_absent()` timing helpers
  - pytest-bdd Gherkin syntax: https://pytest-bdd.readthedocs.io/en/stable/

  **Acceptance Criteria**:
  - [ ] File exists at `electrum/plugins/satochip/tests/features/story_0_factory_reset.feature`
  - [ ] Contains `Feature:`, `Scenario:`, `Given`, `When`, `Then` keywords
  - [ ] Steps match the logical flow of existing Story 0 test
  - [ ] Readable as plain-English documentation without code knowledge

  **QA Scenarios:**
  ```
  Scenario: Feature file is valid Gherkin
    Tool: Bash
    Steps:
      1. Run: python3 -c "
         from pathlib import Path
         content = Path('electrum/plugins/satochip/tests/features/story_0_factory_reset.feature').read_text()
         assert 'Feature:' in content
         assert 'Scenario:' in content
         assert 'Given' in content
         assert 'When' in content
         assert 'Then' in content
         print('Valid Gherkin structure')"
      2. Assert: prints 'Valid Gherkin structure'
    Expected Result: File parses as valid Gherkin
    Evidence: .sisyphus/evidence/task-4-gherkin-valid.txt

  Scenario: Feature file missing or empty
    Tool: Bash
    Steps:
      1. Run: wc -l electrum/plugins/satochip/tests/features/story_0_factory_reset.feature
      2. Assert: line count is >= 10 (not empty placeholder)
    Expected Result: File has substantive content
    Evidence: .sisyphus/evidence/task-4-not-empty.txt
  ```

  **Commit**: YES (groups with Tasks 5, 6)
  - Message: `feat(satochip): add BDD user story framework with Story 0 factory reset`

- [x] 5. Create features/conftest.py with BDD fixtures and Allure hooks

  **What to do**:
  - Create `electrum/plugins/satochip/tests/features/conftest.py`
  - Add a `@pytest.fixture` that wraps the `create_gui_observer()` + `set_status()` pattern with Allure attachment:
    - After each step, call `allure.attach.file(screenshot_path, name=step_name, attachment_type=allure.attachment_type.PNG)`
  - Add a `bdd_artifacts` fixture that creates a `StoryArtifacts` instance for BDD tests
  - Add a `bdd_status_fn` fixture that returns a status function wrapping `set_status()` + Allure attachment
  - Reuse existing fixtures from parent conftest: `cc_session`, `story_artifact_root`
  - Add `@pytest.fixture` for `allure_step_screenshot` that attaches the latest screenshot after each Gherkin step
  - Ensure `SATOCHIP_OBSERVE_GUI=1` check works the same as existing tests

  **Must NOT do**:
  - Do NOT create a new `cc_session` fixture - reuse the session-scoped one from parent conftest
  - Do NOT create a new `story_artifact_root` fixture - reuse from parent conftest
  - Do NOT duplicate screenshot capture logic - call `set_status()` from `story_helpers`
  - Do NOT modify the parent conftest.py

  **Recommended Agent Profile**:
  - **Category**: `deep`
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES (with Task 4 in Wave 2)
  - **Parallel Group**: Wave 2 (with Task 4)
  - **Blocks**: Task 6
  - **Blocked By**: Tasks 1, 2

  **References**:
  - `electrum/plugins/satochip/tests/story_helpers.py:78-124` - `create_gui_observer()` returns (app, widget, status_label, observe_gui)
  - `electrum/plugins/satochip/tests/story_helpers.py:131-165` - `set_status()` prints + updates GUI + saves screenshot
  - `electrum/plugins/satochip/tests/story_helpers.py:43-72` - `StoryArtifacts` class for artifact directory layout
  - `electrum/plugins/satochip/tests/story_helpers.py:171-186` - `record_event()` for JSONL logging
  - `electrum/plugins/satochip/tests/conftest.py:276-332` - `cc_session` session-scoped fixture
  - `electrum/plugins/satochip/tests/conftest.py:334-345` - `story_artifact_root` session-scoped fixture
  - `electrum/plugins/satochip/tests/conftest.py:219-257` - `pytest_collection_modifyitems()` for --run-user-stories gating
  - `electrum/plugins/satochip/tests/ui_workflows/conftest.py` - example of sub-conftest that adds fixtures without duplicating parent ones
  - allure-pytest docs: `allure.attach.file(path, name, attachment_type)`

  **Acceptance Criteria**:
  - [ ] File exists at `electrum/plugins/satochip/tests/features/conftest.py`
  - [ ] Imports from `story_helpers` (create_gui_observer, set_status, StoryArtifacts, record_event)
  - [ ] Imports `allure` for screenshot attachment
  - [ ] Does NOT define `cc_session` or `story_artifact_root` fixtures
  - [ ] Provides a fixture that wraps status/screenshot with Allure attachment

  **QA Scenarios:**
  ```
  Scenario: Conftest imports from story_helpers not reimplements
    Tool: Bash
    Steps:
      1. Run: grep -c 'from electrum.plugins.satochip.tests.story_helpers import' electrum/plugins/satochip/tests/features/conftest.py
      2. Assert: count >= 1
      3. Run: grep -c 'def cc_session' electrum/plugins/satochip/tests/features/conftest.py
      4. Assert: count == 0 (not redefined)
    Expected Result: Imports helpers, does not redefine parent fixtures
    Evidence: .sisyphus/evidence/task-5-conftest-imports.txt

  Scenario: Allure integration present
    Tool: Bash
    Steps:
      1. Run: grep -c 'import allure' electrum/plugins/satochip/tests/features/conftest.py
      2. Assert: count >= 1
      3. Run: grep -c 'allure.attach' electrum/plugins/satochip/tests/features/conftest.py
      4. Assert: count >= 1
    Expected Result: Allure attachment logic present
    Evidence: .sisyphus/evidence/task-5-allure-present.txt
  ```

  **Commit**: YES (groups with Tasks 4, 6)
  - Message: `feat(satochip): add BDD user story framework with Story 0 factory reset`

- [x] 6. Create test_bdd_user_stories.py with step definitions

  **What to do**:
  - Create `electrum/plugins/satochip/tests/test_bdd_user_stories.py`
  - Import the scenario from the feature file using `@scenario()`
  - Define `@given`, `@when`, `@then` step definitions that:
    - Call `create_gui_observer()`, `set_status()`, `apdu_factory_reset()`, `record_event()` from `story_helpers`
    - Call `wait_for_card_absent()`, `wait_for_card_present()` from `story_helpers`
    - Use `cc_session` fixture for card operations
    - Attach Allure screenshots at each step
  - Add `@pytest.mark.user_story` marker
  - Add module-level docstring explaining: what this file is, how to run, relationship to existing tests
  - Use `target_fixture` in `@given` steps to pass context between steps (e.g., observer, artifacts, status_fn)
  - The `@when("the APDU factory reset flow is initiated")` step calls `apdu_factory_reset(cc_session, _status_fn, app=app)`
  - The `@then("the card status shows setup_done is False")` step calls `cc_session.card_get_status()` and asserts `setup_done is False`

  **Must NOT do**:
  - Do NOT reimplement factory reset logic - call `apdu_factory_reset()` from `story_helpers`
  - Do NOT create a new card connection - use `cc_session` fixture
  - Do NOT add step definitions for Stories 1-3
  - Do NOT use `time.sleep` - reuse existing wait helpers from `story_helpers`
  - Do NOT add new pytest markers - use `@pytest.mark.user_story`
  - Do NOT duplicate the cascade-skip mechanism from existing tests

  **Recommended Agent Profile**:
  - **Category**: `deep`
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: NO (depends on Tasks 4 and 5)
  - **Parallel Group**: Wave 2 (sequential after Tasks 4, 5)
  - **Blocks**: Tasks 7, 8, 9
  - **Blocked By**: Tasks 4, 5

  **References**:
  - `electrum/plugins/satochip/tests/test_satochip_user_stories.py:162-301` - Story 0 test implementation - THE reference for what each step does
  - `electrum/plugins/satochip/tests/story_helpers.py:293-399` - `apdu_factory_reset()` - the actual factory reset function to call
  - `electrum/plugins/satochip/tests/story_helpers.py:78-124` - `create_gui_observer()` - creates Qt observer window
  - `electrum/plugins/satochip/tests/story_helpers.py:131-165` - `set_status()` - prints status + updates GUI + saves screenshot
  - `electrum/plugins/satochip/tests/story_helpers.py:171-186` - `record_event()` - JSONL event logging
  - `electrum/plugins/satochip/tests/story_helpers.py:266-291` - `wait_for_card_present/absent()` - card polling helpers
  - `electrum/plugins/satochip/tests/story_helpers.py:192-229` - `require_card_state()` - card state checking
  - `electrum/plugins/satochip/tests/conftest.py:276-332` - `cc_session` fixture definition
  - `electrum/plugins/satochip/tests/conftest.py:334-345` - `story_artifact_root` fixture
  - `electrum/plugins/satochip/tests/conftest.py:219-257` - `pytest_collection_modifyitems` with `--run-user-stories` gating
  - pytest-bdd docs: `@scenario()`, `@given()`, `@when()`, `@then()`, `target_fixture` parameter

  **Acceptance Criteria**:
  - [ ] File exists at `electrum/plugins/satochip/tests/test_bdd_user_stories.py`
  - [ ] Contains `@scenario('features/story_0_factory_reset.feature', ...)` binding
  - [ ] Contains `@given`, `@when`, `@then` decorators matching feature file steps
  - [ ] Imports `apdu_factory_reset`, `create_gui_observer`, `set_status`, `record_event` from `story_helpers`
  - [ ] Uses `@pytest.mark.user_story` marker
  - [ ] Has module-level docstring with run instructions

  **QA Scenarios:**
  ```
  Scenario: Step definitions match feature file steps
    Tool: Bash
    Steps:
      1. Run: grep -c '@given\|@when\|@then' electrum/plugins/satochip/tests/test_bdd_user_stories.py
      2. Assert: count >= 8 (matching feature file steps)
      3. Run: grep 'from electrum.plugins.satochip.tests.story_helpers import' electrum/plugins/satochip/tests/test_bdd_user_stories.py
      4. Assert: output contains apdu_factory_reset
    Expected Result: All steps defined, all helpers imported
    Evidence: .sisyphus/evidence/task-6-step-defs.txt

  Scenario: Test collects with pytest
    Tool: Bash
    Steps:
      1. Run: python3 -m pytest --co -q electrum/plugins/satochip/tests/test_bdd_user_stories.py --run-user-stories 2>&1
      2. Assert: output contains 1 test collected
    Expected Result: BDD scenario collected as a pytest test
    Evidence: .sisyphus/evidence/task-6-collection.txt

  Scenario: Test skipped without --run-user-stories flag
    Tool: Bash
    Steps:
      1. Run: python3 -m pytest --co -q electrum/plugins/satochip/tests/test_bdd_user_stories.py 2>&1
      2. Assert: output shows 0 collected or deselected/skipped
    Expected Result: BDD test gated by existing flag
    Evidence: .sisyphus/evidence/task-6-skip-behavior.txt
  ```

  **Commit**: YES (groups with Tasks 4, 5)
  - Message: `feat(satochip): add BDD user story framework with Story 0 factory reset`
  - Files: `test_bdd_user_stories.py`, `features/story_0_factory_reset.feature`, `features/conftest.py`

- [ ] 7. Verify BDD test collection, skip behavior, and marker integration

  **What to do**:
  - Run pytest collection and verify BDD test is found
  - Verify it is skipped/deselected without `--run-user-stories`
  - Verify it is collected WITH `--run-user-stories`
  - Verify existing Story 0-3 tests are still collected alongside BDD test
  - Verify `@pytest.mark.user_story` marker is applied

  **Must NOT do**:
  - Do NOT modify any files during verification
  - Do NOT run the actual test (that is Task 8)

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES (with Tasks 8, 9 in Wave 3)
  - **Parallel Group**: Wave 3
  - **Blocks**: None
  - **Blocked By**: Task 6

  **References**:
  - `electrum/plugins/satochip/tests/conftest.py:219-257` - `pytest_collection_modifyitems()` that gates `--run-user-stories`

  **Acceptance Criteria**:
  - [ ] `python3 -m pytest --co -q electrum/plugins/satochip/tests/test_bdd_user_stories.py --run-user-stories` shows 1 test
  - [ ] Without `--run-user-stories`: 0 collected or skipped
  - [ ] Existing tests still collected normally alongside BDD test

  **QA Scenarios:**
  ```
  Scenario: BDD test collected with flag
    Tool: Bash
    Steps:
      1. Run: python3 -m pytest --co -q electrum/plugins/satochip/tests/test_bdd_user_stories.py --run-user-stories 2>&1
      2. Assert: output contains test name and 1 collected
    Expected Result: 1 BDD test collected
    Evidence: .sisyphus/evidence/task-7-collected.txt

  Scenario: BDD test skipped without flag
    Tool: Bash
    Steps:
      1. Run: python3 -m pytest --co -q electrum/plugins/satochip/tests/test_bdd_user_stories.py 2>&1
      2. Assert: 0 tests collected or all deselected
    Expected Result: Gated by --run-user-stories
    Evidence: .sisyphus/evidence/task-7-skipped.txt

  Scenario: Coexistence with existing tests
    Tool: Bash
    Steps:
      1. Run: python3 -m pytest --co -q electrum/plugins/satochip/tests/ --run-user-stories 2>&1
      2. Assert: output shows both existing story tests AND new BDD test
    Expected Result: Both test types coexist
    Evidence: .sisyphus/evidence/task-7-coexist.txt
  ```

  **Commit**: NO

- [ ] 8. Run full BDD test with real card and verify Allure output

  **What to do**:
  - Ensure SSH tunnel is active: `ls -la /tmp/pcscd-remote.comm`
  - Set environment: `PCSCLITE_CSOCK_NAME=/tmp/pcscd-remote.comm SATOCHIP_OBSERVE_GUI=1`
  - Run: `python3 -m pytest electrum/plugins/satochip/tests/test_bdd_user_stories.py --run-user-stories --alluredir=/tmp/allure-bdd-results -v -s`
  - Verify test passes
  - Verify Allure results directory contains JSON result files
  - Verify screenshots were attached (check for PNG attachments in Allure results)
  - Also run existing tests to verify no regression: `python3 -m pytest electrum/plugins/satochip/tests/test_satochip_user_stories.py --run-user-stories -v -s`
  - NOTE: This task requires the user to physically remove/reinsert the card when prompted

  **Must NOT do**:
  - Do NOT modify any files
  - Do NOT skip the existing test regression check

  **Recommended Agent Profile**:
  - **Category**: `deep`
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: NO (needs real card - sequential with card access)
  - **Parallel Group**: Wave 3 (but card access is exclusive)
  - **Blocks**: Final Wave
  - **Blocked By**: Task 6

  **References**:
  - `electrum/plugins/satochip/tests/ui_workflows/README.md` - Environment setup instructions
  - SSH tunnel: `ssh -f -N -L "/tmp/pcscd-remote.comm:/run/pcscd/pcscd.comm" root@192.168.13.202`

  **Acceptance Criteria**:
  - [ ] BDD test passes: exit code 0
  - [ ] `/tmp/allure-bdd-results/` contains at least one JSON result file
  - [ ] Allure result contains attachments (screenshots)
  - [ ] Existing Story 0 test still passes (no regression)

  **QA Scenarios:**
  ```
  Scenario: BDD test passes with real card
    Tool: Bash
    Preconditions: SSH tunnel active, SATOCHIP_OBSERVE_GUI=1, real Satochip card inserted
    Steps:
      1. Run: PCSCLITE_CSOCK_NAME=/tmp/pcscd-remote.comm SATOCHIP_OBSERVE_GUI=1 python3 -m pytest electrum/plugins/satochip/tests/test_bdd_user_stories.py --run-user-stories --alluredir=/tmp/allure-bdd-results -v -s
      2. Assert: exit code is 0
      3. Run: ls /tmp/allure-bdd-results/ | grep -c '.json'
      4. Assert: count >= 1
    Expected Result: Test passes and Allure captures results
    Failure Indicators: Exit code non-zero, no JSON files in allure dir
    Evidence: .sisyphus/evidence/task-8-bdd-run.txt

  Scenario: Existing tests not regressed
    Tool: Bash
    Preconditions: Same SSH tunnel + card
    Steps:
      1. Run: PCSCLITE_CSOCK_NAME=/tmp/pcscd-remote.comm SATOCHIP_OBSERVE_GUI=1 python3 -m pytest electrum/plugins/satochip/tests/test_satochip_user_stories.py --run-user-stories -v -s 2>&1 | tail -5
      2. Assert: output shows passed (not failed)
    Expected Result: Existing Story 0 still passes
    Evidence: .sisyphus/evidence/task-8-regression.txt
  ```

  **Commit**: NO

- [ ] 9. Update README with BDD test run instructions

  **What to do**:
  - Add a new section to `electrum/plugins/satochip/tests/ui_workflows/README.md` titled "BDD User Story Tests"
  - Document:
    - What BDD tests are and how they relate to existing tests
    - How to install BDD dependencies: `pip install -r contrib/requirements/requirements-bdd.txt`
    - How to run BDD tests: `python3 -m pytest test_bdd_user_stories.py --run-user-stories --alluredir=/tmp/allure-results -v -s`
    - How to view Allure reports (requires `allure` CLI: `allure serve /tmp/allure-results`)
    - That BDD tests and existing tests share the same card and cannot run concurrently
    - Link to the `.feature` file as the "single source of truth" documentation

  **Must NOT do**:
  - Do NOT rewrite existing README content
  - Do NOT document Stories 1-3 BDD tests (not yet implemented)

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES (with Tasks 7, 8 in Wave 3)
  - **Parallel Group**: Wave 3
  - **Blocks**: None
  - **Blocked By**: Task 6

  **References**:
  - `electrum/plugins/satochip/tests/ui_workflows/README.md` - existing README to extend

  **Acceptance Criteria**:
  - [ ] README contains "BDD" section
  - [ ] Documents install command for requirements-bdd.txt
  - [ ] Documents run command with --alluredir

  **QA Scenarios:**
  ```
  Scenario: README has BDD section
    Tool: Bash
    Steps:
      1. Run: grep -c 'BDD' electrum/plugins/satochip/tests/ui_workflows/README.md
      2. Assert: count >= 3
      3. Run: grep 'requirements-bdd' electrum/plugins/satochip/tests/ui_workflows/README.md
      4. Assert: output is non-empty
    Expected Result: BDD documentation present
    Evidence: .sisyphus/evidence/task-9-readme.txt
  ```

  **Commit**: YES
  - Message: `docs(satochip): add BDD test run instructions to README`
  - Files: `electrum/plugins/satochip/tests/ui_workflows/README.md`

---

## Final Verification Wave (MANDATORY — after ALL implementation tasks)

> 4 review agents run in PARALLEL. ALL must APPROVE. Rejection → fix → re-run.

- [ ] F1. **Plan Compliance Audit** — `oracle`
  Read the plan end-to-end. For each "Must Have": verify implementation exists (read file, run command). For each "Must NOT Have": search codebase for forbidden patterns — reject with file:line if found. Check evidence files exist in `.sisyphus/evidence/`. Compare deliverables against plan.
  Output: `Must Have [N/N] | Must NOT Have [N/N] | Tasks [N/N] | VERDICT: APPROVE/REJECT`

- [ ] F2. **Code Quality Review** — `unspecified-high`
  Review all new files for: import errors, unused imports, syntax errors, missing `__init__.py`. Run `python3 -m py_compile` on each new file. Verify no modifications to protected files (`test_satochip_user_stories.py`, `story_helpers.py`, parent `conftest.py`). Check for AI slop: excessive comments, over-abstraction, generic names.
  Output: `Compile [PASS/FAIL] | Protected Files [CLEAN/MODIFIED] | Code Quality [N issues] | VERDICT`

- [ ] F3. **Real QA — Full BDD Test Run** — `unspecified-high`
  Start from clean state. Run: `SATOCHIP_OBSERVE_GUI=1 python3 -m pytest electrum/plugins/satochip/tests/test_bdd_user_stories.py --run-user-stories --alluredir=/tmp/allure-results -v -s`. Verify test passes. Check Allure results directory has attachments. Verify screenshots captured at each step. Also run existing tests to confirm they still pass.
  Output: `BDD Test [PASS/FAIL] | Allure Attachments [N found] | Existing Tests [PASS/FAIL] | VERDICT`

- [ ] F4. **Scope Fidelity Check** — `deep`
  For each task: read "What to do", read actual diff (git log/diff). Verify 1:1 — everything in spec was built (no missing), nothing beyond spec was built (no creep). Check "Must NOT do" compliance: no modifications to protected files, no Stories 1-3, no Mermaid, no Qt clicks. Flag unaccounted changes.
  Output: `Tasks [N/N compliant] | Scope Creep [CLEAN/N issues] | Protected Files [CLEAN/MODIFIED] | VERDICT`

---

## Commit Strategy

- **Wave 1**: `chore(satochip): add pytest-bdd and allure-pytest dependencies` — `contrib/requirements/requirements-bdd.txt`, `features/__init__.py`
- **Wave 2**: `feat(satochip): add BDD user story framework with Story 0 factory reset` — `features/story_0_factory_reset.feature`, `features/conftest.py`, `test_bdd_user_stories.py`
- **Wave 3**: `docs(satochip): add BDD test run instructions to README` — `ui_workflows/README.md`

---

## Success Criteria

### Verification Commands
```bash
# Collect BDD tests (should find scenario)
python3 -m pytest --co -q electrum/plugins/satochip/tests/test_bdd_user_stories.py --run-user-stories 2>&1
# Expected: 1 test collected

# Skip without flag
python3 -m pytest --co -q electrum/plugins/satochip/tests/test_bdd_user_stories.py 2>&1
# Expected: 0 tests collected (deselected/skipped)

# Full run with real card
SATOCHIP_OBSERVE_GUI=1 python3 -m pytest electrum/plugins/satochip/tests/test_bdd_user_stories.py --run-user-stories --alluredir=/tmp/allure-results -v -s
# Expected: 1 passed

# Allure results exist
ls /tmp/allure-results/*.json
# Expected: result files with attachments

# Existing tests unchanged
python3 -m pytest electrum/plugins/satochip/tests/test_satochip_user_stories.py --run-user-stories -v -s
# Expected: same results as before (no regression)

# Feature file readable
cat electrum/plugins/satochip/tests/features/story_0_factory_reset.feature
# Expected: human-readable Gherkin with Given/When/Then
```

### Final Checklist
- [ ] All "Must Have" present
- [ ] All "Must NOT Have" absent
- [ ] BDD test passes with real card
- [ ] Allure attachments captured
- [ ] Existing tests unmodified and passing
- [ ] Feature file is readable English documentation
