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