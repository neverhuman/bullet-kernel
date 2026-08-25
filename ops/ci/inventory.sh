#!/usr/bin/env bash
# Canonical nextest partitions. Keep the counts and identities explicit: adding,
# removing, or moving a test is a reviewed CI inventory change, never a silent
# change in coverage.
# shellcheck disable=SC2034 # declarations are consumed by scripts that source this library

readonly EXPECTED_TOTAL_TESTS=545
readonly EXPECTED_STANDALONE_TESTS=502
readonly EXPECTED_STANDALONE_EXECUTED_TESTS=499
readonly EXPECTED_STANDALONE_IGNORED_TESTS=3
readonly EXPECTED_CONTRACT_TESTS=34
readonly EXPECTED_FAMILY_TESTS=9

readonly EXPECTED_ALL_IDENTITIES_SHA256='f289d6c377e1c50850a974d636a31bbdb3463948824a15f69726bb4ed309310b'
readonly EXPECTED_STANDALONE_IDENTITIES_SHA256='85663aea02b4740239f14d9e98aa9d2dda438411353078b769f44313b1153199'
readonly EXPECTED_CONTRACT_IDENTITIES_SHA256='a0161cb946bf20d4ed5c993a367f06832d19353aa118497ab9c2e9e7b7a0b236'
readonly EXPECTED_FAMILY_IDENTITIES_SHA256='09de88e55e74fbf5a611480912897480d5fb1f43a250de115c61557ba9b8d7d8'

readonly CONTRACT_FILTER='binary_id(bullet-harness-claude::offline) | binary_id(bullet-harness-codex::offline) | binary_id(bullet-harness-cursor::offline) | binary_id(bullet-harness-antigravity::offline) | package(bullet-test-simulation)'
readonly FAMILY_FILTER='binary_id(bullet-runner-core::heartbeat_stale) | binary_id(bullet-runner-core::kill_retry) | binary_id(bullet-runner-core::loop_sim) | binary_id(bullet::synthetic_e2e) | binary_id(bullet::transaction_demo)'
readonly STANDALONE_FILTER="not (($CONTRACT_FILTER) | ($FAMILY_FILTER))"

readonly FAMILY_TEST_IDENTITIES=(
  'bullet::transaction_demo::painted_success_and_stale_pass_cannot_be_signed'
  'bullet::transaction_demo::production_gitd_constructor_child_still_refuses_clone'
  'bullet::transaction_demo::self_signed_component_cannot_claim_transaction_admission'
  'bullet::transaction_demo::signed_transaction_component_roundtrip'
  'bullet::transaction_demo::zero_tests_never_satisfy_a_blocking_gate'
  'bullet-runner-core::heartbeat_stale::unavailable_authority_stops_before_running_and_heartbeat'
  'bullet-runner-core::kill_retry::successor_refusals_never_reuse_a_fence_or_create_a_clone'
  'bullet-runner-core::loop_sim::production_authority_refusal_is_typed_and_repository_inert'
  'bullet::synthetic_e2e::synthetic_scaffold_records_typed_authority_refusal_without_evidence'
)

readonly STANDALONE_IGNORED_TEST_IDENTITIES=(
  'bullet-harness-egress::sandbox::claude_strict_sandbox_proves_every_probe_and_blocks_real_commands'
  'bullet-harness-egress::sandbox::custom_policy_tunnels_only_to_the_allowlisted_host_and_port'
  'bullet-harness-egress::sandbox::teardown_kills_holder_uplink_proxy_and_group_children'
)

readonly FAMILY_TEST_SOURCES=(
  'apps/bullet/tests/synthetic_e2e.rs'
  'apps/bullet/tests/transaction_demo.rs'
  'crates/runner/tests/heartbeat_stale.rs'
  'crates/runner/tests/kill_retry.rs'
  'crates/runner/tests/loop_sim.rs'
  'crates/runner/tests/support/mod.rs'
)
