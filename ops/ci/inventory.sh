#!/usr/bin/env bash
# Canonical nextest partitions. Keep the counts and identities explicit: adding,
# removing, or moving a test is a reviewed CI inventory change, never a silent
# change in coverage.
# shellcheck disable=SC2034 # declarations are consumed by scripts that source this library

readonly EXPECTED_TOTAL_TESTS=534
readonly EXPECTED_STANDALONE_TESTS=496
readonly EXPECTED_STANDALONE_EXECUTED_TESTS=493
readonly EXPECTED_STANDALONE_IGNORED_TESTS=3
readonly EXPECTED_CONTRACT_TESTS=34
readonly EXPECTED_FAMILY_TESTS=4

readonly EXPECTED_ALL_IDENTITIES_SHA256='5edae10649d92e7937b6f659e7ac35c0f00093da9b7eae854119c06c1ad78882'
readonly EXPECTED_STANDALONE_IDENTITIES_SHA256='03ca8d524c56175d0f4c6c401bfa7f93dde18dca2180d74839a2bf397a714297'
readonly EXPECTED_CONTRACT_IDENTITIES_SHA256='a0161cb946bf20d4ed5c993a367f06832d19353aa118497ab9c2e9e7b7a0b236'
readonly EXPECTED_FAMILY_IDENTITIES_SHA256='809724b6d8acc4ad4338db6c6f3c04b9624d459d7257c1ee5752a9537354c6e9'

readonly CONTRACT_FILTER='binary_id(bullet-harness-claude::offline) | binary_id(bullet-harness-codex::offline) | binary_id(bullet-harness-cursor::offline) | binary_id(bullet-harness-antigravity::offline) | package(bullet-test-simulation)'
readonly FAMILY_FILTER='binary_id(bullet-runner-core::heartbeat_stale) | binary_id(bullet-runner-core::kill_retry) | binary_id(bullet-runner-core::loop_sim) | binary_id(bullet::synthetic_e2e)'
readonly STANDALONE_FILTER="not (($CONTRACT_FILTER) | ($FAMILY_FILTER))"

readonly FAMILY_TEST_IDENTITIES=(
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
  'crates/runner/tests/heartbeat_stale.rs'
  'crates/runner/tests/kill_retry.rs'
  'crates/runner/tests/loop_sim.rs'
  'crates/runner/tests/support/mod.rs'
)
