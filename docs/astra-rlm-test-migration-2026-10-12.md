# Astra RLM Regression Migration — 2026-10-12

## Accounting

| Collection | Result |
|---|---:|
| Historical `HEAD` functions in `test_rlm.py` + `test_rlm_repl.py` | 81 |
| Historical run recorded before the fail-closed migration | 30 passed, 51 failed unsafe-positive expectations |
| Current function definitions | 50 |
| Current collected nodes | 56 |
| Current migrated run | 56 passed |
| Native/AppContainer physical tests | 0 executed; approval blocked |

The historical 51 failures were not treated as defects to restore. They
expected generated code to execute in the legacy in-process REPL or an
ordinary worker. The current contract denies those cases before evaluation or
process creation.

## Exact node relationship

Thirty-four historical function node IDs remain unchanged by name and retain
their original non-execution intent (registration, parsing, prompt/context
assembly, safe result classification, and denial checks). They are:

```text
test_rlm.py:
TestRLMAgentRegistration::{test_registered,test_agent_id}
TestRLMCodeExtraction::{test_extract_python_block,test_extract_bare_block,test_no_block,test_python_preferred_over_bare}
TestRLMStripThink::{test_strip_think,test_no_think_tags}
TestRLMDirectAnswer::{test_no_code_block_returns_content,test_default_mode_rejects_generated_code_without_host_execution,test_default_deny_blocks_agent_before_generated_code}
TestRLMWorkerAgentIntegration::{test_worker_mode_requires_explicit_capability_policy,test_worker_mode_denies_without_grant,test_worker_mode_is_explicit_and_ignores_model_override,test_worker_and_legacy_modes_cannot_be_combined}
TestRLMContextInjection::{test_context_from_metadata,test_context_from_memory_results}
TestRLMSubLMCalls::test_sub_lm_called_from_repl
TestRLMMultiTurn::{test_multi_turn_loop,test_max_turns_exceeded,test_max_turns_with_partial_answer}
TestRLMEventBus::{test_agent_events,test_agent_events_with_code}
TestRLMSubLMWithTools::test_sub_lm_tool_resolution
TestRLMDirectToolBridge::{test_root_repl_can_use_file_read_tool_directly,test_root_repl_can_use_bounded_read_helper,test_root_repl_can_use_file_chunk_helper}
TestRLMBlockedCode::test_blocked_code_returns_error
TestRLMToolSectionInjection::{test_system_prompt_includes_tool_section,test_system_prompt_no_tool_section_without_tools}
TestRLMReplResults::test_repl_results_in_tool_results
TestRLMReplResultClassification::{test_import_failure_is_not_success,test_runtime_failure_is_not_success,test_error_like_stdout_remains_success}
```

The following old nodes were explicitly replaced by denial assertions:

| Historical node | Current replacement | Safety assertion |
|---|---|---|
| `TestRLMWorkerAgentIntegration::test_worker_mode_executes_with_context_without_host_callbacks` | `...::test_worker_mode_denies_with_context_without_sandbox` | `RLM_SANDBOX_UNAVAILABLE`, no model generation |
| `...::test_worker_failure_is_returned_without_retry_or_legacy_fallback` | `...::test_worker_failure_cannot_reach_unsandboxed_execution` | denial before worker start |
| `...::test_worker_unknown_outcome_is_propagated_without_retry` | `...::test_worker_unknown_outcome_cannot_start_without_sandbox` | no dispatch before sandbox authorization |
| `...::test_worker_helper_is_explicitly_unavailable` | `...::test_worker_helper_is_unavailable_before_sandbox` | no generated code/model call |
| `TestRLMFinalTermination::test_final_terminates` and `test_final_var_terminates` | `TestRLMLegacyExecution::test_legacy_execution_is_denied_before_model_generation[...]` | parameterized denial for `FINAL`, `FINAL_VAR`, file access, and sub-LM call |
| `TestRLMReplWorkerGate::test_default_repl_is_fail_closed_without_worker` | `TestRLMReplDisabled::test_default_mode_denies_before_code_execution[...]` | four denial inputs; no namespace mutation |
| `TestRLMReplWorkerGate::test_legacy_execution_requires_explicit_opt_in` | `TestRLMReplDisabled::test_legacy_flag_cannot_enable_in_process_execution` | unsafe flag cannot bypass |
| `TestRLMReplCallbacks::*` | `TestRLMReplDisabled::test_direct_execute_is_structured_denial` plus worker callback rejection | no callback or tool dispatch |
| `TestRLMReplSecurity::*` execution positives | `TestRLMReplBoundaryChecks::test_security_check_is_defense_in_depth_only` | filtering is not treated as isolation |
| `TestRLMReplExecutionAllowlist::*` execution positives | `TestRLMReplDisabled::{test_namespace_access_does_not_execute_code,test_close_without_worker_is_safe}` | only non-executing state checks remain |
| `TestRLMReplTermination::*` | no positive replacement | termination requires executing generated code and is not valid without approved sandbox |
| `TestRLMReplOutput::*` runtime/syntax positives | `TestRLMReplResultClassification::*` and denial matrix | no unsandboxed evaluation |

All remaining historical `TestRLMReplBasics::*`, callback execution,
allowlist execution, termination, and output-execution nodes are classified
`OBSOLETE_UNSAFE_POSITIVE_EXPECTATION`, not deleted as evidence of a passing
production capability. Their physical equivalent is
`NATIVE_APPROVAL_BLOCKED` until an approved AppContainer lane exists.

## Coverage boundary

The current suite proves denial before model generation, code evaluation, or
worker creation, structured error propagation, callback rejection, and
`UNKNOWN_OUTCOME` quarantine preconditions. It does not prove native OS token,
filesystem, IPC, network, or descendant isolation.
