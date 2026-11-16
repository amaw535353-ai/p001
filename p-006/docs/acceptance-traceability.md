# Acceptance traceability — 66 requirements

The requested matrix actually enumerates 66 IDs. More than 66 distinct executable assertions are
provided without treating fixtures as native enforcement. Structured cases: contracts/acceptance-catalog.json.
Live results, blocked gates and engineering results have separate counts in validation status.

| ID | Requirement | Offline test / live gate |
|---|---|---|
| C01 | P-006 starts from the approved repository base and does not alter sibling project source. | test_c01_repository_and_siblings_preserved |
| C02 | hardened profile is the default. | test_c02_hardened_default |
| C03 | weak profile requires explicit opt-in. | test_c03_weak_cli_requires_confirmation |
| C04 | weak profile cannot bind public interfaces. | test_c04_weak_cannot_bind_public |
| C05 | strict configuration rejects unknown security-sensitive fields. | test_c05_unknown_config_rejected |
| C06 | unpinned/`latest` service images are rejected in the reproducible profile. | test_c06_mutable_image_rejected |
| C07 | committed files contain no real credentials or generated secrets. | test_c07_committed_inputs_secret_scan |
| C08 | cleanup removes only explicitly labelled P-006-owned resources. | test_c08_cleanup_refuses_unrelated_resource |
| A01 | protected UI/API denies unauthenticated access. | test_a01_identity_missing_denied |
| A02 | valid Keycloak-issued token is accepted for the intended client. | test_a02_identity_valid_signed_fixture |
| A03 | invalid signature is denied. | test_a03_identity_invalid_signature |
| A04 | wrong issuer is denied. | test_a04_identity_wrong_issuer |
| A05 | wrong audience is denied. | test_a05_identity_wrong_audience |
| A06 | expired token is denied. | test_a06_identity_expired |
| A07 | unsupported signing algorithm is denied. | test_a07_identity_unsafe_algorithm |
| A08 | missing required subject/tenant claims is denied. | test_a08_identity_missing_subject |
| A09 | client-supplied identity headers cannot impersonate another user. | test_a09_identity_header_impersonation |
| A10 | client-supplied tenant headers cannot cross tenant boundaries. | test_a10_identity_tenant_header |
| A11 | session expiry/logout behavior is verified. | test_a11_identity_logout_introspection_fixture |
| A12 | disabled/deprovisioned user behavior is tested or explicitly marked unsupported. | test_a12_identity_deactivated_fixture |
| P01 | OPA policy denies by default. | test_p01_policy_deny_never_reaches_vault |
| P02 | authorized user/model/action is allowed. | test_p02_policy_allow_uses_trusted_context |
| P03 | unauthorized model is denied. | test_p03_policy_unauthorized_model |
| P04 | Tenant A cannot access Tenant B. | test_p04_policy_cross_tenant |
| P05 | normal user cannot access administrative operation. | test_p05_policy_normal_user_admin_denied |
| P06 | tenant admin cannot become platform admin. | test_p06_policy_tenant_admin_not_platform |
| P07 | OPA outage fails closed. | test_p07_policy_outage_fails_closed |
| P08 | invalid OPA response fails closed. | test_p08_policy_invalid_response_fails_closed |
| P09 | direct LiteLLM bypass without required PEP authorization is denied. | Explicit native integration gate; status may be BLOCKED/NOT_TESTED |
| P10 | authorization is bound to the actual request model/action/tenant and cannot be reused for a different request. | test_p10_policy_authorized_request_reconstructed |
| V01 | application never uses the Vault root token. | test_v01_vault_root_policy_rejected |
| V02 | intended service can read its approved synthetic secret. | test_v02_vault_reads_and_revokes_per_request |
| V03 | unrelated identity cannot read the secret. | Explicit native integration gate; status may be BLOCKED/NOT_TESTED |
| V04 | expired/revoked application token is denied. | test_v04_vault_revoked_token_denied |
| V05 | Vault outage does not trigger insecure fallback. | test_v05_vault_outage_no_fallback |
| V06 | rotation changes the secret version and application uses the new approved version. | test_v06_vault_rotation_used_without_cache |
| V07 | secret values do not appear in logs, browser responses or error traces. | test_v07_vault_secret_not_returned_or_logged |
| V08 | secret scanning detects a planted dummy-secret marker in a disposable negative-test fixture. | test_v08_secret_scan_negative_control |
| L01 | approved local model route works. | test_l01_gateway_local_request_and_safe_projection |
| L02 | unknown model route is denied. | test_l02_gateway_unknown_model |
| L03 | unauthorized provider route is denied. | test_l03_gateway_provider_route_override |
| L04 | user cannot supply arbitrary provider URL. | test_l04_gateway_arbitrary_url_rejected |
| L05 | LiteLLM master key is never exposed to browser/client. | test_l05_gateway_key_not_in_http_error |
| L06 | quota/rate/size limits are enforced where configured. | test_l06_gateway_rate_limit |
| L07 | provider timeout/outage is safely handled without secret leakage or fail-open routing. | test_l07_gateway_timeout_safely_denied |
| L08 | model/provider override after authorization is denied. | test_l08_gateway_identity_metadata_override |
| N01 | application/gateway local default network has no public egress. | Explicit native integration gate; status may be BLOCKED/NOT_TESTED |
| N02 | only required service-to-service paths are reachable. | Explicit native integration gate; status may be BLOCKED/NOT_TESTED |
| N03 | browser/client cannot reach OPA, Vault or internal administration endpoints. | Explicit native integration gate; status may be BLOCKED/NOT_TESTED |
| N04 | Open WebUI cannot bypass the PEP to reach an unrestricted backend. | Explicit native integration gate; status may be BLOCKED/NOT_TESTED |
| N05 | unapproved external destination is blocked at an actual network enforcement point or marked `NOT_TESTED`/`BLOCKED`. | Explicit native integration gate; status may be BLOCKED/NOT_TESTED |
| N06 | host listeners bind to loopback only. | Explicit native integration gate; status may be BLOCKED/NOT_TESTED |
| U01 | supported Keycloak login path is verified end-to-end or marked blocked. | Explicit native integration gate; status may be BLOCKED/NOT_TESTED |
| U02 | authenticated end-user identity is correctly propagated to the PEP or marked blocked. | Explicit native integration gate; status may be BLOCKED/NOT_TESTED |
| U03 | ordinary user cannot access admin UI/API. | Explicit native integration gate; status may be BLOCKED/NOT_TESTED |
| U04 | disabled plugins/functions/tools remain unavailable to ordinary users. | Explicit native integration gate; status may be BLOCKED/NOT_TESTED |
| U05 | browser does not receive gateway/Vault secrets. | Explicit native integration gate; status may be BLOCKED/NOT_TESTED |
| U06 | unapproved origin is rejected. | test_u06_unapproved_origin |
| U07 | oversized input is rejected within documented bounds. | test_u07_input_size_bounded |
| U08 | direct API calls cannot bypass UI restrictions and server-side authorization. | test_u08_direct_api_still_authorized |
| W01 | selected weakness is reproduced only in the isolated weak profile. | test_w01_weak_cross_tenant_header_reproduced |
| W02 | same scenario is blocked by a verified hardened enforcement point. | test_w02_weak_same_attack_hardened_denied |
| W03 | weak profile is disabled by default and cannot be accidentally exposed. | test_w03_weak_factory_opt_in |
| W04 | hardened profile cannot silently fall back to weak settings. | test_w04_weak_profile_cannot_enter_hardened_engine |
| W05 | P-006 target descriptor validates against the actual P-007 schema. | test_w05_real_p007_descriptor_validates |
| W06 | P-007 live target integration is marked verified only after actual end-to-end P-007 execution; otherwise it remains blocked/not tested. | test_w06_live_p007_not_claimed_available |
