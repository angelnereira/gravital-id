# Matriz de Trazabilidad Requisitos -> Pruebas (REQ-DOC-003)

| ID | Fase | Nivel | Verificación | Principio | Pruebas / Archivos | Estado |
|---|---|---|---|---|---|---|
| REQ-KEY-001 | F2 | DEBE | T, I | P-07 | keystore.rs, lib.rs, purpose.rs, compile_fail.rs, keys_tests.rs, agree_with_signing_key.rs, assign_wrong_purpose.rs, sign_with_hpke_key.rs, trace.rs | Cubierto |
| REQ-KEY-002 | F9 | DEBE | T, D | P-03 | — | Pendiente (Fase futura) |
| REQ-KEY-003 | F9 | DEBE | I, A | P-03 | keystore.rs | Cubierto |
| REQ-KEY-004 | F2 | DEBE | T | P-11 | keystore.rs, lib.rs, software.rs, keys_tests.rs | Cubierto |
| REQ-KEY-005 | F4 | DEBE | T | P-08 | bundle.rs, lib.rs, trust_bundle_integration.rs, verifier_pipeline_integration.rs | Cubierto |
| REQ-KEY-006 | F4 | DEBE | T | — | bundle.rs, lib.rs, trust_bundle_integration.rs, pipeline.rs, verifier_pipeline_integration.rs | Cubierto |
| REQ-KEY-007 | F2 | DEBE | T | P-04 | jwk.rs, api_coverage.rs, lib.rs, software.rs, keys_tests.rs | Cubierto |
| REQ-KEY-008 | F5 | DEBE | T | P-09 | lib.rs, credential.rs, lib.rs, presentation.rs, wallet.rs, holder_credential_management.rs | Cubierto |
| REQ-KEY-009 | F2 | DEBE | T | P-07 | keystore.rs, lib.rs, purpose.rs, compile_fail.rs, keys_tests.rs, agree_with_signing_key.rs, sign_with_hpke_key.rs | Cubierto |
| REQ-KEY-010 | F2 | DEBE | T | P-11 | sign.rs, api_coverage.rs, lib.rs, signature.rs, keys_tests.rs, ids.rs | Cubierto |
| REQ-CRED-001 | F3 | DEBE | T | P-04 | kb.rs, lib.rs, parser.rs, vc.rs, kb_jwt_integration.rs, sd_jwt_parsing_verification.rs, sd_jwt_vc_integration.rs, sd_jwt_parser.rs, generate_vectors.rs | Cubierto |
| REQ-CRED-002 | F3 | DEBE | T, I | P-07 | disclosure.rs, issuer.rs, lib.rs, salt.rs, sd_jwt_emission.rs, batch.rs, lib.rs, issuer_api.rs, generate_vectors.rs | Cubierto |
| REQ-CRED-003 | F3 | DEBE | T | P-09 | decoy.rs, issuer.rs, lib.rs, vc.rs, sd_jwt_emission.rs, request.rs, issuer_api.rs | Cubierto |
| REQ-CRED-004 | F3 | DEBE | T | P-08 | lib.rs, parser.rs, profile.rs, vc.rs, profile_schema_integration.rs, lib.rs, request.rs, issuer_api.rs, verifier_negative_matrix_and_precedence.rs, generate_vectors.rs | Cubierto |
| REQ-CRED-005 | F3 | PUEDE | T | P-09 | lib.rs, predicate.rs, profile.rs, predicate_integration.rs, lib.rs, issuer_api.rs, generate_vectors.rs | Cubierto |
| REQ-CRED-006 | F3 | DEBERÍA | T | P-09 | batch.rs, lib.rs, request.rs, issuer_api.rs, generate_vectors.rs | Cubierto |
| REQ-CRED-007 | F4 | DEBE | T | P-08 | lib.rs, vc.rs, sd_jwt_vc_integration.rs, request.rs, pipeline.rs, policy.rs, verifier_negative_matrix_and_precedence.rs, verifier_pipeline_integration.rs, generate_vectors.rs | Cubierto |
| REQ-CRED-008 | F3 | DEBE | T, F | P-07 | lib.rs, parser.rs, vc.rs, sd_jwt_vc_integration.rs, lib.rs, issuer_api.rs, pipeline.rs, policy.rs, verifier_pipeline_integration.rs, verifier_policy_integration.rs, sd_jwt_parser.rs, generate_vectors.rs | Cubierto |
| REQ-CRED-009 | F2 | DEBE | T, F | P-08 | json.rs, lib.rs, parser.rs, sd_jwt_parsing_verification.rs, json_bounded.rs, sd_jwt_parser.rs, generate_vectors.rs | Cubierto |
| REQ-PRES-001 | F5 | DEBE | T | P-09 | lib.rs, lib.rs, plan.rs, presentation.rs, wallet.rs, holder_dcql_and_presentation.rs, offline_wallet_policy.rs, protocol_wallet_request_validation.rs | Cubierto |
| REQ-PRES-002 | F5 | DEBE | T | P-08 | lib.rs, kb.rs, lib.rs, parser.rs, kb_jwt_integration.rs, profile_schema_integration.rs, sd_jwt_vc_integration.rs, presentation.rs, wallet.rs, holder_dcql_and_presentation.rs, pipeline.rs, verifier_negative_matrix_and_precedence.rs, generate_vectors.rs | Cubierto |
| REQ-PRES-003 | F5 | DEBE | T, I | P-09 | lib.rs, query.rs, wallet.rs, holder_dcql_and_presentation.rs, offline_request.rs | Cubierto |
| REQ-PRES-004 | F4 | DEBE | T | P-08 | offline_request.rs, verifier_state.rs, sqlite_storage_integration.rs, lib.rs, nonce.rs, pipeline.rs, state.rs, verifier_nonce_integration.rs, verifier_pipeline_integration.rs, verifier_state_integration.rs | Cubierto |
| REQ-PRES-005 | F5 | DEBE | T, D | P-01 | lib.rs, cli_integration.rs, cli_m1_demonstration.rs, lib.rs, offline_multi_qr.rs, offline_request.rs, offline_transcoding.rs, protocol_multi_qr_and_budgets.rs, protocol_offline_request.rs, protocol_transcoding_and_qr.rs | Cubierto |
| REQ-PRES-006 | F5 | DEBE | T, D | P-01 | lib.rs, offline_multi_qr.rs, protocol_multi_qr_and_budgets.rs | Cubierto |
| REQ-PRES-007 | F5 | DEBE | T | P-09 | lib.rs, cli_integration.rs, offline_signed_request.rs, offline_wallet_policy.rs, protocol_wallet_request_validation.rs, bundle.rs | Cubierto |
| REQ-PRES-008 | F10 | DEBE | T | P-04 | — | Pendiente (Fase futura) |
| REQ-VER-001 | F4 | DEBE | T, I | P-01 | lib.rs, cli_integration.rs, verifier_offline_and_determinism.rs | Cubierto |
| REQ-VER-002 | F4 | DEBE | T | P-05 | pipeline.rs, result.rs, verifier_negative_matrix_and_precedence.rs, verifier_pipeline_integration.rs | Cubierto |
| REQ-VER-003 | F4 | DEBE | T, F | P-08 | kb.rs, lib.rs, parser.rs, profile.rs, vc.rs, kb_jwt_integration.rs, predicate_integration.rs, profile_schema_integration.rs, sd_jwt_parsing_verification.rs, sd_jwt_vc_integration.rs, holder_credential_management.rs, holder_dcql_and_presentation.rs, issuer_api.rs, cache.rs, status_list_integration.rs, verifier_negative_matrix_and_precedence.rs, verifier_state_integration.rs, sd_jwt_parser.rs, status_list_parser.rs | Cubierto |
| REQ-VER-004 | F4 | DEBE | T | P-08 | pipeline.rs, verifier_negative_matrix_and_precedence.rs, verifier_pipeline_integration.rs | Cubierto |
| REQ-VER-005 | F4 | DEBE | T | — | parser.rs, lib.rs, policy.rs, verifier_negative_matrix_and_precedence.rs, verifier_offline_and_determinism.rs, verifier_policy_integration.rs | Cubierto |
| REQ-VER-006 | F4 | DEBE | T | P-08 | cache.rs, lib.rs, verifier_state.rs, sqlite_storage_integration.rs, lib.rs, pipeline.rs, state.rs, verifier_negative_matrix_and_precedence.rs, verifier_pipeline_integration.rs, verifier_state_integration.rs | Cubierto |
| REQ-VER-007 | F4 | DEBE | I | P-05 | lib.rs, policy.rs, verifier_negative_matrix_and_precedence.rs, verifier_policy_integration.rs | Cubierto |
| REQ-VER-008 | F2 | DEBE | T, F | P-08 | base64url.rs, cbor.rs, json.rs, differential_serde_json.rs, lib.rs, parser.rs, vc.rs, sd_jwt_parsing_verification.rs, sd_jwt_vc_integration.rs, query.rs, request.rs, cache.rs, manifest.rs, status_list_integration.rs, bundle.rs, root.rs, ids.rs, proptest_ids.rs, nonce.rs, state.rs, verifier_nonce_integration.rs, base64url_strict.rs, cbor_bounded.rs, json_bounded.rs, sd_jwt_parser.rs | Cubierto |
| REQ-VER-009 | F4 | DEBE | T | P-06 | cbor.rs, json.rs, differential_serde_json.rs, issuer_api.rs, status_list_integration.rs, lib.rs, clock.rs, verifier_offline_and_determinism.rs, cbor_bounded.rs, json_bounded.rs, jwk_parser.rs, sd_jwt_parser.rs, status_list_parser.rs | Cubierto |
| REQ-VER-010 | F4 | DEBE | T | P-08 | pipeline.rs, result.rs, verifier_negative_matrix_and_precedence.rs, verifier_pipeline_integration.rs | Cubierto |
| REQ-VER-011 | F4 | DEBE | T | P-08 | cache.rs, lib.rs, verifier_state.rs, error.rs, lib.rs, pipeline.rs, state.rs, verifier_negative_matrix_and_precedence.rs, verifier_pipeline_integration.rs, verifier_state_integration.rs | Cubierto |
| REQ-VER-012 | F4 | DEBE | T, I | P-08 | pipeline.rs, result.rs, compile_fail.rs, cannot_construct_valid_directly.rs, verifier_pipeline_integration.rs | Cubierto |
| REQ-STAT-001 | F4 | DEBE | T | P-04 | lib.rs, status_list.rs, status_list_integration.rs, status_list_parser.rs | Cubierto |
| REQ-STAT-002 | F7 | DEBE | T | P-09 | — | Pendiente (Fase futura) |
| REQ-STAT-003 | F4 | DEBE | T, F | P-08 | base45.rs, deflate.rs, lib.rs, status_list.rs, status_list_integration.rs, base45_strict.rs, deflate_bounded.rs, status_list_parser.rs | Cubierto |
| REQ-STAT-004 | F4 | DEBE | T | P-05 | cache.rs, lib.rs, manifest.rs, status_list_integration.rs, pipeline.rs, policy.rs, verifier_pipeline_integration.rs, verifier_policy_integration.rs | Cubierto |
| REQ-STAT-005 | F7 | DEBE | T | P-10 | — | Pendiente (Fase futura) |
| REQ-STAT-006 | F7 | DEBE | T | P-14 | ledger_state_and_derivation.rs, evm_adapter_integration.rs | Cubierto |
| REQ-STAT-007 | F4 | DEBE | T | — | cache.rs, lib.rs, status_list.rs, status_list_integration.rs | Cubierto |
| REQ-STAT-008 | F7 | DEBE | T | P-08 | lib.rs, manifest.rs, status_list_integration.rs, status_list_parser.rs | Cubierto |
| REQ-TRUST-001 | F4 | DEBE | T | P-08 | bundle.rs, jws_json.rs, lib.rs, trust_bundle_integration.rs | Cubierto |
| REQ-TRUST-002 | F4 | DEBE | T | P-08 | bundle.rs, lib.rs, trust_bundle_integration.rs | Cubierto |
| REQ-TRUST-003 | F7 | DEBE | T | P-14 | — | Pendiente (Fase futura) |
| REQ-TRUST-004 | F7 | DEBE | T | P-10 | diff.rs, ledger_state_and_derivation.rs | Cubierto |
| REQ-TRUST-005 | F7 | DEBE | T, I | P-08 | — | Pendiente (Fase futura) |
| REQ-TRUST-006 | F8 | DEBE | T | P-10 | — | Pendiente (Fase futura) |
| REQ-TRUST-007 | F6 | DEBERÍA | T | P-09 | ledger_state_and_derivation.rs, bundle.rs | Cubierto |
| REQ-TRUST-008 | F7 | DEBE | T | P-15 | derivation.rs, diff.rs, error.rs, event.rs, lib.rs, state.rs, ledger_proptest.rs, ledger_state_and_derivation.rs, abi.rs, evm_adapter_integration.rs | Cubierto |
| REQ-TRUST-009 | F4 | DEBE | T | P-15 | verifier_state.rs, sqlite_storage_integration.rs, jws_json.rs, lib.rs, root.rs, trust_bundle_integration.rs | Cubierto |
| REQ-TRUST-010 | F4 | DEBE | T | P-14 | manifest.rs, bundle.rs, lib.rs, trust_bundle_integration.rs | Cubierto |
| REQ-LEDG-001 | F6 | DEBE | T, A | P-02 | event.rs, lib.rs, ledger_state_and_derivation.rs, abi.rs, lib.rs, evm_adapter_integration.rs, contracts_privacy.rs | Cubierto |
| REQ-LEDG-002 | F6 | DEBE | T, I | P-14 | adapter.rs, derivation.rs, diff.rs, error.rs, event.rs, lib.rs, state.rs, ledger_proptest.rs, ledger_state_and_derivation.rs, abi.rs, adapter.rs, lib.rs, transport.rs, evm_adapter_integration.rs | Cubierto |
| REQ-LEDG-003 | F6 | DEBE | I, A | — | — | Inspección / Auditoría |
| REQ-LEDG-004 | F6 | DEBE | T | P-10 | error.rs, lib.rs, state.rs, ledger_state_and_derivation.rs | Cubierto |
| REQ-LEDG-005 | F7 | DEBE | T | P-08 | adapter.rs, client.rs, error.rs, lib.rs, evm_adapter_integration.rs, evm_fault_tolerance.rs | Cubierto |
| REQ-LEDG-006 | F7 | DEBE | T | P-10 | adapter.rs, client.rs, error.rs, lib.rs, transport.rs, evm_adapter_integration.rs, evm_fault_tolerance.rs | Cubierto |
| REQ-LEDG-007 | F6 | DEBE | I | P-02 | event.rs, lib.rs, ledger_state_and_derivation.rs, contracts_privacy.rs | Cubierto |
| REQ-SYNC-001 | F7 | DEBE | T | P-01 | — | Pendiente (Fase futura) |
| REQ-SYNC-002 | F7 | DEBE | T | — | — | Pendiente (Fase futura) |
| REQ-SYNC-003 | F7 | DEBE | T | — | client.rs, evm_fault_tolerance.rs | Cubierto |
| REQ-SYNC-004 | F7 | DEBE | T | P-08 | manifest.rs | Cubierto |
| REQ-SYNC-005 | F7 | DEBE | T, I | P-09 | — | Pendiente (Fase futura) |
| REQ-SYNC-006 | F7 | DEBE | T | P-09 | — | Pendiente (Fase futura) |
| REQ-SYNC-007 | F7 | DEBE | T | P-10 | — | Pendiente (Fase futura) |
| REQ-STOR-001 | F5 | DEBE | T | P-03 | lib.rs, cli_m1_demonstration.rs, credential.rs, wallet.rs, holder_credential_management.rs, envelope.rs, lib.rs, record.rs, storage_envelope_and_indices.rs | Cubierto |
| REQ-STOR-002 | F9 | DEBE | T, D | P-03 | envelope.rs, lib.rs, storage_envelope_and_indices.rs | Cubierto |
| REQ-STOR-003 | F5 | DEBE | T, I | P-09 | wallet.rs, holder_credential_management.rs, backend.rs, blind_index.rs, envelope.rs, lib.rs, storage_envelope_and_indices.rs, storage.rs, sqlite_storage_integration.rs | Cubierto |
| REQ-STOR-004 | F5 | DEBE | T | — | lib.rs, cli_m1_demonstration.rs, wallet.rs, holder_credential_management.rs, backend.rs, lib.rs, storage_envelope_and_indices.rs, lib.rs, migration.rs, storage.rs, sqlite_fault_tolerance.rs, sqlite_storage_integration.rs | Cubierto |
| REQ-STOR-005 | F5 | DEBE | T | — | lib.rs, migration.rs, sqlite_migrations.rs | Cubierto |
| REQ-STOR-006 | F5 | DEBE | T, I | P-09 | audit.rs, lib.rs, wallet.rs, holder_credential_management.rs, holder_privacy_and_forensics.rs, migration.rs | Cubierto |
| REQ-STOR-007 | F9 | DEBE | D, I | P-03 | — | Inspección / Auditoría |
| REQ-STOR-008 | F5 | DEBE | T | P-11 | holder_credential_management.rs, holder_privacy_and_forensics.rs, backend.rs, lib.rs, storage_envelope_and_indices.rs, lib.rs, storage.rs, sqlite_storage_integration.rs | Cubierto |
| REQ-REC-001 | F8 | DEBE | T, D | P-03 | — | Pendiente (Fase futura) |
| REQ-REC-002 | F8 | DEBE | T | P-03 | — | Pendiente (Fase futura) |
| REQ-REC-003 | F8 | DEBERÍA | T | P-10 | — | Inspección / Auditoría |
| REQ-REC-004 | F8 | DEBE | T | P-07 | — | Pendiente (Fase futura) |
| REQ-REC-005 | F8 | DEBE | I | — | — | Inspección / Auditoría |
| REQ-REC-006 | F8 | DEBE | I | P-10 | — | Inspección / Auditoría |
| REQ-REC-007 | F8 | DEBE | T | P-09 | — | Pendiente (Fase futura) |
| REQ-ISS-001 | F10 | DEBE | T | P-04 | — | Pendiente (Fase futura) |
| REQ-ISS-002 | F15 | DEBE | I, A | P-03 | — | Inspección / Auditoría |
| REQ-ISS-003 | F7 | DEBE | T | — | — | Pendiente (Fase futura) |
| REQ-ISS-004 | F10 | DEBE | T | P-08 | — | Pendiente (Fase futura) |
| REQ-ISS-005 | F10 | DEBE | T, D | P-08 | — | Pendiente (Fase futura) |
| REQ-ISS-006 | F8 | DEBE | T | — | — | Pendiente (Fase futura) |
| REQ-SDK-001 | F9 | DEBE | I | P-11 | lib.rs | Cubierto |
| REQ-SDK-002 | F9 | DEBE | T, D | P-11 | — | Pendiente (Fase futura) |
| REQ-SDK-003 | F9 | DEBE | T | P-11 | lib.rs, error.rs, error_codes.rs | Cubierto |
| REQ-SDK-004 | F9 | DEBE | T, F | P-08 | error.rs | Cubierto |
| REQ-SDK-005 | F9 | DEBE | T | P-11 | — | Pendiente (Fase futura) |
| REQ-SDK-006 | F9 | DEBE | T | — | — | Pendiente (Fase futura) |
| REQ-SDK-007 | F9 | DEBE | T | P-11 | — | Pendiente (Fase futura) |
| REQ-SDK-008 | F4 | DEBE | T | P-14 | lib.rs, cli_integration.rs, verifier_offline_and_determinism.rs | Cubierto |
| REQ-SDK-009 | F9 | DEBE | T, I | P-12 | — | Pendiente (Fase futura) |
| REQ-GOV-001 | F14 | DEBE | I | P-12 | — | Inspección / Auditoría |
| REQ-GOV-002 | F14 | DEBE | I, D | P-08 | — | Inspección / Auditoría |
| REQ-GOV-003 | F14 | DEBE | I | P-12 | — | Inspección / Auditoría |
| REQ-PROX-001 | F20 | DEBE | T | P-09 | — | Pendiente (Fase futura) |
| REQ-PROX-002 | F20 | DEBE | T | P-08 | — | Pendiente (Fase futura) |
| REQ-PROX-003 | F20 | DEBE | T | P-06 | error.rs | Cubierto |
| REQ-PROX-004 | F20 | DEBE | T, F | P-08 | — | Pendiente (Fase futura) |
| REQ-PROX-005 | F20 | DEBE | T, D | P-01 | — | Pendiente (Fase futura) |
| REQ-PROX-006 | F21 | DEBE | T, I | P-09 | — | Pendiente (Fase futura) |
| REQ-PROX-007 | F20 | DEBE | T, I | P-09 | — | Pendiente (Fase futura) |
| REQ-PROX-008 | F21 | DEBE | I | P-11 | — | Inspección / Auditoría |
| REQ-CARD-001 | F22 | DEBE | T, I | P-03 | — | Pendiente (Fase futura) |
| REQ-CARD-002 | F22 | DEBE | T | P-08 | — | Pendiente (Fase futura) |
| REQ-CARD-003 | F22 | DEBE | T | P-08 | — | Pendiente (Fase futura) |
| REQ-CARD-004 | F22 | DEBE | T | P-11 | — | Pendiente (Fase futura) |
| REQ-CARD-005 | F22 | DEBE | T, D | P-08 | — | Pendiente (Fase futura) |
| REQ-CODE-001 | F23 | DEBE | T | P-09 | — | Pendiente (Fase futura) |
| REQ-CODE-002 | F23 | DEBE | T, F | P-08 | — | Pendiente (Fase futura) |
| REQ-CODE-003 | F23 | DEBE | T, I | P-08 | — | Pendiente (Fase futura) |
| REQ-CODE-004 | F23 | DEBE | T, I | P-02 | — | Pendiente (Fase futura) |
| REQ-IDDOC-001 | F24 | DEBE | T | P-08 | — | Pendiente (Fase futura) |
| REQ-IDDOC-002 | F24 | DEBE | T, I | P-09 | — | Pendiente (Fase futura) |
| REQ-IDDOC-003 | F24 | DEBE | T, I | P-09 | — | Pendiente (Fase futura) |
| REQ-SEC-001 | F1 | DEBE | T, I | — | layers.rs | Cubierto |
| REQ-SEC-002 | F2 | DEBE | I | — | aead.rs, ecdh.rs, hpke.rs, kdf.rs, rng.rs, sha.rs, api_coverage.rs, external_vectors.rs | Cubierto |
| REQ-SEC-003 | F2 | DEBE | T, I | — | aead.rs, secret.rs, api_coverage.rs, secret_hygiene.rs, software.rs, state.rs, verifier_state_integration.rs | Cubierto |
| REQ-SEC-004 | F2 | DEBE | I | — | mac.rs, secret.rs, secret_hygiene.rs | Cubierto |
| REQ-SEC-005 | F2 | DEBE | F | — | trust_bundle_integration.rs, base45_strict.rs, base64url_strict.rs, cbor_bounded.rs, deflate_bounded.rs, json_bounded.rs, jwk_parser.rs, sd_jwt_parser.rs, status_list_parser.rs, trace.rs | Cubierto |
| REQ-SEC-006 | F1 | DEBE | T | — | — | Pendiente (Fase futura) |
| REQ-SEC-007 | F13 | DEBE | A | — | — | Inspección / Auditoría |
| REQ-SEC-008 | F13 | DEBE | A | — | — | Inspección / Auditoría |
| REQ-SEC-009 | F15 | DEBE | T | — | — | Pendiente (Fase futura) |
| REQ-SEC-010 | F0 | DEBE | I | — | — | Inspección / Auditoría |
| REQ-SEC-011 | F0 | DEBE | I | — | — | Inspección / Auditoría |
| REQ-PRIV-001 | F5 | DEBE | I | — | lib.rs, lib.rs, plan.rs, presentation.rs, query.rs, wallet.rs, holder_dcql_and_presentation.rs, offline_wallet_policy.rs, protocol_wallet_request_validation.rs | Cubierto |
| REQ-PRIV-002 | F4 | DEBE | T | — | verifier_offline_and_determinism.rs | Cubierto |
| REQ-PRIV-003 | F7 | DEBE | T, I | — | — | Pendiente (Fase futura) |
| REQ-PRIV-004 | F14 | DEBE | A | — | — | Inspección / Auditoría |
| REQ-PRIV-005 | F5 | DEBE | T | — | lib.rs, cli_m1_demonstration.rs, audit.rs, lib.rs, presentation.rs, wallet.rs, holder_privacy_and_forensics.rs | Cubierto |
| REQ-PORT-001 | F9 | DEBE | T | — | lib.rs | Cubierto |
| REQ-PORT-002 | F2 | DEBE | T | — | — | Pendiente (Fase futura) |
| REQ-PORT-003 | F2 | DEBE | T, I | — | layers.rs | Cubierto |
| REQ-PORT-004 | F1 | DEBE | T | — | layers.rs | Cubierto |
| REQ-REL-001 | F15 | DEBE | A, D | — | — | Inspección / Auditoría |
| REQ-REL-002 | F15 | DEBE | I | — | — | Inspección / Auditoría |
| REQ-REL-003 | F15 | DEBE | D | — | — | Inspección / Auditoría |
| REQ-REL-004 | F4 | DEBE | T | — | verifier_negative_matrix_and_precedence.rs, verifier_offline_and_determinism.rs | Cubierto |
| REQ-PERF-001 | F2 | DEBE | T | — | crypto_primitives.rs | Cubierto |
| REQ-PERF-002 | F9 | DEBE | T | — | — | Pendiente (Fase futura) |
| REQ-PERF-003 | F5 | DEBE | T | — | lib.rs, cli_integration.rs, cli_m1_demonstration.rs, lib.rs, protocol_multi_qr_and_budgets.rs | Cubierto |
| REQ-MAINT-001 | F1 | DEBE | T | — | — | Pendiente (Fase futura) |
| REQ-MAINT-002 | F1 | DEBE | T | — | layers.rs, trace.rs | Cubierto |
| REQ-MAINT-003 | F4 | DEBE | T | — | verifier_negative_matrix_and_precedence.rs, conformance.rs | Cubierto |
| REQ-MAINT-004 | F1 | DEBE | T | — | — | Pendiente (Fase futura) |
| REQ-MAINT-005 | F4 | DEBERÍA | T | — | protocol_coverage_boost.rs, protocol_wallet_request_validation.rs, verifier_negative_matrix_and_precedence.rs | Cubierto |
| REQ-MAINT-006 | F4 | DEBERÍA | T | — | verifier_negative_matrix_and_precedence.rs | Cubierto |
| REQ-COMP-001 | F14 | DEBE | A | — | — | Inspección / Auditoría |
| REQ-COMP-002 | F14 | DEBE | A | — | — | Inspección / Auditoría |
| REQ-COMP-003 | F1 | DEBE | T | — | — | Pendiente (Fase futura) |
| REQ-OBS-001 | F7 | DEBE | T | — | — | Pendiente (Fase futura) |
| REQ-OBS-002 | F15 | DEBE | D | — | — | Inspección / Auditoría |
| REQ-OBS-003 | F9 | DEBE | T, I | — | — | Pendiente (Fase futura) |
| REQ-DOC-001 | F0 | DEBE | I | — | — | Inspección / Auditoría |
| REQ-DOC-002 | F0 | DEBE | I | — | — | Inspección / Auditoría |
| REQ-DOC-003 | F1 | DEBE | T | — | trace.rs | Cubierto |
| REQ-DOC-004 | F17 | DEBE | I | — | — | Inspección / Auditoría |
