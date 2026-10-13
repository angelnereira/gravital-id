# Matriz de Trazabilidad Requisitos -> Pruebas (REQ-DOC-003)

| ID | Fase | Nivel | Verificación | Principio | Pruebas / Archivos | Estado |
|---|---|---|---|---|---|---|
| REQ-KEY-001 | F2 | DEBE | T, I | P-07 | keystore.rs, lib.rs, purpose.rs, compile_fail.rs, keys_tests.rs, agree_with_signing_key.rs, assign_wrong_purpose.rs, sign_with_hpke_key.rs, trace.rs | Cubierto |
| REQ-KEY-002 | F9 | DEBE | T, D | P-03 | — | Pendiente (Fase futura) |
| REQ-KEY-003 | F9 | DEBE | I, A | P-03 | keystore.rs | Cubierto |
| REQ-KEY-004 | F2 | DEBE | T | P-11 | keystore.rs, lib.rs, software.rs, keys_tests.rs | Cubierto |
| REQ-KEY-005 | F4 | DEBE | T | P-08 | — | Pendiente (Fase futura) |
| REQ-KEY-006 | F4 | DEBE | T | — | — | Pendiente (Fase futura) |
| REQ-KEY-007 | F2 | DEBE | T | P-04 | jwk.rs, api_coverage.rs, lib.rs, software.rs, keys_tests.rs | Cubierto |
| REQ-KEY-008 | F5 | DEBE | T | P-09 | — | Pendiente (Fase futura) |
| REQ-KEY-009 | F2 | DEBE | T | P-07 | keystore.rs, lib.rs, purpose.rs, compile_fail.rs, keys_tests.rs, agree_with_signing_key.rs, sign_with_hpke_key.rs | Cubierto |
| REQ-KEY-010 | F2 | DEBE | T | P-11 | sign.rs, api_coverage.rs, lib.rs, signature.rs, keys_tests.rs, ids.rs | Cubierto |
| REQ-CRED-001 | F3 | DEBE | T | P-04 | kb.rs, lib.rs, parser.rs, kb_jwt_integration.rs, sd_jwt_parsing_verification.rs, sd_jwt_parser.rs | Cubierto |
| REQ-CRED-002 | F3 | DEBE | T, I | P-07 | disclosure.rs, issuer.rs, lib.rs, salt.rs, sd_jwt_emission.rs | Cubierto |
| REQ-CRED-003 | F3 | DEBE | T | P-09 | decoy.rs, issuer.rs, lib.rs, sd_jwt_emission.rs | Cubierto |
| REQ-CRED-004 | F3 | DEBE | T | P-08 | — | Pendiente (Fase futura) |
| REQ-CRED-005 | F3 | PUEDE | T | P-09 | — | Inspección / Auditoría |
| REQ-CRED-006 | F3 | DEBERÍA | T | P-09 | — | Inspección / Auditoría |
| REQ-CRED-007 | F4 | DEBE | T | P-08 | — | Pendiente (Fase futura) |
| REQ-CRED-008 | F3 | DEBE | T, F | P-07 | — | Pendiente (Fase futura) |
| REQ-CRED-009 | F2 | DEBE | T, F | P-08 | json.rs, lib.rs, parser.rs, sd_jwt_parsing_verification.rs, json_bounded.rs, sd_jwt_parser.rs | Cubierto |
| REQ-PRES-001 | F5 | DEBE | T | P-09 | — | Pendiente (Fase futura) |
| REQ-PRES-002 | F5 | DEBE | T | P-08 | kb.rs, lib.rs, parser.rs, kb_jwt_integration.rs | Cubierto |
| REQ-PRES-003 | F5 | DEBE | T, I | P-09 | — | Pendiente (Fase futura) |
| REQ-PRES-004 | F4 | DEBE | T | P-08 | — | Pendiente (Fase futura) |
| REQ-PRES-005 | F5 | DEBE | T, D | P-01 | — | Pendiente (Fase futura) |
| REQ-PRES-006 | F5 | DEBE | T, D | P-01 | — | Pendiente (Fase futura) |
| REQ-PRES-007 | F5 | DEBE | T | P-09 | — | Pendiente (Fase futura) |
| REQ-PRES-008 | F10 | DEBE | T | P-04 | — | Pendiente (Fase futura) |
| REQ-VER-001 | F4 | DEBE | T, I | P-01 | — | Pendiente (Fase futura) |
| REQ-VER-002 | F4 | DEBE | T | P-05 | — | Pendiente (Fase futura) |
| REQ-VER-003 | F4 | DEBE | T, F | P-08 | kb.rs, lib.rs, parser.rs, kb_jwt_integration.rs, sd_jwt_parsing_verification.rs, sd_jwt_parser.rs | Cubierto |
| REQ-VER-004 | F4 | DEBE | T | P-08 | — | Pendiente (Fase futura) |
| REQ-VER-005 | F4 | DEBE | T | — | — | Pendiente (Fase futura) |
| REQ-VER-006 | F4 | DEBE | T | P-08 | — | Pendiente (Fase futura) |
| REQ-VER-007 | F4 | DEBE | I | P-05 | — | Inspección / Auditoría |
| REQ-VER-008 | F2 | DEBE | T, F | P-08 | base64url.rs, cbor.rs, json.rs, differential_serde_json.rs, lib.rs, parser.rs, sd_jwt_parsing_verification.rs, ids.rs, proptest_ids.rs, base64url_strict.rs, cbor_bounded.rs, json_bounded.rs, sd_jwt_parser.rs | Cubierto |
| REQ-VER-009 | F4 | DEBE | T | P-06 | cbor.rs, json.rs, differential_serde_json.rs, lib.rs, clock.rs, cbor_bounded.rs, json_bounded.rs, jwk_parser.rs, sd_jwt_parser.rs | Cubierto |
| REQ-VER-010 | F4 | DEBE | T | P-08 | — | Pendiente (Fase futura) |
| REQ-VER-011 | F4 | DEBE | T | P-08 | — | Pendiente (Fase futura) |
| REQ-VER-012 | F4 | DEBE | T, I | P-08 | — | Pendiente (Fase futura) |
| REQ-STAT-001 | F4 | DEBE | T | P-04 | — | Pendiente (Fase futura) |
| REQ-STAT-002 | F7 | DEBE | T | P-09 | — | Pendiente (Fase futura) |
| REQ-STAT-003 | F4 | DEBE | T, F | P-08 | base45.rs, deflate.rs, base45_strict.rs, deflate_bounded.rs | Cubierto |
| REQ-STAT-004 | F4 | DEBE | T | P-05 | — | Pendiente (Fase futura) |
| REQ-STAT-005 | F7 | DEBE | T | P-10 | — | Pendiente (Fase futura) |
| REQ-STAT-006 | F7 | DEBE | T | P-14 | — | Pendiente (Fase futura) |
| REQ-STAT-007 | F4 | DEBE | T | — | — | Pendiente (Fase futura) |
| REQ-STAT-008 | F7 | DEBE | T | P-08 | — | Pendiente (Fase futura) |
| REQ-TRUST-001 | F4 | DEBE | T | P-08 | — | Pendiente (Fase futura) |
| REQ-TRUST-002 | F4 | DEBE | T | P-08 | — | Pendiente (Fase futura) |
| REQ-TRUST-003 | F7 | DEBE | T | P-14 | — | Pendiente (Fase futura) |
| REQ-TRUST-004 | F7 | DEBE | T | P-10 | — | Pendiente (Fase futura) |
| REQ-TRUST-005 | F7 | DEBE | T, I | P-08 | — | Pendiente (Fase futura) |
| REQ-TRUST-006 | F8 | DEBE | T | P-10 | — | Pendiente (Fase futura) |
| REQ-TRUST-007 | F6 | DEBERÍA | T | P-09 | — | Inspección / Auditoría |
| REQ-TRUST-008 | F7 | DEBE | T | P-15 | — | Pendiente (Fase futura) |
| REQ-TRUST-009 | F4 | DEBE | T | P-15 | — | Pendiente (Fase futura) |
| REQ-TRUST-010 | F4 | DEBE | T | P-14 | — | Pendiente (Fase futura) |
| REQ-LEDG-001 | F6 | DEBE | T, A | P-02 | — | Pendiente (Fase futura) |
| REQ-LEDG-002 | F6 | DEBE | T, I | P-14 | — | Pendiente (Fase futura) |
| REQ-LEDG-003 | F6 | DEBE | I, A | — | — | Inspección / Auditoría |
| REQ-LEDG-004 | F6 | DEBE | T | P-10 | — | Pendiente (Fase futura) |
| REQ-LEDG-005 | F7 | DEBE | T | P-08 | — | Pendiente (Fase futura) |
| REQ-LEDG-006 | F7 | DEBE | T | P-10 | — | Pendiente (Fase futura) |
| REQ-LEDG-007 | F6 | DEBE | I | P-02 | — | Inspección / Auditoría |
| REQ-SYNC-001 | F7 | DEBE | T | P-01 | — | Pendiente (Fase futura) |
| REQ-SYNC-002 | F7 | DEBE | T | — | — | Pendiente (Fase futura) |
| REQ-SYNC-003 | F7 | DEBE | T | — | — | Pendiente (Fase futura) |
| REQ-SYNC-004 | F7 | DEBE | T | P-08 | — | Pendiente (Fase futura) |
| REQ-SYNC-005 | F7 | DEBE | T, I | P-09 | — | Pendiente (Fase futura) |
| REQ-SYNC-006 | F7 | DEBE | T | P-09 | — | Pendiente (Fase futura) |
| REQ-SYNC-007 | F7 | DEBE | T | P-10 | — | Pendiente (Fase futura) |
| REQ-STOR-001 | F5 | DEBE | T | P-03 | — | Pendiente (Fase futura) |
| REQ-STOR-002 | F9 | DEBE | T, D | P-03 | — | Pendiente (Fase futura) |
| REQ-STOR-003 | F5 | DEBE | T, I | P-09 | — | Pendiente (Fase futura) |
| REQ-STOR-004 | F5 | DEBE | T | — | — | Pendiente (Fase futura) |
| REQ-STOR-005 | F5 | DEBE | T | — | — | Pendiente (Fase futura) |
| REQ-STOR-006 | F5 | DEBE | T, I | P-09 | — | Pendiente (Fase futura) |
| REQ-STOR-007 | F9 | DEBE | D, I | P-03 | — | Inspección / Auditoría |
| REQ-STOR-008 | F5 | DEBE | T | P-11 | — | Pendiente (Fase futura) |
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
| REQ-SDK-008 | F4 | DEBE | T | P-14 | — | Pendiente (Fase futura) |
| REQ-SDK-009 | F9 | DEBE | T, I | P-12 | — | Pendiente (Fase futura) |
| REQ-GOV-001 | F14 | DEBE | I | P-12 | — | Inspección / Auditoría |
| REQ-GOV-002 | F14 | DEBE | I, D | P-08 | — | Inspección / Auditoría |
| REQ-GOV-003 | F14 | DEBE | I | P-12 | — | Inspección / Auditoría |
| REQ-SEC-001 | F1 | DEBE | T, I | — | layers.rs | Cubierto |
| REQ-SEC-002 | F2 | DEBE | I | — | aead.rs, ecdh.rs, hpke.rs, kdf.rs, rng.rs, sha.rs, api_coverage.rs, external_vectors.rs | Cubierto |
| REQ-SEC-003 | F2 | DEBE | T, I | — | aead.rs, secret.rs, api_coverage.rs, secret_hygiene.rs, software.rs | Cubierto |
| REQ-SEC-004 | F2 | DEBE | I | — | mac.rs, secret.rs, secret_hygiene.rs | Cubierto |
| REQ-SEC-005 | F2 | DEBE | F | — | base45_strict.rs, base64url_strict.rs, cbor_bounded.rs, deflate_bounded.rs, json_bounded.rs, jwk_parser.rs, sd_jwt_parser.rs, trace.rs | Cubierto |
| REQ-SEC-006 | F1 | DEBE | T | — | — | Pendiente (Fase futura) |
| REQ-SEC-007 | F13 | DEBE | A | — | — | Inspección / Auditoría |
| REQ-SEC-008 | F13 | DEBE | A | — | — | Inspección / Auditoría |
| REQ-SEC-009 | F15 | DEBE | T | — | — | Pendiente (Fase futura) |
| REQ-SEC-010 | F0 | DEBE | I | — | — | Inspección / Auditoría |
| REQ-SEC-011 | F0 | DEBE | I | — | — | Inspección / Auditoría |
| REQ-PRIV-001 | F5 | DEBE | I | — | — | Inspección / Auditoría |
| REQ-PRIV-002 | F4 | DEBE | T | — | — | Pendiente (Fase futura) |
| REQ-PRIV-003 | F7 | DEBE | T, I | — | — | Pendiente (Fase futura) |
| REQ-PRIV-004 | F14 | DEBE | A | — | — | Inspección / Auditoría |
| REQ-PRIV-005 | F5 | DEBE | T | — | — | Pendiente (Fase futura) |
| REQ-PORT-001 | F9 | DEBE | T | — | lib.rs | Cubierto |
| REQ-PORT-002 | F2 | DEBE | T | — | — | Pendiente (Fase futura) |
| REQ-PORT-003 | F2 | DEBE | T, I | — | layers.rs | Cubierto |
| REQ-PORT-004 | F1 | DEBE | T | — | layers.rs | Cubierto |
| REQ-REL-001 | F15 | DEBE | A, D | — | — | Inspección / Auditoría |
| REQ-REL-002 | F15 | DEBE | I | — | — | Inspección / Auditoría |
| REQ-REL-003 | F15 | DEBE | D | — | — | Inspección / Auditoría |
| REQ-REL-004 | F4 | DEBE | T | — | — | Pendiente (Fase futura) |
| REQ-PERF-001 | F2 | DEBE | T | — | crypto_primitives.rs | Cubierto |
| REQ-PERF-002 | F9 | DEBE | T | — | — | Pendiente (Fase futura) |
| REQ-PERF-003 | F5 | DEBE | T | — | — | Pendiente (Fase futura) |
| REQ-MAINT-001 | F1 | DEBE | T | — | — | Pendiente (Fase futura) |
| REQ-MAINT-002 | F1 | DEBE | T | — | layers.rs, trace.rs | Cubierto |
| REQ-MAINT-003 | F4 | DEBE | T | — | — | Pendiente (Fase futura) |
| REQ-MAINT-004 | F1 | DEBE | T | — | — | Pendiente (Fase futura) |
| REQ-MAINT-005 | F4 | DEBERÍA | T | — | — | Inspección / Auditoría |
| REQ-MAINT-006 | F4 | DEBERÍA | T | — | — | Inspección / Auditoría |
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
