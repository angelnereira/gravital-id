# gravital-id-verifier

> **Capa:** L3 · **no_std:** Sí (`#![no_std]` + `alloc`)

## Propósito

Pipeline de verificación offline para Gravital ID. Implementa el flujo completo de evaluación de credenciales SD-JWT VC con typestate, comprobaciones ordenadas, evidencia paso a paso y resolución estricta en el modelo cerrado de cuatro estados (`Valid`, `ValidWithStaleStatus`, `Unverifiable`, `Invalid`).

## Invariantes aplicables

- **INV-01:** Cero I/O de red en L1–L4 (L1–L3 `no_std`, L4 sans-I/O). El estado persistente vive en el host; el núcleo solo define el contrato.
- **INV-04:** Modelo cerrado de cuatro estados con evidencia exhaustiva por paso.
- **INV-05:** Fail-closed: ante cualquier duda, incoherencia o estado ausente, el resultado nunca es `Valid`.
- **INV-06:** Claves de emisor obtenidas únicamente del trust bundle, nunca de cabeceras JWS (`jku`, `x5u`, `jwk`).
- **INV-08:** Algoritmo ES256 obligatorio; `alg: none` siempre rechazado de forma tajante.
- **INV-10:** Sin pánicos en código de biblioteca.
- **INV-11:** El núcleo nunca lee el reloj: recibe el instante inyectado (`UnixTime`) y, si existe, el tiempo monotónico.

## Funcionalidades

### 1. Pipeline con typestate (`pipeline.rs`, F4.T06)

- **`VerifierPipeline::verify(...)`**: Ejecuta las 11 comprobaciones normativas en orden estricto:
  1. `Structure`: Estructura sintáctica SD-JWT VC compacta y cabeceras JWS (`typ: dc+sd-jwt`, `alg: ES256`).
  2. `IssuerAuthorized`: Emisor registrado y activo en el `TrustBundle` y admitido por la política.
  3. `KeyState`: Clave pública en estado `Active` o `Retired` (válida antes de su retiro).
  4. `Signature`: Firma criptográfica del emisor verificada contra la clave del trust bundle.
  5. `Validity`: Marcas temporales `iat`, `nbf`, `exp` coherentes y vigentes respecto al reloj inyectado.
  6. `Disclosures`: Digests de divulgaciones selectivas verificados contra los hashes firmados.
  7. `Schema`: Validación de identificador de tipo (`vct`) y conformidad con el esquema del perfil.
  8. `KeyBinding`: Verificación de firma del Key Binding JWT del titular contra `cnf.jwk` (si se requiere).
  9. `Nonce`: Validación anti-replay del desafío de sesión contra `VerifierStateStore`.
  10. `Status`: Comprobación del bit de revocación/suspensión en el `StatusSnapshot` de Token Status List.
  11. `Policy`: Verificación de restricciones y perfiles requeridos por el integrador.

- **Typestate y datos no autenticados (REQ-VER-012, ADR-0020)**:
  Si la firma del emisor falla, las 7 comprobaciones que dependen de claims no autenticados (`Validity`, `Disclosures`, `Schema`, `KeyBinding`, `Nonce`, `Status`, `Policy`) quedan marcadas irreversiblemente como `CheckStatus::Skipped`.

- **Inconstruibilidad de `Valid` sin testigo (REQ-VER-012)**:
  El estado `VerificationResult::Valid` solo puede construirse aportando el testigo privado `AllMandatoryPassed`, garantizado mediante pruebas de compilación fallida (`trybuild`).

- **Precedencia normativa de estados (REQ-VER-010)**:
  `Invalid` > `Unverifiable` > `ValidWithStaleStatus` > `Valid`.

### 2. Estado del verificador (`state.rs`, F4.T04)

- **`VerifierStateStore`**: Trait que implementa el host (SQLite, IndexedDB, fichero cifrado) con piso de tiempo, último bundle aceptado, caché de nonces con expiración, `integrity_check()` y `reset()`.
- **`TimeFloorGuard`**: Detección de retroceso de reloj y de estado corrupto antes de procesar credenciales.
- **`StateIntegrityKey`**: Clave secreta con `Zeroize` y `Debug`/`Display` redactados.
- **`InMemoryStateStore`**: Implementación de referencia con integridad HMAC-SHA256 y caché acotada de nonces (4.096 por defecto).

### 3. Política de verificación (`policy.rs`, F4.T05)

- **`VerificationPolicy`**: Configuración declarativa aportada por el integrador.
- **Clases de operación** (`OperationClass::Transaction` / `Query` / `Default`) con frescura máxima de estado normativo por perfil.
- **Sesgo de reloj acotado**: Hasta 300 segundos, rechazando excesos por encima del perfil.

## Ejemplo de uso

```rust,ignore
use gravital_id_verifier::{
    InMemoryStateStore, StateIntegrityKey, VerificationPolicy, VerificationRequest,
    VerifierPipeline, VerificationStatus, OperationClass,
};
use gravital_id_types::UnixTime;

let policy = VerificationPolicy::default();
let mut state_store = InMemoryStateStore::new(StateIntegrityKey::new([0x42; 32]));

let request = VerificationRequest::new(
    "random-nonce-challenge",
    "https://verifier.example.com",
    UnixTime::from_seconds(now.as_seconds() + 300),
    OperationClass::Default,
);

let result = VerifierPipeline::verify(
    &presentation_compact,
    Some(&request),
    &trust_bundle,
    Some(&status_snapshot),
    &mut state_store,
    &policy,
    now,
    None,
);

match result.status() {
    VerificationStatus::Valid => {
        let claims = result.verified_claims().unwrap();
        // Credencial plenamente verificada
    }
    VerificationStatus::ValidWithStaleStatus => {
        // Válida, pero el snapshot de estado excede la frescura de la política
    }
    VerificationStatus::Unverifiable => {
        // Datos no concluyentes (emisor desconocido, estado corrupto, rollback de reloj)
    }
    VerificationStatus::Invalid => {
        // Rechazo normativo (firma inválida, revocada, expirada, replay)
    }
}
```
