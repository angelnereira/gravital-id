# gravital-id-verifier

> **Capa:** L3 · **no_std:** Sí (`#![no_std]` + `alloc`)

## Propósito

Pipeline de verificación offline para Gravital ID. En F4 se está construyendo por piezas:
esta fase aporta el **estado del verificador** (piso de tiempo confiable, versiones
aceptadas y caché de nonces).

## Invariantes aplicables

- **INV-01:** Cero I/O en L1–L4 (L1–L3 `no_std`, L4 sans-I/O). El estado persistente vive en
  el host; el n\u00facleo solo define el contrato.
- **INV-05:** Fail-closed: ante cualquier duda sobre el estado, nunca se acepta.
- **INV-10:** Sin pánicos en código de biblioteca.
- **INV-11:** El n\u00fucleo nunca lee el reloj: recibe el instante y, si existe, el monotónico.

## Funcionalidades

### Estado del verificador (`state.rs`, F4.T04)

- **`VerifierStateStore`**: trait que implementa el host (SQLite, IndexedDB, fichero cifrado)
  con piso de tiempo, último bundle aceptado, cach\u00e9 de nonces con expiraci\u00f3n,
  `integrity_check()` y `reset()`.
- **`TimeFloorGuard`**: l\u00f3n de decisi\u00f3n en orden fail-closed:
  1. integridad del estado \u219d si falla, `Unverifiable` (`VerifierStateCorrupted`, 5009);
  2. retroceso de reloj \u219d `ClockRollbackDetected` (5007), incluso si el monot\u00f3nico avanza
     (el piso manda);
  3. solo entonces se eleva el piso.
- **`StateIntegrityKey`**: clave de integridad inyectada por el host, tipo secreto con
  `Zeroize`/`ZeroizeOnDrop` y `Debug`/`Display` redactados (REQ-SEC-003, INV-02).
- **`InMemoryStateStore`**: implementaci\u00f3n de referencia con integridad HMAC-SHA256 sobre
  la serializaci\u00f3n can\u00f3nica del estado, cach\u00e9 de nonces acotada (4.096 por defecto) con
  expulsi\u00f3n del que caduca antes, y `raise_time_floor` que nunca baja el piso.

## Ejemplo de uso

```rust,ignore
use gravital_id_verifier::{
    InMemoryStateStore, StateIntegrityKey, TimeFloorCheck, TimeFloorGuard, VerifierStateStore,
};
use gravital_id_types::UnixTime;

// El host inyecta su clave de integridad y respalda el almac\u00e9n.
let mut store = InMemoryStateStore::new(StateIntegrityKey::new([/* 32 bytes del host */ 0; 32]));

// Antes de verificar nada, se comprueba el piso de tiempo confiable.
let mut guard = TimeFloorGuard::new(&mut store);
match guard.check(clock_now, clock.monotonic_elapsed_millis())? {
    TimeFloorCheck::FirstRun => { /* primera ejecuci\u00f3n: se registra el piso */ }
    TimeFloorCheck::Ok => { /* continuar */ }
}

// Tras aceptar una credencial, se recuerda su nonce hasta la expiraci\u00f3n de la sesi\u00f3n.
store.remember_nonce(&nonce, session_expires_at)?;
if store.nonce_seen(&nonce, clock_now)? {
    // REPLAY: el nonce ya se utiliz\u00f3 (REQ-PRES-004).
}
```
