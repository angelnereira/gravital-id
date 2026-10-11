# Especificación PIP: Estrategia de Pruebas y Aseguramiento de Calidad

> **Identificador normativo:** `SPEC-PIP-TEST-001`  
> **Versión:** `0.1.0-draft` (Fase F0 / Tarea `F0.T19`)  
> **Estado:** Normativo / En revisión  
> **Fecha:** 2026-10-10  
> **Trazabilidad:** REQ-MAINT-003, REQ-MAINT-001..005; `AGENTS.md §10, §11`; P-06, P-08, P-11; INV-05, INV-10, INV-11, INV-12.

---

## 1. Principios y Niveles de Prueba

El protocolo PIP maneja identidad y criptografía crítica. La calidad no se confía a la intuición: se valida mediante una pirámide de pruebas automatizada, determinista y exhaustiva:

```text
               /\
              /  \     Fuzzing Continuo (cargo-fuzz, libFuzzer)
             /────\
            /      \    Verificación Formal & Kani (Aritmética/Límites)
           /────────\
          /          \   Pruebas de Propiedades (proptest)
         /────────────\
        /              \  Pruebas de Conformidad & Vectores Inmutables
       /────────────────\
      /                  \ Pruebas Unitarias y Negativas (cargo-nextest)
     /────────────────────\
    /  Lints & L1-L5 Layers\ (check-layers, clippy -D warnings, cargo-deny)
   └────────────────────────┘
```

### Invariantes de Prueba
* **Determinismo (INV-11):** Toda prueba unitaria y de integración se ejecuta sin dependencias de reloj real ni fuentes de entropía no sembradas. Se inyecta `MockClock` y RNG determinista de `pip-testkit`.
* **Pruebas Negativas Obligatorias:** Cada regla de rechazo o condición de fallo debe contar con al menos una prueba unitaria que dispare y verifique el error tipado correspondiente.
* **Cero Datos Reales (INV-02):** Todos los vectores y fixtures utilizan datos sintéticos generados artificialmente.
* **Vectores Inmutables (INV-12):** Los vectores oficiales en `conformance/vectors/` no se modifican bajo ninguna circunstancia para forzar la aprobación de un test.

---

## 2. Herramientas y Frameworks de Calidad

| Nivel | Herramienta | Función |
|---|---|---|
| **Ejecución de Tests** | `cargo-nextest` | Ejecución paralela, aislada y determinista de tests unitarios y de integración. |
| **Pruebas de Propiedades** | `proptest` | Generación masiva de entradas arbitrarias para parsers CBOR, Base45, JWS y SD-JWT. |
| **Verificación Formal** | `Kani Rust Verifier` | Demostración matemática de ausencia de desbordamientos, pánicos y bucles infinitos en L1. |
| **Pruebas de Mutación** | `cargo-mutants` | Mutación de código para validar que la suite detecta cualquier cambio inadvertido en la lógica. |
| **Fuzzing Robusto** | `cargo-fuzz` (libFuzzer) | Detección de caídas, excepciones de memoria, *out-of-bounds* y *Zip Bombs*. |
| **Reglas de Capas** | `cargo xtask check-layers` | Comprobación estricta de que crates L1–L4 no contengan I/O, `std` ni dependencias prohibidas. |
| **Trazabilidad** | `cargo xtask trace` | Verificación de que cada requisito `REQ-*` de fases cerradas tenga pruebas trazadas. |

---

## 3. Presupuesto y Horas Mínimas de Fuzzing por Gate

Para cerrar formalmente un Gate de la hoja de ruta (`docs/ROADMAP.md`), la suite de fuzzing debe superar un número mínimo de horas de ejecución continua **sin ningún pánico ni fallo de memoria**:

| Gate | Fase | Horas Mínimas Continuas | Objetivos de Fuzzing Requeridos |
|---|---|---|---|
| **G0** | F0 | Spikes exploratorios | Spikes de hardware y prototipo de serialización. |
| **G1** | F1 | $\ge 10$ horas | Parsers L1, decodificadores Base45, JCS canónico, bounds de integers. |
| **G2** | F2 | $\ge 24$ horas | Parser SD-JWT (RFC 9901), descompresión Token Status List, límites de descompresión. |
| **G3** | F3 | $\ge 48$ horas | Generación de disclosures, digests señuelo, ensamblado de credenciales. |
| **G4** | F4 | $\ge 48$ horas | Verificador L3, motor de resolución offline, anti-rollback, piso de tiempo. |
| **G5** | F5 | $\ge 48$ horas | Wallet L3, almacenamiento cifrado AEAD, transcodificación binaria QR. |
| **Nightly**| CI continuo | 4 horas / noche | Toda la superficie de parsing en rama `main`. |

---

## 4. Criterios de Cobertura de Código

* **Workspace General:** $\ge 85\%$ de cobertura de líneas medida con `cargo-llvm-cov`.
* **Crates Críticos (`pip-crypto`, `pip-verifier`, `pip-trust`):** $\ge 95\%$ de cobertura de líneas y $100\%$ de cobertura de ramas críticas en validaciones de firma y anti-rollback.
* **Trazabilidad de Requisitos:** Todo test que valide un requisito normativo debe incluir el comentario canónico:
  ```rust
  // Verifies: REQ-VER-004
  #[test]
  fn verify_ignores_jku_header_and_resolves_only_from_trust_bundle() {
      // ...
  }
  ```
