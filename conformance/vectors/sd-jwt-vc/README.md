# Vectores de conformidad — SD-JWT VC (`sd-jwt-vc`)

> **Estado:** v1 (F3.T09) · **Trazabilidad:** REQ-MAINT-003, REQ-CRED-001, REQ-CRED-004,
> REQ-CRED-005, REQ-CRED-006, REQ-CRED-007, REQ-CRED-008, REQ-CRED-009, REQ-PRES-002.

Corpus publicado de vectores positivos y negativos para la capa SD-JWT VC
(`draft-ietf-oauth-sd-jwt-vc-19`) sobre RFC 9901. Es la referencia que deben cumplir
cualquier implementación del protocolo y contra la que se ejecuta
`cargo xtask conformance`.

## Formato de vector

Cada fichero `.json` es un objeto con estos miembros:

| Miembro | Tipo | Significado |
|---|---|---|
| `name` | texto | Identificador estable del vector (`sd-jwt-vc-<caso>`). |
| `description` | texto | Qué comprueba el vector. |
| `verifies` | array de texto | Identificadores `REQ-*` que el vector verifica. |
| `kind` | `credential` \| `presentation` | Si incluye Key Binding JWT al final. |
| `sd_jwt` | texto | Serialización compacta SD-JWT bajo prueba. |
| `issuer_jwk` | objeto JWK | Clave pública del emisor (rol de la entrada del trust bundle local). Nunca contiene material privado. |
| `holder_jwk` | objeto JWK | Clave pública del titular, solo en presentaciones. |
| `aud`, `nonce` | texto | Valores esperados del KB-JWT, solo en presentaciones. |
| `now` | entero | Instante de referencia (`UnixTime`) con el que se evalúa la vigencia. |
| `policy` | objeto | Política de verificación: `require_status`, `require_exp`, `require_cnf`, `clock_skew_seconds`, `allowed_algorithms`, `profile`. |
| `expected` | objeto | Resultado esperado: `{"result":"valid", …}` o `{"result":"invalid","error_code":"GID-Exxxx"}`. |
| `expected_predicates` | objeto | Predicados que deben aparecer divulgados con un valor booleano concreto (opcional). |

Todos los datos son sintéticos (`INV-02`): ningún vector contiene datos personales reales.

## Ejecución

```bash
cargo xtask conformance
```

El runner:

1. lee todos los `.json` del directorio,
2. parsea el SD-JWT,
3. verifica la firma del emisor contra la JWK del vector,
4. ejecuta `ParsedSdJwt::verify_vc` con la política y el instante del vector,
5. en presentaciones, verifica además el Key Binding JWT,
6. compara el resultado con `expected`.

Cualquier discrepancia hace fallar el comando con código de salida no cero, y la salida
indica el vector y el código observado.

## Inmutabilidad (INV-12)

Un vector publicado **nunca** se edita para que una prueba pase. Si la implementación y un
vector discrepan:

1. se abre un issue (`type:bug` o `type:spec-gap`),
2. se corrige la implementación, salvo que el vector esté demostrablemente erróco,
3. si el vector estaba mal, se marca como obsoleto (se renombra con prefijo `obsolete-`)
   y se publica uno nuevo con nombre estable diferente.

Antes de su primera publicación en `main`, el corpus puede ajustarse desde el generador
(`cargo xtask gen-conformance-vectors`). A partir de ese commit, es inmutable.

## Regeneración (solo para vectores nuevos)

```bash
cargo xtask gen-conformance-vectors
```

Usa `SeededRng` con semillas fijas, de modo que la salida es reproducible y determinista
(REQ-VER-009). No debe usarse para modificar vectores ya publicados.

## Cobertura

| Vector | Regla que rechaza / verifica | Resultado esperado |
|---|---|---|
| `sd-jwt-vc-personal-nominal` | Credencial válida del perfil personal con predicado y estado | `valid` |
| `sd-jwt-vc-presentation-minimized` | Presentación con KB-JWT que divulga solo `age_over_18` | `valid` |
| `sd-jwt-vc-financial-nominal` | Credencial válida del perfil financiero (`enum`, país ISO) | `valid` |
| `sd-jwt-vc-enterprise-nominal` | Credencial válida del perfil empresarial (array de zonas) | `valid` |
| `sd-jwt-vc-batch-copy-0` / `-1` | Copias de lote con clave e índice distintos | `valid` |
| `sd-jwt-vc-alg-none-rejected` | `alg: none` (INV-08) | `GID-E2002` |
| `sd-jwt-vc-algorithm-outside-profile-rejected` | Algoritmo fuera de la lista del perfil (REQ-CRED-008) | `GID-E2002` |
| `sd-jwt-vc-wrong-typ-rejected` | `typ` distinto de `dc+sd-jwt` | `GID-E3001` |
| `sd-jwt-vc-iss-not-https-rejected` | `iss` que no es URL HTTPS | `GID-E3001` |
| `sd-jwt-vc-missing-vct-rejected` | Claim obligatorio ausente | `GID-E3002` |
| `sd-jwt-vc-missing-status-rejected` | Sin referencia de estado (REQ-CRED-007) | `GID-E3002` |
| `sd-jwt-vc-expired-rejected` | `exp` caducada | `GID-E3005` |
| `sd-jwt-vc-not-yet-valid-rejected` | `nbf` futura | `GID-E3006` |
| `sd-jwt-vc-future-iat-rejected` | `iat` futura | `GID-E3006` |
| `sd-jwt-vc-malformed-status-rejected` | `status_list` sin `uri` | `GID-E4001` |
| `sd-jwt-vc-cnf-private-material-rejected` | `cnf.jwk` con parámetro privado `d` | `GID-E2003` |
| `sd-jwt-vc-duplicate-disclosure-rejected` | Divulgación repetida | `GID-E3001` |
| `sd-jwt-vc-unreferenced-disclosure-rejected` | Divulgación no referenciada | `GID-E3001` |
| `sd-jwt-vc-duplicate-claim-name-rejected` | Miembro JSON duplicado (REQ-CRED-009) | `GID-E3001` |
| `sd-jwt-vc-attribute-outside-schema-rejected` | Atributo fuera del esquema del perfil | `GID-E3004` |
| `sd-jwt-vc-vct-profile-mismatch-rejected` | `vct` que no coincide con el perfil de la política | `GID-E3004` |
| `sd-jwt-vc-tampered-signature-rejected` | Firma manipulada | `GID-E2001` |
| `sd-jwt-vc-unsupported-sd-alg-rejected` | `_sd_alg` distinto de `sha-256` | `GID-E2002` |
