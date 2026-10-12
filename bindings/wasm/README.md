# WASM binding (F1)

> Binding WASM del SDK de Gravital ID para navegador y Node.js
> (`PROJECT_STRUCTURE.md §2`, `bindings/wasm/`).

## Estado

Andamiaje de F1.T13: valida que la fachada `gravital-id-sdk` compila a
`wasm32-unknown-unknown` y que sus tipos cruzan la frontera FFI. La superficie
expuesta aquí es **de humo** (scaffolding) y será sustituida por la API completa
en F9.T01/F9.T06; ningún integrador debe depender de ella aún.

## Reglas

- Solo depende de `gravital-id-sdk` (nunca de crates internos directamente;
  `PROJECT_STRUCTURE.md §4` regla 6, verificado por `cargo xtask check-layers`).
- El código generado por `wasm-bindgen` no se edita ni se versiona
  (`PROJECT_STRUCTURE.md §10`).
- Crate excluido del workspace principal (`[workspace]` vacío): solo compila
  para `wasm32-unknown-unknown`.

## Comandos

```bash
wasm-pack build bindings/wasm --target web        # o bundler/node
wasm-pack test bindings/wasm --node               # pruebas de humo en Node
```
