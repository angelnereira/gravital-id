# pip-cli / gid-cli — Herramienta de línea de comandos para desarrollo y verificación offline

Binario de línea de comandos para desarrollo, pruebas de integración y verificación completamente offline de credenciales SD-JWT VC para el protocolo Gravital ID (`PIP`).

Cumple con **F4.T12** y verifica **REQ-VER-001**, **REQ-SDK-008**, **INV-01**, **INV-04** e **INV-05**.

## Uso

```bash
# Ejecutar demostración determinista reproducible de los 4 estados offline:
cargo run -p pip-cli -- demo-offline

# Generar emisor y clave de desarrollo (marcada como insegura):
cargo run -p pip-cli -- dev-issuer --out-jwk /tmp/issuer.jwk.json

# Generar trust bundle local:
cargo run -p pip-cli -- dev-bundle --issuer-uri https://issuer.cedula.example.gov --jwk /tmp/issuer.jwk.json --out /tmp/bundle.json

# Verificar una presentación completamente sin conexión:
cargo run -p pip-cli -- verify --presentation "<sd_jwt>" --bundle /tmp/bundle.json
```

## Subcomandos

- `demo-offline`: Reproduce de forma determinista y sin red los 4 estados canónicos de verificación (`Valid`, `ValidWithStaleStatus`, `Unverifiable`, `Invalid`).
- `dev-issuer`: Genera par de claves de emisor para desarrollo con advertencia visible de no apto para producción.
- `dev-bundle`: Construye un archivo de trust bundle JSON canónico con emisores y claves autorizadas.
- `issue`: Emite una credencial SD-JWT VC de prueba.
- `verify`: Ejecuta el pipeline sans-I/O offline sobre una presentación con archivos locales.
