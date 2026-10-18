# Módulo de Claves Criptográficas AWS KMS (ADR-0007, ADR-0010, ADR-0013, REQ-ISS-002, REQ-SEC-003)
# Claves criptográficas gestionadas en hardware para firma de Trust Bundles y cifrado de secretos.

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# ------------------------------------------------------------------------------
# 1. Clave Simétrica KMS para Cifrado de Secretos y Bases de Datos
# ------------------------------------------------------------------------------
resource "aws_kms_key" "secrets" {
  description             = "Clave simétrica para cifrado de almacenamiento y secretos de Gravital ID"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name        = "gravital-id-${var.environment}-secrets-kms"
    Environment = var.environment
  }
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/gravital-id-${var.environment}-secrets"
  target_key_id = aws_kms_key.secrets.key_id
}

# ------------------------------------------------------------------------------
# 2. Clave Asimétrica P-256 para Firma de Trust Bundles (pip-trust-service)
# Conforme a ADR-0007, ADR-0010 y perfil ES256 (ECDSA sobre NIST P-256 / SHA-256)
# ------------------------------------------------------------------------------
resource "aws_kms_key" "bundle_signing" {
  description              = "Clave asimétrica ECC NIST P-256 para firma de Trust Bundles de Gravital ID (ES256)"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
  deletion_window_in_days  = 30

  tags = {
    Name        = "gravital-id-${var.environment}-bundle-signing-key"
    Environment = var.environment
    Component   = "pip-trust-service"
  }
}

resource "aws_kms_alias" "bundle_signing" {
  name          = "alias/gravital-id-${var.environment}-bundle-signing"
  target_key_id = aws_kms_key.bundle_signing.key_id
}
