output "secrets_kms_key_arn" {
  description = "ARN de la clave simétrica KMS para secretos"
  value       = aws_kms_key.secrets.arn
}

output "secrets_kms_key_id" {
  description = "ID de la clave simétrica KMS para secretos"
  value       = aws_kms_key.secrets.key_id
}

output "bundle_signing_key_arn" {
  description = "ARN de la clave asimétrica P-256 para firma de Trust Bundles"
  value       = aws_kms_key.bundle_signing.arn
}

output "bundle_signing_key_id" {
  description = "ID de la clave asimétrica P-256 para firma de Trust Bundles"
  value       = aws_kms_key.bundle_signing.key_id
}
