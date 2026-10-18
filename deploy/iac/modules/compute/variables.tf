variable "environment" {
  description = "Nombre del entorno (dev, testnet, pilot, prod)"
  type        = string
}

variable "aws_region" {
  description = "Región de AWS"
  type        = string
  default     = "us-east-1"
}

variable "vpc_id" {
  description = "Identificador de la VPC"
  type        = string
}

variable "vpc_cidr_block" {
  description = "Bloque CIDR de la VPC"
  type        = string
}

variable "private_subnet_ids" {
  description = "Lista de subredes privadas para despliegue de tareas Fargate"
  type        = list(string)
}

variable "log_retention_days" {
  description = "Días de retención para logs de CloudWatch"
  type        = number
  default     = 14
}

variable "kms_key_arn" {
  description = "ARN de la clave KMS para cifrado de logs"
  type        = string
}

variable "indexer_image" {
  description = "Imagen OCI para el servicio pip-indexer"
  type        = string
  default     = "ghcr.io/angelnereira/gravital-id/pip-indexer:latest"
}

variable "evm_chain_id" {
  description = "Chain ID de la red EVM"
  type        = number
}

variable "trust_registry_address" {
  description = "Dirección del contrato TrustRegistry"
  type        = string
}

variable "status_anchor_address" {
  description = "Dirección del contrato StatusAnchor"
  type        = string
}

variable "db_secret_arn" {
  description = "ARN del secreto que contiene la cadena de conexión de la base de datos"
  type        = string
}

variable "trust_bundles_bucket_arn" {
  description = "ARN del bucket de Trust Bundles"
  type        = string
}

variable "status_lists_bucket_arn" {
  description = "ARN del bucket de Listas de Revocación"
  type        = string
}

variable "bundle_signing_key_arn" {
  description = "ARN de la clave KMS de firma de bundles"
  type        = string
}
