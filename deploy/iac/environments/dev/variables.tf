variable "aws_region" {
  description = "Región de AWS para el despliegue de dev"
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "Bloque CIDR de la VPC"
  type        = string
  default     = "10.10.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "Lista de bloques CIDR para subredes públicas"
  type        = list(string)
  default     = ["10.10.1.0/24", "10.10.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "Lista de bloques CIDR para subredes privadas"
  type        = list(string)
  default     = ["10.10.10.0/24", "10.10.20.0/24"]
}

variable "availability_zones" {
  description = "Zonas de disponibilidad en la región elegida"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "trust_registry_address" {
  description = "Dirección del contrato TrustRegistry"
  type        = string
  default     = "0x89D227B04381014e41E9D70FE1dF49b99971D2Ac"
}

variable "status_anchor_address" {
  description = "Dirección del contrato StatusAnchor"
  type        = string
  default     = "0xC10E45E8F3C9010A51D68FE1e93De45B9071c3DA"
}

variable "indexer_image" {
  description = "Imagen OCI del indexador"
  type        = string
  default     = "ghcr.io/angelnereira/gravital-id/pip-indexer:dev-latest"
}
