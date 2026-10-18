variable "environment" {
  description = "Nombre del entorno (dev, testnet, pilot, prod)"
  type        = string
}

variable "vpc_id" {
  description = "Identificador de la VPC"
  type        = string
}

variable "private_subnet_ids" {
  description = "Lista de subredes privadas para el DB subnet group"
  type        = list(string)
}

variable "allowed_security_group_ids" {
  description = "Grupos de seguridad autorizados a conectarse al puerto 5432"
  type        = list(string)
  default     = []
}

variable "database_name" {
  description = "Nombre de la base de datos inicial"
  type        = string
  default     = "gravital_id"
}

variable "admin_username" {
  description = "Nombre de usuario administrador de PostgreSQL"
  type        = string
  default     = "gravital_admin"
}

variable "instance_class" {
  description = "Tipo de instancia RDS"
  type        = string
  default     = "db.t4g.micro"
}

variable "allocated_storage_gb" {
  description = "Espacio en disco asignado inicialmente en GiB"
  type        = number
  default     = 20
}

variable "max_allocated_storage_gb" {
  description = "Espacio máximo de auto-escalado en GiB"
  type        = number
  default     = 100
}

variable "backup_retention_days" {
  description = "Días de retención de copias de seguridad automatizadas"
  type        = number
  default     = 7
}

variable "kms_key_arn" {
  description = "ARN de la clave KMS para cifrado de almacenamiento y credenciales"
  type        = string
}
