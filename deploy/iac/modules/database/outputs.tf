output "db_endpoint" {
  description = "Punto de conexión completo host:puerto de la base de datos"
  value       = aws_db_instance.postgresql.endpoint
}

output "db_host" {
  description = "Dirección de host de la base de datos"
  value       = aws_db_instance.postgresql.address
}

output "db_port" {
  description = "Puerto de la base de datos"
  value       = aws_db_instance.postgresql.port
}

output "db_name" {
  description = "Nombre de la base de datos"
  value       = aws_db_instance.postgresql.db_name
}

output "db_security_group_id" {
  description = "ID del grupo de seguridad de RDS"
  value       = aws_security_group.rds.id
}

output "master_password_secret_arn" {
  description = "ARN del secreto en AWS Secrets Manager con las credenciales maestras"
  value       = aws_db_instance.postgresql.master_user_secret[0].secret_arn
}
