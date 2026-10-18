output "vpc_id" {
  description = "ID de la VPC en dev"
  value       = module.networking.vpc_id
}

output "database_endpoint" {
  description = "Punto de conexión a la base de datos PostgreSQL de dev"
  value       = module.database.db_endpoint
}

output "cdn_domain_name" {
  description = "Dominio público de la CDN para consulta de Trust Bundles y Listas de Revocación"
  value       = module.storage.cdn_domain_name
}

output "bundle_signing_key_id" {
  description = "ID de la clave KMS de firma de bundles para el operador de dev"
  value       = module.kms.bundle_signing_key_id
}

output "ecs_cluster_name" {
  description = "Nombre del cluster ECS Fargate"
  value       = module.compute.ecs_cluster_name
}
