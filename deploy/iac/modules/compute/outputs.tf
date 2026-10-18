output "ecs_cluster_name" {
  description = "Nombre del cluster ECS Fargate"
  value       = aws_ecs_cluster.main.name
}

output "ecs_cluster_arn" {
  description = "ARN del cluster ECS Fargate"
  value       = aws_ecs_cluster.main.arn
}

output "compute_security_group_id" {
  description = "ID del grupo de seguridad de cómputo ECS"
  value       = aws_security_group.compute.id
}

output "indexer_task_definition_arn" {
  description = "ARN de la definición de tarea de pip-indexer"
  value       = aws_ecs_task_definition.indexer.arn
}
