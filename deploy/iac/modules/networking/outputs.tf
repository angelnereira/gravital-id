output "vpc_id" {
  description = "Identificador de la VPC"
  value       = aws_vpc.main.id
}

output "vpc_cidr_block" {
  description = "Bloque CIDR de la VPC"
  value       = aws_vpc.main.cidr_block
}

output "public_subnet_ids" {
  description = "Identificadores de las subredes públicas"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "Identificadores de las subredes privadas"
  value       = aws_subnet.private[*].id
}
