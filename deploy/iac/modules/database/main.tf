# Módulo de Base de Datos PostgreSQL para pip-indexer (ADR-0013, REQ-REL-001, REQ-LEDG-005)
# Instancia relacional PostgreSQL 16 aislada en subred privada sin acceso a Internet.

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

resource "aws_db_subnet_group" "rds" {
  name        = "gravital-id-${var.environment}-db-subnet-group"
  subnet_ids  = var.private_subnet_ids
  description = "Subredes privadas para PostgreSQL de Gravital ID"

  tags = {
    Name        = "gravital-id-${var.environment}-db-subnet-group"
    Environment = var.environment
  }
}

resource "aws_security_group" "rds" {
  name        = "gravital-id-${var.environment}-rds-sg"
  description = "Permite acceso a PostgreSQL exclusivamente desde los servicios autorizados"
  vpc_id      = var.vpc_id

  ingress {
    description     = "Acceso PostgreSQL desde ECS / servicios de computo"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = var.allowed_security_group_ids
  }

  egress {
    description = "Salida bloqueada por defecto"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "gravital-id-${var.environment}-rds-sg"
    Environment = var.environment
  }
}

resource "aws_db_parameter_group" "rds" {
  name   = "gravital-id-${var.environment}-pg16-params"
  family = "postgres16"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  tags = {
    Environment = var.environment
  }
}

resource "aws_db_instance" "postgresql" {
  identifier                  = "gravital-id-${var.environment}-indexer-db"
  engine                      = "postgres"
  engine_version              = "16.3"
  instance_class              = var.instance_class
  allocated_storage           = var.allocated_storage_gb
  max_allocated_storage       = var.max_allocated_storage_gb
  storage_type                = "gp3"
  storage_encrypted           = true
  kms_key_id                  = var.kms_key_arn
  publicly_accessible         = false
  db_subnet_group_name        = aws_db_subnet_group.rds.name
  vpc_security_group_ids      = [aws_security_group.rds.id]
  parameter_group_name        = aws_db_parameter_group.rds.name
  auto_minor_version_upgrade  = true
  allow_major_version_upgrade = false

  db_name  = var.database_name
  username = var.admin_username

  # Gestión segura de credenciales maestras mediante AWS Secrets Manager nativo (cero contraseñas en git)
  manage_master_user_password   = true
  master_user_secret_kms_key_id = var.kms_key_arn

  backup_retention_period   = var.backup_retention_days
  backup_window             = "03:00-04:00"
  maintenance_window        = "Mon:04:30-Mon:05:30"
  copy_tags_to_snapshot     = true
  deletion_protection       = var.environment == "prod" ? true : false
  skip_final_snapshot       = var.environment == "prod" ? false : true
  final_snapshot_identifier = "gravital-id-${var.environment}-indexer-db-final"

  tags = {
    Name        = "gravital-id-${var.environment}-indexer-db"
    Environment = var.environment
    Component   = "pip-indexer"
  }
}
