# Módulo de Cómputo ECS Fargate para Servicios de Gravital ID (ADR-0013, REQ-REL-001, REQ-OBS-001)
# Contenedores OCI ejecutados sin privilegios en entorno Fargate serverless multi-AZ.

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
# 1. Cluster ECS y Grupos de Logs
# ------------------------------------------------------------------------------
resource "aws_ecs_cluster" "main" {
  name = "gravital-id-${var.environment}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name        = "gravital-id-${var.environment}-cluster"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_log_group" "services" {
  name              = "/ecs/gravital-id-${var.environment}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn

  tags = {
    Environment = var.environment
  }
}

# ------------------------------------------------------------------------------
# 2. Roles de IAM para ECS (Ejecución y Tarea con Menor Privilegio)
# ------------------------------------------------------------------------------
resource "aws_iam_role" "execution" {
  name = "gravital-id-${var.environment}-ecs-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "execution_standard" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role" "task" {
  name = "gravital-id-${var.environment}-ecs-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })
}

# Política de permisos para interactuar con S3 y KMS
resource "aws_iam_role_policy" "task_permissions" {
  name = "gravital-id-${var.environment}-task-policy"
  role = aws_iam_role.task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          var.trust_bundles_bucket_arn,
          "${var.trust_bundles_bucket_arn}/*",
          var.status_lists_bucket_arn,
          "${var.status_lists_bucket_arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Sign",
          "kms:GetPublicKey",
          "kms:DescribeKey"
        ]
        Resource = [var.bundle_signing_key_arn]
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# 3. Grupo de Seguridad para Cómputo
# ------------------------------------------------------------------------------
resource "aws_security_group" "compute" {
  name        = "gravital-id-${var.environment}-compute-sg"
  description = "Grupo de seguridad para tareas ECS Fargate de Gravital ID"
  vpc_id      = var.vpc_id

  egress {
    description = "Salida HTTPS para llamadas RPC EVM y APIs externas"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Salida interna hacia PostgreSQL"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr_block]
  }

  tags = {
    Name        = "gravital-id-${var.environment}-compute-sg"
    Environment = var.environment
  }
}

# ------------------------------------------------------------------------------
# 4. Definición de Tarea: pip-indexer (Larga Duración)
# ------------------------------------------------------------------------------
resource "aws_ecs_task_definition" "indexer" {
  family                   = "gravital-id-${var.environment}-indexer"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  container_definitions = jsonencode([{
    name      = "pip-indexer"
    image     = var.indexer_image
    essential = true

    environment = [
      { name = "PORT", value = "8081" },
      { name = "EVM_CHAIN_ID", value = tostring(var.evm_chain_id) },
      { name = "TRUST_REGISTRY_ADDRESS", value = var.trust_registry_address },
      { name = "STATUS_ANCHOR_ADDRESS", value = var.status_anchor_address },
      { name = "RUST_LOG", value = "info" }
    ]

    secrets = [
      {
        name      = "DATABASE_URL"
        valueFrom = var.db_secret_arn
      }
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.services.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "indexer"
      }
    }
  }])
}
