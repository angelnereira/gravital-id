# Entorno Dev para Gravital ID (ADR-0013, REQ-REL-001)
# Despliegue de desarrollo para pruebas de integración con recursos optimizados en costes.

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "GravitalID"
      Environment = "dev"
      ManagedBy   = "OpenTofu"
    }
  }
}

# 1. Red
module "networking" {
  source = "../../modules/networking"

  environment          = "dev"
  vpc_cidr             = var.vpc_cidr
  public_subnet_cidrs  = var.public_subnet_cidrs
  private_subnet_cidrs = var.private_subnet_cidrs
  availability_zones   = var.availability_zones
}

# 2. Claves Criptográficas (KMS)
module "kms" {
  source = "../../modules/kms"

  environment = "dev"
}

# 3. Almacenamiento S3 y CDN
module "storage" {
  source = "../../modules/storage"

  environment = "dev"
}

# 4. Base de Datos Relacional para Indexador (RDS PostgreSQL)
module "database" {
  source = "../../modules/database"

  environment                = "dev"
  vpc_id                     = module.networking.vpc_id
  private_subnet_ids         = module.networking.private_subnet_ids
  allowed_security_group_ids = [module.compute.compute_security_group_id]
  kms_key_arn                = module.kms.secrets_kms_key_arn
  instance_class             = "db.t4g.micro"
  database_name              = "gravital_id_dev"
  admin_username             = "gravital_admin"
  backup_retention_days      = 1
}

# 5. Servicios de Cómputo (ECS Fargate)
module "compute" {
  source = "../../modules/compute"

  environment              = "dev"
  aws_region               = var.aws_region
  vpc_id                   = module.networking.vpc_id
  vpc_cidr_block           = module.networking.vpc_cidr_block
  private_subnet_ids       = module.networking.private_subnet_ids
  kms_key_arn              = module.kms.secrets_kms_key_arn
  evm_chain_id             = 421614
  trust_registry_address   = var.trust_registry_address
  status_anchor_address    = var.status_anchor_address
  db_secret_arn            = module.database.master_password_secret_arn
  trust_bundles_bucket_arn = module.storage.trust_bundles_bucket_arn
  status_lists_bucket_arn  = module.storage.status_lists_bucket_arn
  bundle_signing_key_arn   = module.kms.bundle_signing_key_arn
  indexer_image            = var.indexer_image
}
