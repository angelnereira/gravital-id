# Módulo de Almacenamiento S3 y Distribución CDN (ADR-0010, ADR-0013, ADR-0017, REQ-REL-001)
# Publicación inmutable y distribución pública de Trust Bundles y Listas de Revocación.

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
# 1. Bucket S3 para Trust Bundles
# ------------------------------------------------------------------------------
resource "aws_s3_bucket" "trust_bundles" {
  bucket        = "gravital-id-${var.environment}-trust-bundles"
  force_destroy = var.environment != "prod"

  tags = {
    Name        = "gravital-id-${var.environment}-trust-bundles"
    Environment = var.environment
    Component   = "pip-trust-service"
  }
}

resource "aws_s3_bucket_versioning" "trust_bundles" {
  bucket = aws_s3_bucket.trust_bundles.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trust_bundles" {
  bucket = aws_s3_bucket.trust_bundles.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# ------------------------------------------------------------------------------
# 2. Bucket S3 para Listas de Revocación / Estado
# ------------------------------------------------------------------------------
resource "aws_s3_bucket" "status_lists" {
  bucket        = "gravital-id-${var.environment}-status-lists"
  force_destroy = var.environment != "prod"

  tags = {
    Name        = "gravital-id-${var.environment}-status-lists"
    Environment = var.environment
    Component   = "pip-issuer-service"
  }
}

resource "aws_s3_bucket_versioning" "status_lists" {
  bucket = aws_s3_bucket.status_lists.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "status_lists" {
  bucket = aws_s3_bucket.status_lists.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# ------------------------------------------------------------------------------
# 3. Control de Acceso Público y CloudFront Origin Access Control (OAC)
# ------------------------------------------------------------------------------
resource "aws_cloudfront_origin_access_control" "oac" {
  name                              = "gravital-id-${var.environment}-oac"
  description                       = "OAC para acceso de lectura pública cacheada desde CloudFront a S3"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# Política para permitir lectura pública solo vía CloudFront
data "aws_iam_policy_document" "s3_cdn_policy" {
  statement {
    actions   = ["s3:GetObject"]
    resources = [
      "${aws_s3_bucket.trust_bundles.arn}/*",
      "${aws_s3_bucket.status_lists.arn}/*",
    ]

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.cdn.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "trust_bundles" {
  bucket = aws_s3_bucket.trust_bundles.id
  policy = data.aws_iam_policy_document.s3_cdn_policy.json
}

resource "aws_s3_bucket_policy" "status_lists" {
  bucket = aws_s3_bucket.status_lists.id
  policy = data.aws_iam_policy_document.s3_cdn_policy.json
}

# Bloqueo estricto de escrituras públicas no autenticadas
resource "aws_s3_bucket_public_access_block" "trust_bundles" {
  bucket = aws_s3_bucket.trust_bundles.id

  block_public_acls       = true
  block_public_policy     = false # Permitir política gestionada de CloudFront OAC
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "status_lists" {
  bucket = aws_s3_bucket.status_lists.id

  block_public_acls       = true
  block_public_policy     = false
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ------------------------------------------------------------------------------
# 4. Distribución CloudFront (CDN) para Distribución Global de Confianza
# ------------------------------------------------------------------------------
resource "aws_cloudfront_distribution" "cdn" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "CDN de alta disponibilidad para Trust Bundles y Listas de Revocación de Gravital ID"
  default_root_object = ""
  price_class         = "PriceClass_100"

  origin {
    domain_name              = aws_s3_bucket.trust_bundles.bucket_regional_domain_name
    origin_id                = "S3-TrustBundles"
    origin_access_control_id = aws_cloudfront_origin_access_control.oac.id
  }

  origin {
    domain_name              = aws_s3_bucket.status_lists.bucket_regional_domain_name
    origin_id                = "S3-StatusLists"
    origin_access_control_id = aws_cloudfront_origin_access_control.oac.id
  }

  default_cache_behavior {
    target_origin_id       = "S3-TrustBundles"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    min_ttl     = 0
    default_ttl = 300   # 5 minutos
    max_ttl     = 86400 # 24 horas
    compress    = true
  }

  ordered_cache_behavior {
    path_pattern           = "/status/*"
    target_origin_id       = "S3-StatusLists"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    min_ttl     = 0
    default_ttl = 60    # 1 minuto para frescura de listas de estado
    max_ttl     = 3600  # 1 hora
    compress    = true
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  tags = {
    Name        = "gravital-id-${var.environment}-cdn"
    Environment = var.environment
  }
}
