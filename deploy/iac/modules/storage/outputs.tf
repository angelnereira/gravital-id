output "trust_bundles_bucket_name" {
  description = "Nombre del bucket S3 para Trust Bundles"
  value       = aws_s3_bucket.trust_bundles.bucket
}

output "trust_bundles_bucket_arn" {
  description = "ARN del bucket S3 para Trust Bundles"
  value       = aws_s3_bucket.trust_bundles.arn
}

output "status_lists_bucket_name" {
  description = "Nombre del bucket S3 para Listas de Revocación"
  value       = aws_s3_bucket.status_lists.bucket
}

output "status_lists_bucket_arn" {
  description = "ARN del bucket S3 para Listas de Revocación"
  value       = aws_s3_bucket.status_lists.arn
}

output "cdn_domain_name" {
  description = "Nombre de dominio público de la distribución CDN CloudFront"
  value       = aws_cloudfront_distribution.cdn.domain_name
}

output "cdn_hosted_zone_id" {
  description = "Hosted Zone ID de CloudFront para registros DNS de tipo Alias"
  value       = aws_cloudfront_distribution.cdn.hosted_zone_id
}
