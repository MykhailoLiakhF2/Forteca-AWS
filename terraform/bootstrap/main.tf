# ============================================================
# S3 BUCKET — зберігає Terraform state файли
# ============================================================

resource "aws_s3_bucket" "terraform_state" {
  bucket = var.state_bucket_name

  # Захист від випадкового видалення через terraform destroy
  lifecycle {
    prevent_destroy = true
  }

  tags = var.tags
}

# ------------------------------------------------------------
# Versioning — зберігає історію змін state файлу
# ------------------------------------------------------------
resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  versioning_configuration {
    status = "Enabled"
  }
}

# ------------------------------------------------------------
# Encryption — шифрує state файл в S3
# ------------------------------------------------------------
resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# ------------------------------------------------------------
# Block public access — S3 bucket ніколи не буде публічним
# ------------------------------------------------------------
resource "aws_s3_bucket_public_access_block" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# ============================================================
# DYNAMODB TABLE — lock механізм для state файлу
# ============================================================

resource "aws_dynamodb_table" "terraform_lock" {
  name         = var.lock_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  tags = var.tags
}
