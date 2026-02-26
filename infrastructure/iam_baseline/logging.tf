# SECTION 4: LOGGING & MONITORING BASELINE

# --- [CIS 4.5 & 4.6] KMS Key for Encryption & Rotation ---
resource "aws_kms_key" "cloudtrail_key" {
  description             = "KMS Key for CloudTrail log encryption (CIS 4.5)"
  deletion_window_in_days = 7
  enable_key_rotation     = true # (CIS 4.6) - Tu dong xoay vong khoa hàng nam

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudTrail to encrypt logs"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "kms:GenerateDataKey*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudTrail to describe key"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "kms:DescribeKey"
        Resource = "*"
      }
    ]
  })
}

# --- [CIS 4.2, 4.5, 4.8, 4.9] CloudTrail Configuration ---
resource "aws_cloudtrail" "main" {
  name                          = "CIS-Main-CloudTrail"
  s3_bucket_name                = aws_s3_bucket.logging_bucket.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true # (CIS 4.2) - Xac thuc tep nhat ky
  kms_key_id                    = aws_kms_key.cloudtrail_key.arn # (CIS 4.5) - Ma hoa voi KMS

  # [CIS 4.8 & 4.9] - Ghi nhat ky cap doi tuong S3 (Data Events)
  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3"] # Theo doi tat ca bucket trong tai khoan
    }
  }

  depends_on = [aws_s3_bucket_policy.logging_bucket_policy]
}

# --- [CIS 4.7] VPC Flow Logs ---
# Gia su ban da co VPC id, neu chua co co the dung vpc mac dinh
data "aws_vpcs" "all" {}

resource "aws_flow_log" "main" {
  for_each             = toset(data.aws_vpcs.all.ids)
  iam_role_arn         = aws_iam_role.flow_log_role.arn
  log_destination      = aws_cloudwatch_log_group.flow_log_group.arn
  traffic_type         = "ALL"
  vpc_id               = each.value
}

resource "aws_cloudwatch_log_group" "flow_log_group" {
  name              = "/aws/vpc/flow-logs"
  retention_in_days = 90
}

# --- IAM Role for Flow Logs ---
resource "aws_iam_role" "flow_log_role" {
  name = "CIS_VPC_Flow_Log_Role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "flow_log_policy" {
  name = "CIS_VPC_Flow_Log_Policy"
  role = aws_iam_role.flow_log_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Effect   = "Allow"
      Resource = "*"
    }]
  })
}

# --- S3 Bucket for Logging (Phuc vu cho CloudTrail) ---
resource "aws_s3_bucket" "logging_bucket" {
  bucket_prefix = "aws-cloudtrail-logs-"
  force_destroy = true
}

resource "aws_s3_bucket_policy" "logging_bucket_policy" {
  bucket = aws_s3_bucket.logging_bucket.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.logging_bucket.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.logging_bucket.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      }
    ]
  })
}