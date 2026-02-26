# NHOM 1: CAU HINH HE THONG (SYSTEM CONFIGURATION)

# --- CIS 2.7 & 2.8: Password Policy ---
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
  hard_expiry                    = false
}

# --- CIS 2.16: Support Role ---
data "aws_caller_identity" "current" {}

resource "aws_iam_role" "cis_support_role" {
  name        = "CIS_Support_Role"
  description = "Role for AWS Support access (CIS 2.16)"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "support_attach" {
  role       = aws_iam_role.cis_support_role.name
  policy_arn = "arn:aws:iam::aws:policy/AWSSupportAccess"
}

# --- CIS 2.19: Access Analyzer ---
resource "aws_accessanalyzer_analyzer" "account_analyzer" {
  analyzer_name = "CIS-Account-Analyzer-Terraform"
  type          = "ACCOUNT"
}

# --- CIS 2.17: Empty IAM Role for EC2 ---
resource "aws_iam_role" "cis_empty_instance_role" {
  name        = "CIS_Empty_Instance_Role"
  description = "Empty role for EC2 instances to satisfy CIS 2.17"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_instance_profile" "cis_empty_instance_profile" {
  name = "CIS_Empty_Instance_Profile"
  role = aws_iam_role.cis_empty_instance_role.name
}

# --- [CIS 2.9] Force MFA Policy ---
resource "aws_iam_policy" "force_mfa_policy" {
  name        = "Force_MFA_Policy"
  description = "Policy to force MFA (CIS 2.9)"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowViewAccountInfo"
        Effect   = "Allow"
        Action   = ["iam:ListVirtualMFADevices", "iam:ListUsers"]
        Resource = "*"
      },
      {
        Sid      = "AllowManageOwnVirtualMFADevice"
        Effect   = "Allow"
        Action   = ["iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice", "iam:ResyncMFADevice"]
        Resource = "arn:aws:iam::*:mfa/$${aws:username}"
      },
      {
        Sid      = "AllowManageOwnUserMFA"
        Effect   = "Allow"
        Action   = ["iam:DeactivateMFADevice", "iam:EnableMFADevice", "iam:ListMFADevices", "iam:ResyncMFADevice"]
        Resource = "arn:aws:iam::*:user/$${aws:username}"
      },
      {
        Sid    = "DenyAllExceptMFA"
        Effect = "Deny"
        NotAction = [
          "iam:CreateVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:ListMFADevices",
          "iam:ListUsers",
          "iam:ListVirtualMFADevices",
          "iam:ResyncMFADevice",
          "iam:ChangePassword",
          "iam:GetUser"
        ]
        Resource = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })
}

# ==============================================================================
# SECTION 3: STORAGE BASELINE (S3 PROTECTION)
# ==============================================================================

# --- [CIS 3.1.4] S3 Account Public Access Block ---
# Cấu hình này sẽ chặn truy cập công khai cho TOÀN BỘ Bucket trong Account.
# Giúp rút gọn logic "remediate_s3_block_public" trong Python.
resource "aws_s3_account_public_access_block" "main" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# --- [CIS 3.1.1] S3 SSL Policy Template ---
# Định nghĩa sẵn chính sách "Bắt buộc HTTPS" để Python script có thể tham chiếu.
data "aws_iam_policy_document" "s3_enforce_https" {
  statement {
    sid       = "AllowSSLRequestsOnly"
    effect    = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [
      "arn:aws:s3:::*",
      "arn:aws:s3:::*/*"
    ]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}