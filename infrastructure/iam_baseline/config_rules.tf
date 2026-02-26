# NHOM 3: GIAM SAT LIEN TUC (AWS CONFIG RULES)

# --- 1. CẤU HÌNH AWS CONFIG ---

resource "aws_config_configuration_recorder" "main" {
  name     = "CIS-Config-Recorder"
  role_arn = aws_iam_role.config_role.arn
  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
  depends_on = [aws_iam_role_policy_attachment.config_policy_attach]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.main]
}

resource "aws_s3_bucket" "config_bucket" {
  bucket_prefix = "config-bucket-cis-"
  force_destroy = true 
}

resource "aws_s3_bucket_policy" "config_policy" {
  bucket = aws_s3_bucket.config_bucket.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSConfigBucketPermissionsCheck"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.config_bucket.arn
      },
      {
        Sid       = "AWSConfigBucketDelivery"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.config_bucket.arn}/AWSLogs/*/Config/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

resource "aws_config_delivery_channel" "main" {
  name           = "CIS-Delivery-Channel"
  s3_bucket_name = aws_s3_bucket.config_bucket.id
  depends_on     = [aws_s3_bucket_policy.config_policy]
}

resource "aws_iam_role" "config_role" {
  name = "CIS_Config_Role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "config.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config_policy_attach" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

# --- 2. CÁC RULE KIỂM TRA TỰ ĐỘNG ---

# QUAN TRỌNG: Tất cả Rule phải depends_on status để đảm bảo Recorder đã chạy.

# --- SECTION 2: IDENTITY & ACCESS MANAGEMENT ---

# [CIS 2.3] Root Access Key Check
resource "aws_config_config_rule" "root_access_key" {
  name = "iam-root-access-key-check"
  source {
    owner             = "AWS"
    source_identifier = "IAM_ROOT_ACCESS_KEY_CHECK"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

# [CIS 2.4] Root Account MFA Enabled
resource "aws_config_config_rule" "root_mfa_check" {
  name = "root-account-mfa-enabled"
  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED" 
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

# [CIS 2.11] Unused Credentials
resource "aws_config_config_rule" "unused_creds" {
  name = "iam-user-unused-credentials-check"
  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_UNUSED_CREDENTIALS_CHECK"
  }
  input_parameters = jsonencode({ maxCredentialUsageAge = "45" })
  depends_on = [aws_config_configuration_recorder_status.main]
}

# [CIS 2.13] Access Key Rotation
resource "aws_config_config_rule" "key_rotation" {
  name = "access-keys-rotated"
  source {
    owner             = "AWS"
    source_identifier = "ACCESS_KEYS_ROTATED"
  }
  input_parameters = jsonencode({ maxAccessKeyAge = "90" })
  depends_on = [aws_config_configuration_recorder_status.main]
}

# [CIS 2.17] EC2 Instance Profile Attached
resource "aws_config_config_rule" "ec2_instance_profile_attached" {
  name = "ec2-instance-profile-attached"
  source {
    owner             = "AWS"
    source_identifier = "EC2_INSTANCE_PROFILE_ATTACHED"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

# [CIS 2.18] Expired SSL/TLS
resource "aws_config_config_rule" "acm_certificate_expiration" {
  name = "acm-certificate-expiration-check"
  source {
    owner             = "AWS"
    source_identifier = "ACM_CERTIFICATE_EXPIRATION_CHECK"
  }
  scope { compliance_resource_types = ["AWS::ACM::Certificate"] }
  depends_on = [aws_config_configuration_recorder_status.main]
}

# --- SECTION 3: STORAGE ---

# [CIS 3.1.1] S3 Bucket SSL Requests Only
resource "aws_config_config_rule" "s3_bucket_ssl_requests_only" {
  name = "s3-bucket-ssl-requests-only"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SSL_REQUESTS_ONLY"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

# [CIS 3.1.4] S3 Public Read Prohibited
resource "aws_config_config_rule" "s3_bucket_public_read_prohibited" {
  name = "s3-bucket-public-read-prohibited"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

# [CIS 3.2.1] RDS Storage Encrypted
resource "aws_config_config_rule" "rds_storage_encrypted" {
  name = "rds-storage-encrypted"
  source {
    owner             = "AWS"
    source_identifier = "RDS_STORAGE_ENCRYPTED"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

# [CIS 3.2.2] RDS Auto Minor Version Upgrade
resource "aws_config_config_rule" "rds_auto_minor_version_upgrade" {
  name = "rds-auto-minor-version-upgrade-check"
  source {
    owner             = "AWS"
    source_identifier = "RDS_AUTOMATIC_MINOR_VERSION_UPGRADE_ENABLED"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

# [CIS 3.2.3] RDS Public Access
resource "aws_config_config_rule" "rds_instance_public_access_check" {
  name = "rds-instance-public-access-check"
  source {
    owner             = "AWS"
    source_identifier = "RDS_INSTANCE_PUBLIC_ACCESS_CHECK"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

# [CIS 3.2.4] RDS Multi-AZ Support
resource "aws_config_config_rule" "rds_multi_az_support" {
  name = "rds-multi-az-support"
  source {
    owner             = "AWS"
    source_identifier = "RDS_MULTI_AZ_SUPPORT"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

# [CIS 3.3.1] EFS Encrypted Check
resource "aws_config_config_rule" "efs_encrypted_check" {
  name = "efs-encrypted-check"
  source {
    owner             = "AWS"
    source_identifier = "EFS_ENCRYPTED_CHECK"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

# --- SECTION 6: NETWORKING ---

# [CIS 6.1.1] EBS Encryption Default
resource "aws_config_config_rule" "ebs_encryption_by_default" {
  name = "cis-6-1-1-ebs-encryption-by-default"
  source {
    owner             = "AWS"
    source_identifier = "EC2_EBS_ENCRYPTION_BY_DEFAULT"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

# [CIS 6.x] Restricted Ports (SSH, RDP, CIFS)
resource "aws_config_config_rule" "restricted_common_ports" {
  name = "cis-6-restricted-common-ports"
  source {
    owner             = "AWS"
    source_identifier = "RESTRICTED_INCOMING_TRAFFIC"
  }
  input_parameters = jsonencode({
    blockedPort1 = "22"
    blockedPort2 = "3389"
    blockedPort3 = "445"
  })
  depends_on = [aws_config_configuration_recorder_status.main]
}

# [CIS 6.5] VPC Default SG Closed
resource "aws_config_config_rule" "vpc_default_sg_closed" {
  name = "cis-6-5-vpc-default-sg-closed"
  source {
    owner             = "AWS"
    source_identifier = "VPC_DEFAULT_SECURITY_GROUP_CLOSED"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

# [CIS 6.7] EC2 IMDSv2 Check
resource "aws_config_config_rule" "ec2_imdsv2_check" {
  name = "cis-6-7-ec2-imdsv2-check"
  source {
    owner             = "AWS"
    source_identifier = "EC2_IMDSV2_CHECK"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}