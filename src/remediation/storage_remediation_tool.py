import boto3
import sys
import os
import time
import json
import subprocess
from botocore.exceptions import ClientError

# Cau hinh mac dinh
TARGET_REGION = 'ap-southeast-1'
TERRAFORM_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../infrastructure/iam_baseline")

# --- UTILS ---
def get_aws_profiles():
    try:
        session = boto3.Session()
        return session.available_profiles if session.available_profiles else []
    except: return []

def select_profile(profiles):
    while True:
        for idx, p in enumerate(profiles): print(f"  [{idx + 1}] {p}")
        add_idx = len(profiles) + 1
        print(f"  [{add_idx}] (+) Thêm Profile mới")
        p_choice = input("\nChọn Profile: ").strip()
        if p_choice.isdigit():
            choice = int(p_choice)
            if 1 <= choice <= len(profiles): return profiles[choice - 1]
            if choice == add_idx:
                subprocess.run(["aws", "configure", "--profile", input("Tên profile mới: ")], check=True)
                profiles = get_aws_profiles(); continue
        print("[!] Không hợp lệ.")

def print_cis_section(cis_id, title):
    print(f"\n>>> [{cis_id}] {title}\n" + "-" * 60)

# ==============================================================================
# PHẦN 1: HẠ TẦNG (TERRAFORM)
# ==============================================================================
def apply_infrastructure_baseline(profile):
    print(f"\n=== TRIỂN KHAI HẠ TẦNG (Profile: {profile}) ===")
    if not os.path.isdir(TERRAFORM_DIR): return print("[!] Thiếu thư mục Terraform.")
    if input("=> Triển khai Guardrails (3.1.4, Config Rules)? (y/n): ").lower() == 'y':
        try:
            subprocess.run("terraform init", shell=True, cwd=TERRAFORM_DIR, check=True, stdout=subprocess.DEVNULL)
            subprocess.run(f'terraform apply -var="aws_profile={profile}" -auto-approve', shell=True, cwd=TERRAFORM_DIR, check=True)
            print("[OK] Đã thiết lập hạ tầng.")
        except: print("[!] Lỗi Terraform.")

# ==============================================================================
# PHẦN 2: KHẮC PHỤC (PYTHON)
# ==============================================================================

def remediate_cis_3_1_1_s3_https(session):
    """[CIS 3.1.1] Enforce HTTPS only - Đã tối ưu hóa diện tích code"""
    print_cis_section("CIS 3.1.1", "S3 ENFORCE HTTPS")
    s3 = session.client('s3')
    
    for b in s3.list_buckets()['Buckets']:
        name = b['Name']
        try:
            policy_res = s3.get_bucket_policy(Bucket=name)
            policy = json.loads(policy_res['Policy'])
            if any(s.get('Effect') == 'Deny' and 'aws:SecureTransport' in str(s.get('Condition')) for s in policy.get('Statement', [])):
                print(f"  [PASS] {name}"); continue
        except ClientError:
            policy = {"Version": "2012-10-17", "Statement": []}

        if input(f"  [FAIL] {name} thiếu chính sách HTTPS. Sửa ngay? (y/n): ").lower() == 'y':
            policy['Statement'].append({
                "Sid": "AllowSSLRequestsOnly", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
                "Resource": [f"arn:aws:s3:::{name}", f"arn:aws:s3:::{name}/*"],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}}
            })
            s3.put_bucket_policy(Bucket=name, Policy=json.dumps(policy))
            print(f"  [FIXED] {name}")

def remediate_rds_compliance(session):
    """CIS 3.2.x - RDS Safe Fix"""
    print_cis_section("CIS 3.2.x", "RDS COMPLIANCE")
    rds = session.client('rds', region_name=TARGET_REGION)
    for db in rds.describe_db_instances()['DBInstances']:
        name = db['DBInstanceIdentifier']
        for key, val, msg in [('AutoMinorVersionUpgrade', True, 'Auto Upgrade'), ('PubliclyAccessible', False, 'Private Access')]:
            if db.get(key) != val and input(f"  [FAIL] {name} ({msg}). Lên lịch sửa? (y/n): ").lower() == 'y':
                rds.modify_db_instance(DBInstanceIdentifier=name, **{key: val}, ApplyImmediately=False)
                print(f"  [SCHEDULED] {name}")

def remediate_efs_encryption(session):
    """CIS 3.3.1 - EFS Encryption"""
    print_cis_section("CIS 3.3.1", "EFS ENCRYPTION")
    efs = session.client('efs', region_name=TARGET_REGION)
    for fs in efs.describe_file_systems()['FileSystems']:
        if not fs.get('Encrypted') and input(f"  [FAIL] EFS {fs['FileSystemId']} chưa mã hóa. Tạo mới? (y/n): ").lower() == 'y':
            efs.create_file_system(CreationToken=f"fix-{int(time.time())}", Encrypted=True)
            print("  [CREATED] Đã tạo EFS mã hóa mới.")

def main():
    print("\n--- AWS STORAGE REMEDIATION TOOL (CIS SECTION 3) ---")
    profiles = get_aws_profiles()
    if not profiles: return print("[!] Không tìm thấy Profile.")
    profile = select_profile(profiles)
    
    while True:
        print(f"\n[Profile: {profile}]\n  1. Terraform (Hạ tầng/Giám sát)\n  2. Python (Khắc phục trực tiếp)\n  3. Chạy tất cả\n  0. Thoát")
        ans = input("Chọn: ").strip()
        if ans == '1': apply_infrastructure_baseline(profile)
        elif ans == '2':
            s = boto3.Session(profile_name=profile, region_name=TARGET_REGION)
            remediate_cis_3_1_1_s3_https(s)
            remediate_rds_compliance(s)
            remediate_efs_encryption(s)
        elif ans == '3':
            apply_infrastructure_baseline(profile)
            s = boto3.Session(profile_name=profile, region_name=TARGET_REGION)
            remediate_cis_3_1_1_s3_https(s); remediate_rds_compliance(s); remediate_efs_encryption(s)
        elif ans == '0': break

if __name__ == "__main__":
    main()