import boto3
import sys
import json
import subprocess
from botocore.exceptions import ClientError

# Cau hinh Region mac dinh
TARGET_REGION = 'ap-southeast-1'

def get_aws_profiles():
    """Lay danh sach profile tu file credentials"""
    try:
        session = boto3.Session()
        profiles = session.available_profiles
        return profiles if profiles else []
    except Exception:
        return []

def add_new_profile():
    """Goi lenh aws configure de them profile moi"""
    print("\n--- THÊM PROFILE MỚI ---")
    profile_name = input("Nhập tên cho Profile mới (ví dụ: dev-env): ").strip()
    if not profile_name:
        print("[LỖI] Tên Profile không được để trống.")
        return
    try:
        print(f"\n>> Đang chạy cấu hình cho profile '{profile_name}'...")
        subprocess.run(["aws", "configure", "--profile", profile_name], check=True)
        print(f"\n[THÀNH CÔNG] Đã thêm Profile '{profile_name}'.")
    except Exception as e:
        print(f"\n[LỖI] Không thể thêm profile: {e}")

def select_profile(profiles):
    while True:
        print("\nDanh sách Profile khả dụng:")
        for idx, p in enumerate(profiles):
            print(f"  [{idx + 1}] {p}")
        add_option_idx = len(profiles) + 1
        print(f"  [{add_option_idx}] (+) Thêm Profile mới")
        p_choice = input("\nChọn Profile muốn kiểm tra (Nhập số): ").strip()
        if p_choice.isdigit():
            choice = int(p_choice)
            if 1 <= choice <= len(profiles):
                return profiles[choice - 1]
            elif choice == add_option_idx:
                add_new_profile()
                profiles = get_aws_profiles()
                continue
        print("[CẢNH BÁO] Lựa chọn không hợp lệ.")

def check_s3_http_deny(s3_client, bucket_name):
    """CIS 3.1.1: Check if S3 Bucket Policy denies HTTP requests"""
    try:
        policy_res = s3_client.get_bucket_policy(Bucket=bucket_name)
        policy = json.loads(policy_res['Policy'])
        for statement in policy.get('Statement', []):
            if (statement.get('Effect') == 'Deny' and 
                'aws:SecureTransport' in str(statement.get('Condition', {}))):
                return True
        return False
    except ClientError:
        return False

def audit_storage_compliance(selected_profile):
    print(f"{'='*70}")
    print(f"   CIS AWS FOUNDATIONS BENCHMARK v6.0.0 - STORAGE AUDIT")
    print(f"   (Profile: {selected_profile} | Region: {TARGET_REGION})")
    print(f"{'='*70}\n")

    try:
        session = boto3.Session(profile_name=selected_profile, region_name=TARGET_REGION)
        s3 = session.client('s3') 
        rds = session.client('rds')
        efs = session.client('efs')
        macie = session.client('macie2') # CIS 3.1.3
    except Exception as e:
        print(f"[FATAL ERROR] Khong the tao ket noi: {e}")
        return

    # --- 1. S3 STORAGE ---
    print(">>> 1. KIỂM TRA S3 BUCKETS")
    try:
        buckets = s3.list_buckets()['Buckets']
        if not buckets:
            print(" (Không tìm thấy S3 Bucket nào)")
        
        for b in buckets:
            name = b['Name']
            print(f" -> Bucket: {name}")

            # [CIS 3.1.1] Enforce HTTPS (Deny HTTP)
            if check_s3_http_deny(s3, name):
                print("    [3.1.1] S3 Bucket Policy (HTTPS Only): [PASS]")
            else:
                print("    [3.1.1] S3 Bucket Policy (HTTPS Only): [FAIL] (Chưa có chính sách từ chối HTTP)")

            # [CIS 3.1.2] MFA Delete
            try:
                versioning = s3.get_bucket_versioning(Bucket=name)
                mfa_delete = versioning.get('MFADelete', 'Disabled')
                if mfa_delete == 'Enabled':
                    print("    [3.1.2] MFA Delete Enabled: [PASS]")
                else:
                    print("    [3.1.2] MFA Delete Enabled: [FAIL] (Yêu cầu tài khoản Root để bật)")
            except:
                print("    [3.1.2] MFA Delete Enabled: [WARNING] (Không thể kiểm tra)")

            # [CIS 3.1.4] Block Public Access
            try:
                pab = s3.get_public_access_block(Bucket=name)
                conf = pab['PublicAccessBlockConfiguration']
                if all(conf.values()):
                    print("    [3.1.4] Block Public Access: [PASS]")
                else:
                    print("    [3.1.4] Block Public Access: [FAIL] (Chưa bật đủ 4 tùy chọn chặn công khai)")
            except ClientError as e:
                print(f"    [3.1.4] Block Public Access: [FAIL] (Chưa cấu hình)")

    except Exception as e:
        print(f"Lỗi kiểm tra S3: {e}")

    # [CIS 3.1.3] Macie (Data Discovery) - Check Account Level
    print("\n>>> 1.3 KIỂM TRA PHÂN LOẠI DỮ LIỆU (MACIE)")
    try:
        macie_status = macie.get_macie_session()
        if macie_status.get('status') == 'PAUSED':
            print(" [3.1.3] Amazon Macie Status: [FAIL] (Đang bị tạm dừng)")
        else:
            print(f" [3.1.3] Amazon Macie Status: [PASS] ({macie_status.get('status')})")
    except ClientError:
        print(" [3.1.3] Amazon Macie Status: [FAIL] (Chưa kích hoạt Amazon Macie)")

    # --- 2. RDS DATABASE ---
    print("\n>>> 2. KIỂM TRA RDS INSTANCES")
    try:
        dbs = rds.describe_db_instances()['DBInstances']
        if not dbs:
            print(" (Không tìm thấy RDS Instance nào)")
        for db in dbs:
            name = db['DBInstanceIdentifier']
            print(f" -> DB: {name}")
            # CIS 3.2.1: Encryption
            print(f"    [3.2.1] Storage Encrypted: {'[PASS]' if db.get('StorageEncrypted') else '[FAIL]'}")
            # CIS 3.2.2: Auto Upgrade
            print(f"    [3.2.2] Auto Minor Upgrade: {'[PASS]' if db.get('AutoMinorVersionUpgrade') else '[FAIL]'}")
            # CIS 3.2.3: Public Access
            print(f"    [3.2.3] Not Publicly Accessible: {'[PASS]' if not db.get('PubliclyAccessible') else '[FAIL]'}")
            # CIS 3.2.4: Multi-AZ
            print(f"    [3.2.4] Multi-AZ Enabled: {'[PASS]' if db.get('MultiAZ') else '[WARN] (Tắt - Lab/Dev)'}")
    except Exception as e:
        print(f"Lỗi kiểm tra RDS: {e}")

    # --- 3. EFS FILE SYSTEMS ---
    print("\n>>> 3. KIỂM TRA EFS FILE SYSTEMS")
    try:
        filesystems = efs.describe_file_systems()['FileSystems']
        if not filesystems:
            print(" (Không tìm thấy EFS File System nào)")
        for fs in filesystems:
            fs_id = fs['FileSystemId']
            print(f" -> EFS: {fs_id}")
            print(f"    [3.3.1] Encrypted at Rest: {'[PASS]' if fs.get('Encrypted') else '[FAIL]'}")
    except Exception as e:
        print(f"Lỗi kiểm tra EFS: {e}")

    print(f"\n{'='*60}")
    print("   HOÀN TẤT KIỂM TRA STORAGE SECTION 3")
    print(f"{'='*60}")

if __name__ == "__main__":
    profiles = get_aws_profiles()
    if not profiles:
        print("Chưa tìm thấy Profile nào.")
        select_profile([])
    else:
        profile = select_profile(profiles)
        audit_storage_compliance(profile)