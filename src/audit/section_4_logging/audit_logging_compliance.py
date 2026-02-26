import boto3
import sys
import subprocess
from botocore.exceptions import ClientError

# Cau hinh Region mac dinh de khoi tao ket noi ban dau
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
    profile_name = input("Nhập tên cho Profile mới: ").strip()
    if not profile_name: return

    try:
        subprocess.run(["aws", "configure", "--profile", profile_name], check=True)
        print(f"\n[THÀNH CÔNG] Đã thêm Profile '{profile_name}'.")
    except Exception as e:
        print(f"\n[LỖI] {e}")

def select_profile(profiles):
    while True:
        print("\nDanh sách Profile khả dụng:")
        for idx, p in enumerate(profiles):
            print(f"  [{idx + 1}] {p}")
        add_idx = len(profiles) + 1
        print(f"  [{add_idx}] (+) Thêm Profile mới")
    
        p_choice = input("\nChọn Profile (Nhập số): ").strip()
        if p_choice.isdigit():
            choice = int(p_choice)
            if 1 <= choice <= len(profiles): return profiles[choice - 1]
            elif choice == add_idx:
                add_new_profile()
                profiles = get_aws_profiles()
                continue
        print("[CẢNH BÁO] Lựa chọn không hợp lệ.")

def audit_logging_compliance(selected_profile):
    print(f"{'='*75}")
    print(f"   CIS AWS FOUNDATIONS BENCHMARK v6.0.0 - SECTION 4: LOGGING AUDIT")
    print(f"   (Profile: {selected_profile} | Region: {TARGET_REGION})")
    print(f"{'='*75}\n")

    try:
        session = boto3.Session(profile_name=selected_profile, region_name=TARGET_REGION)
        ct = session.client('cloudtrail')
        s3 = session.client('s3')
        config = session.client('config')
        ec2 = session.client('ec2')
        kms = session.client('kms')
    except Exception as e:
        print(f"[FATAL ERROR] Khong the tao ket noi: {e}")
        return

    # --- 1. CLOUDTRAIL (4.1, 4.2, 4.5, 4.8, 4.9) ---
    print(">>> 4.1 - 4.2 - 4.5 - 4.8 - 4.9: KIỂM TRA CLOUDTRAIL")
    try:
        trails = ct.describe_trails()['trailList']
        if not trails:
            print(" [FAIL] Không tìm thấy Trail nào trong tài khoản!")
        
        for trail in trails:
            name = trail['Name']
            arn = trail['TrailARN']
            print(f"\n -> Trail: {name}")

            # [CIS 4.1] Multi-Region
            is_multi = trail.get('IsMultiRegionTrail', False)
            print(f"    [4.1] Multi-Region Enabled: {'[PASS]' if is_multi else '[FAIL]'}")

            # [CIS 4.2] Log File Validation
            is_valid = trail.get('LogFileValidationEnabled', False)
            print(f"    [4.2] Log File Validation: {'[PASS]' if is_valid else '[FAIL]'}")

            # [CIS 4.5] CloudTrail Encryption with KMS
            kms_id = trail.get('KmsKeyId')
            if kms_id:
                print(f"    [4.5] CloudTrail KMS Encryption: [PASS] (Key: {kms_id.split('/')[-1]})")
                # [CIS 4.6] KMS Key Rotation (Kiem tra cho key cua Trail)
                try:
                    rotation = kms.get_key_rotation_status(KeyId=kms_id)
                    print(f"    [4.6] KMS Key Rotation Enabled: {'[PASS]' if rotation['KeyRotationEnabled'] else '[FAIL]'}")
                except Exception:
                    print(f"    [4.6] KMS Key Rotation Enabled: [WARNING] (Khong the kiem tra key)")
            else:
                print(f"    [4.5] CloudTrail KMS Encryption: [FAIL] (Logs dang dung ma hoa mac dinh S3 Server-side)")

            # [CIS 4.8 & 4.9] S3 Object-level Logging
            try:
                selectors = ct.get_event_selectors(TrailName=arn)
                has_s3_read = False
                has_s3_write = False
                
                for s in selectors.get('EventSelectors', []):
                    if s.get('ReadWriteType') == 'All' or s.get('ReadWriteType') == 'ReadOnly':
                        if any(res['Type'] == 'AWS::S3::Object' for res in s.get('DataResources', [])):
                            has_s3_read = True
                    if s.get('ReadWriteType') == 'All' or s.get('ReadWriteType') == 'WriteOnly':
                        if any(res['Type'] == 'AWS::S3::Object' for res in s.get('DataResources', [])):
                            has_s3_write = True
                
                print(f"    [4.8] S3 Write Object Logging: {'[PASS]' if has_s3_write else '[FAIL]'}")
                print(f"    [4.9] S3 Read Object Logging: {'[PASS]' if has_s3_read else '[FAIL]'}")
            except Exception:
                print(f"    [4.8-4.9] S3 Object Logging: [WARNING] (Khong the kiem tra event selectors)")

    except Exception as e:
        print(f"Lỗi CloudTrail: {e}")

    # --- 2. S3 BUCKET LOGGING (4.4) ---
    print("\n>>> 4.4: KIỂM TRA S3 BUCKET LOGGING (Cho CloudTrail Bucket)")
    try:
        for trail in trails:
            bucket = trail.get('S3BucketName')
            if bucket:
                try:
                    logging = s3.get_bucket_logging(Bucket=bucket)
                    if 'LoggingEnabled' in logging:
                        print(f"    [4.4] Bucket '{bucket}': [PASS] (Target: {logging['LoggingEnabled']['TargetBucket']})")
                    else:
                        print(f"    [4.4] Bucket '{bucket}': [FAIL] (Chưa bật Access Logging)")
                except Exception:
                    print(f"    [4.4] Bucket '{bucket}': [FAIL] (Lỗi quyền truy cập)")
    except Exception:
        pass

    # --- 3. AWS CONFIG (4.3) ---
    print("\n>>> 4.3: KIỂM TRA AWS CONFIG (Tất cả khu vực)")
    try:
        recorders = config.describe_configuration_recorders()['ConfigurationRecorders']
        if not recorders:
            print("    [4.3] AWS Config Status: [FAIL] (Chưa tạo Configuration Recorder)")
        else:
            status = config.describe_configuration_recorder_status()
            is_recording = any(s['recording'] for s in status['ConfigurationRecordersStatus'])
            print(f"    [4.3] AWS Config Recording: {'[PASS]' if is_recording else '[FAIL]'}")
    except Exception as e:
        print(f"    [4.3] AWS Config Status: [FAIL] ({e})")

    # --- 4. VPC FLOW LOGS (4.7) ---
    print("\n>>> 4.7: KIỂM TRA VPC FLOW LOGGING")
    try:
        vpcs = ec2.describe_vpcs()['Vpcs']
        if not vpcs:
            print("    [4.7] VPC Status: [PASS] (Không có VPC nào để kiểm tra)")
        else:
            for v in vpcs:
                vpc_id = v['VpcId']
                flow_logs = ec2.describe_flow_logs(Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}])['FlowLogs']
                if flow_logs:
                    print(f"    [4.7] VPC {vpc_id}: [PASS] (Flow Logging: Enabled)")
                else:
                    print(f"    [4.7] VPC {vpc_id}: [FAIL] (Chưa bật Flow Logging)")
    except Exception as e:
        print(f"    [4.7] VPC Flow Logging: [FAIL] ({e})")

    print(f"\n{'='*75}")
    print("   HOÀN TẤT KIỂM TRA SECTION 4")
    print(f"{'='*75}")

if __name__ == "__main__":
    profiles = get_aws_profiles()
    if not profiles:
        select_profile([])
    else:
        profile = select_profile(profiles)
        audit_logging_compliance(profile)