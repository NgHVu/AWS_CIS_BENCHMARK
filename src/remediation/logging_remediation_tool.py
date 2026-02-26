import boto3
import sys
import os
import time
import subprocess
from botocore.exceptions import ClientError

# Cau hinh Region mac dinh
TARGET_REGION = 'ap-southeast-1'

# Duong dan den thu muc Terraform
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TERRAFORM_DIR = os.path.join(BASE_DIR, "../../infrastructure/iam_baseline")

# --- CAC HAM HO TRO (UTILS) ---
def get_aws_profiles():
    try:
        session = boto3.Session()
        profiles = session.available_profiles
        return profiles if profiles else []
    except Exception:
        return []

def add_new_profile():
    print("\n--- THÊM PROFILE MỚI ---")
    print(f"Bạn sẽ cần nhập: Access Key, Secret Key, Region (BẮT BUỘC: {TARGET_REGION})")
    
    profile_name = input("Nhập tên cho Profile mới (ví dụ: dev-env): ").strip()
    if not profile_name: return

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
        
        add_idx = len(profiles) + 1
        print(f"  [{add_idx}] (+) Thêm Profile mới")
    
        p_choice = input("\nChọn Profile (Nhập số): ").strip()
        if p_choice.isdigit():
            choice = int(p_choice)
            if 1 <= choice <= len(profiles):
                return profiles[choice - 1]
            elif choice == add_idx:
                add_new_profile()
                profiles = get_aws_profiles()
                continue
        print("[CẢNH BÁO] Lựa chọn không hợp lệ.")

def print_header(text):
    print("\n" + "=" * 70)
    print(f" {text}")
    print("=" * 70)

def print_cis_section(cis_id, title):
    print(f"\n>>> [{cis_id}] {title}")
    print("-" * 60)

# ==============================================================================
# PHẦN 1: CHIẾN LƯỢC GIÁM SÁT (MONITORING STRATEGY - TERRAFORM)
# ==============================================================================
def apply_monitoring_guardrails(profile):
    print_header(f"CHIẾN LƯỢC GIÁM SÁT (TERRAFORM) - Profile: {profile}")
    print("Mục tiêu: Triển khai hạ tầng Logging & Monitoring nâng cao [Section 4]")
    print("-" * 70)
    print("  - [CIS 4.5] Tạo KMS Key để mã hóa Log")
    print("  - [CIS 4.7] Tạo CloudWatch Log Groups & IAM Roles cho Flow Logs")
    print("  - [CIS 4.3] Cấu hình AWS Config Recorder & Delivery Channel")
    print("-" * 70)
    
    if not os.path.isdir(TERRAFORM_DIR):
        print(f"\n[LỖI] Không tìm thấy thư mục Terraform tại: {TERRAFORM_DIR}")
        return

    if input("\n=> Bạn có muốn triển khai hệ thống hạ tầng này không? (y/n): ").lower() != 'y':
        return

    try:
        print(f"\n[INFO] Đang khởi tạo Terraform...")
        subprocess.run("terraform init", shell=True, cwd=TERRAFORM_DIR, check=True, stdout=subprocess.DEVNULL)
        
        print(f"[INFO] Đang áp dụng cấu hình...")
        cmd = f'terraform apply -var="aws_profile={profile}" -auto-approve'
        subprocess.run(cmd, shell=True, cwd=TERRAFORM_DIR, check=True)
        print(f"\n[THÀNH CÔNG] Hạ tầng Logging đã được kích hoạt.")
    except subprocess.CalledProcessError:
        print(f"\n[LỖI] Terraform thất bại.")

# ==============================================================================
# PHẦN 2: CHIẾN LƯỢC KHẮC PHỤC TRỰC TIẾP (ACTIVE REMEDIATION - PYTHON)
# ==============================================================================

def get_resource_from_tags(client, service_type, tag_key, tag_value):
    """Tìm tài nguyên dựa trên Tags (thường do Terraform gắn)"""
    try:
        if service_type == 'kms':
            keys = client.list_keys()['Keys']
            for k in keys:
                tags = client.list_resource_tags(KeyId=k['KeyId'])['Tags']
                if any(t['TagKey'] == tag_key and t['TagValue'] == tag_value for t in tags):
                    return k['KeyId']
        elif service_type == 's3':
            buckets = client.list_buckets()['Buckets']
            for b in buckets:
                try:
                    tags = client.get_bucket_tagging(Bucket=b['Name'])['TagSet']
                    if any(t['Key'] == tag_key and t['Value'] == tag_value for t in tags):
                        return b['Name']
                except: continue
        return None
    except: return None

def remediate_cloudtrail_advanced(session):
    """[CIS 4.1, 4.2, 4.5, 4.8, 4.9] Toàn diện CloudTrail"""
    print_cis_section("CIS 4.1, 4.2, 4.5, 4.8, 4.9", "CLOUDTRAIL ADVANCED CONFIGURATION")
    ct = session.client('cloudtrail', region_name=TARGET_REGION)
    kms = session.client('kms', region_name=TARGET_REGION)
    s3 = session.client('s3', region_name=TARGET_REGION)
    
    # 1. Tìm tài nguyên từ Terraform (Giả định Terraform đã gắn tag chuẩn)
    # Nếu không tìm thấy bằng tag, script sẽ fallback tìm theo prefix tên
    bucket_name = None
    buckets = s3.list_buckets()['Buckets']
    for b in buckets:
        if "aws-cloudtrail-logs-" in b['Name']:
            bucket_name = b['Name']
            break

    kms_key_id = None
    keys = kms.list_keys()['Keys']
    for k in keys:
        try:
            desc = kms.describe_key(KeyId=k['KeyId'])['KeyMetadata']
            if "CloudTrail log encryption" in desc.get('Description', ''):
                kms_key_id = k['KeyId']
                break
        except: continue

    if not bucket_name:
        print("   [LỖI] Không tìm thấy S3 Bucket cho CloudTrail. Vui lòng chạy Option 1.")
        return

    trail_name = "CIS-Security-Audit-Trail"
    print(f"   [ACTION] Cấu hình Trail: {trail_name}")

    trail_params = {
        'Name': trail_name,
        'S3BucketName': bucket_name,
        'IncludeGlobalServiceEvents': True,
        'IsMultiRegionTrail': True,
        'EnableLogFileValidation': True # CIS 4.2
    }
    
    if kms_key_id:
        trail_params['KmsKeyId'] = kms_key_id # CIS 4.5
        print(f"     -> Tích hợp KMS Encryption: [PASS]")

    try:
        # Create or Update
        try:
            ct.create_trail(**trail_params)
        except ct.exceptions.TrailAlreadyExistsException:
            ct.update_trail(**trail_params)
        
        # Bật Logging
        ct.start_logging(Name=trail_name)
        
        # [CIS 4.8 & 4.9] Bật S3 Data Events (Read/Write)
        ct.put_event_selectors(
            TrailName=trail_name,
            EventSelectors=[{
                'ReadWriteType': 'All',
                'IncludeManagementEvents': True,
                'DataResources': [{'Type': 'AWS::S3::Object', 'Values': ['arn:aws:s3']}]
            }]
        )
        print("     -> Bật S3 Data Events (Read/Write): [FIXED]")
        print("   [SUCCESS] Hoàn tất cấu hình CloudTrail nâng cao.")
        
    except Exception as e:
        print(f"   [LỖI] {e}")

def remediate_kms_rotation(session):
    """[CIS 4.6] Enable KMS Rotation"""
    print_cis_section("CIS 4.6", "KMS KEY ROTATION")
    kms = session.client('kms', region_name=TARGET_REGION)
    try:
        keys = kms.list_keys()['Keys']
        for k in keys:
            kid = k['KeyId']
            meta = kms.describe_key(KeyId=kid)['KeyMetadata']
            if meta['KeyManager'] == 'CUSTOMER' and meta['Enabled']:
                status = kms.get_key_rotation_status(KeyId=kid)
                if not status['KeyRotationEnabled']:
                    print(f"   [VI PHẠM] Key {kid} chưa bật xoay vòng.")
                    if input(f"     => Bật tự động xoay vòng cho key này? (y/n): ").lower() == 'y':
                        kms.enable_key_rotation(KeyId=kid)
                        print(f"     [FIXED] Đã bật xoay vòng cho {kid}.")
    except Exception as e:
        print(f"   [LỖI] {e}")

def remediate_vpc_flow_logs(session):
    """[CIS 4.7] Enable VPC Flow Logs"""
    print_cis_section("CIS 4.7", "VPC FLOW LOGGING")
    ec2 = session.client('ec2', region_name=TARGET_REGION)
    logs = session.client('logs', region_name=TARGET_REGION)
    iam = session.client('iam')
    
    try:
        # 1. Tìm IAM Role & Log Group từ Terraform
        role_arn = None
        try:
            role_arn = iam.get_role(RoleName='CIS_VPC_Flow_Log_Role')['Role']['Arn']
        except: pass

        log_group_name = "/aws/vpc/flow-logs"
        
        vpcs = ec2.describe_vpcs()['Vpcs']
        for vpc in vpcs:
            vpc_id = vpc['VpcId']
            existing = ec2.describe_flow_logs(Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}])['FlowLogs']
            
            if not existing:
                print(f"   [VI PHẠM] VPC {vpc_id} chưa bật Flow Logs.")
                if role_arn and input(f"     => Kích hoạt Flow Logs cho {vpc_id}? (y/n): ").lower() == 'y':
                    ec2.create_flow_logs(
                        ResourceIds=[vpc_id],
                        ResourceType='VPC',
                        TrafficType='ALL',
                        LogDestinationType='cloud-watch-logs',
                        LogGroupName=log_group_name,
                        DeliverLogsPermissionArn=role_arn
                    )
                    print(f"     [FIXED] Đã kích hoạt Flow Logs.")
                else:
                    print("     [SKIP] Thiếu IAM Role hoặc bị từ chối.")
            else:
                print(f"   [PASS] VPC {vpc_id} đã có Flow Logs.")
    except Exception as e:
        print(f"   [LỖI] {e}")

def remediate_aws_config(session):
    """[CIS 4.3] AWS Config Recording"""
    print_cis_section("CIS 4.3", "AWS CONFIG RECORDING")
    config = session.client('config', region_name=TARGET_REGION)
    try:
        recorders = config.describe_configuration_recorders()['ConfigurationRecorders']
        if recorders:
            name = recorders[0]['name']
            status = config.describe_configuration_recorder_status(ConfigurationRecorderNames=[name])
            if not status['ConfigurationRecordersStatus'][0]['recording']:
                print(f"   [VI PHẠM] Config Recorder '{name}' đang tắt.")
                if input("     => Bật Recorder ngay? (y/n): ").lower() == 'y':
                    config.start_configuration_recorder(ConfigurationRecorderName=name)
                    print("     [FIXED] Đã bắt đầu ghi cấu hình.")
            else:
                print(f"   [PASS] AWS Config đang hoạt động.")
        else:
            print("   [INFO] Chưa có Recorder. Vui lòng chạy Terraform (Option 1).")
    except Exception as e:
        print(f"   [LỖI] {e}")

def run_python_remediation(profile):
    print_header(f"KHẮC PHỤC TRỰC TIẾP (PYTHON) - Profile: {profile}")
    try:
        session = boto3.Session(profile_name=profile, region_name=TARGET_REGION)
        remediate_aws_config(session)        # 4.3
        remediate_kms_rotation(session)      # 4.6
        remediate_cloudtrail_advanced(session) # 4.1, 4.2, 4.5, 4.8, 4.9
        remediate_vpc_flow_logs(session)     # 4.7
        print("\n[SUCCESS] Hoàn tất quá trình khắc phục Logging & Monitoring.")
    except Exception as e:
        print(f"[FATAL] {e}")

# --- MAIN MENU ---
def main():
    print("\n--- AWS LOGGING REMEDIATION TOOL (CIS v6.0.0) ---")
    profiles = get_aws_profiles()
    if not profiles:
        select_profile([])
        return
    selected_profile = select_profile(profiles)
    while True:
        print(f"\nProfile: {selected_profile} (Region: {TARGET_REGION})")
        print("  [1] CHIẾN LƯỢC HẠ TẦNG (Terraform):")
        print("      => Cấu hình KMS, Config, Log Groups & IAM Roles")
        print("  [2] CHIẾN LƯỢC KHẮC PHỤC (Python):")
        print("      => [4.1-4.9] Thiết lập CloudTrail & Flow Logs")
        print("  [3] CHẠY TOÀN BỘ (Full Pipeline)")
        print("  [0] Thoát")
        ans = input("\nLựa chọn: ").strip()
        if ans == '1': apply_monitoring_guardrails(selected_profile)
        elif ans == '2': run_python_remediation(selected_profile)
        elif ans == '3':
            apply_monitoring_guardrails(selected_profile)
            run_python_remediation(selected_profile)
        elif ans == '0': sys.exit(0)

if __name__ == "__main__":
    main()