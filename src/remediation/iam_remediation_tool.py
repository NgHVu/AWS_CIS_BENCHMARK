import boto3
import subprocess
import sys
import os
import datetime
import json
from dateutil.tz import tzutc
from botocore.exceptions import ClientError

# Duong dan den thu muc Terraform (Infrastructure)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Dieu chinh duong dan nay tuy theo cau truc thuc te cua ban
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
    """Goi lenh aws configure de them profile moi"""
    print("\n--- THÊM PROFILE MỚI ---")
    print("Bạn sẽ cần nhập: Access Key ID, Secret Access Key, Region (ví dụ: ap-southeast-1)")
    
    profile_name = input("Nhập tên cho Profile mới (ví dụ: dev-env): ").strip()
    if not profile_name:
        print("[LỖI] Tên Profile không được để trống.")
        return

    try:
        print(f"\n>> Đang chạy cấu hình cho profile '{profile_name}'...")
        subprocess.run(["aws", "configure", "--profile", profile_name], check=True)
        print(f"\n[THÀNH CÔNG] Đã thêm Profile '{profile_name}'.")
    except FileNotFoundError:
        print("\n[LỖI] Không tìm thấy lệnh 'aws'. Vui lòng cài đặt AWS CLI trước.")
    except Exception as e:
        print(f"\n[LỖI] Không thể thêm profile: {e}")

def select_profile(profiles):
    while True:
        print("\nDanh sách Profile khả dụng:")
        for idx, p in enumerate(profiles):
            print(f"  [{idx + 1}] {p}")
        
        # Them option them profile
        add_idx = len(profiles) + 1
        print(f"  [{add_idx}] (+) Thêm Profile mới")
    
        p_choice = input("\nChọn Profile (Nhập số): ").strip()
        if p_choice.isdigit():
            choice = int(p_choice)
            if 1 <= choice <= len(profiles):
                return profiles[choice - 1]
            elif choice == add_idx:
                add_new_profile()
                # Reload lai danh sach sau khi them
                profiles = get_aws_profiles()
                continue
        print("[CẢNH BÁO] Lựa chọn không hợp lệ.")

def get_days_since_last_use(last_used_date):
    """Tinh so ngay tu lan cuoi hoat dong"""
    if not last_used_date:
        return "Never"
    now = datetime.datetime.now(tzutc())
    delta = now - last_used_date
    return f"{delta.days} days ago"

def print_header(text):
    print("\n" + "=" * 70)
    print(f" {text}")
    print("=" * 70)

def print_cis_section(cis_id, title):
    print(f"\n>>> [{cis_id}] {title}")
    print("-" * 60)

def get_all_regions(session):
    """Lay danh sach tat ca cac Region ma account co the truy cap"""
    try:
        ec2 = session.client('ec2')
        return [region['RegionName'] for region in ec2.describe_regions()['Regions']]
    except Exception as e:
        print(f"[WARN] Không thể lấy danh sách region: {e}")
        return [session.region_name]

# --- PHAN 1: TERRAFORM INFRASTRUCTURE ---
def run_terraform_infrastructure(profile):
    print_header(f"NHÓM 1 & 3: HẠ TẦNG & GIÁM SÁT (TERRAFORM) - Profile: {profile}")
    print("CÁC MỤC CIS SECTION 2 (IAM) SẼ ĐƯỢC TỰ ĐỘNG CẤU HÌNH/GIÁM SÁT:")
    print("  - [CIS 2.7 & 2.8] Password Policy (14 ký tự, chống tái sử dụng)")
    print("  - [CIS 2.16]      Support Role")
    print("  - [CIS 2.19]      Access Analyzer")
    print("  - [CIS 2.3, 2.4, 2.11, 2.12, 2.13, 2.18] AWS Config Rules (IAM Compliance)")
    print("-" * 70)
    
    if not os.path.isdir(TERRAFORM_DIR):
        print(f"\n[LỖI] Không tìm thấy thư mục Terraform tại: {TERRAFORM_DIR}")
        return

    # B1: Init
    print(f"[INFO] Đang khởi tạo Terraform (Init)...")
    try:
        subprocess.run("terraform init", shell=True, cwd=TERRAFORM_DIR, check=True, stdout=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        print("[ERROR] Terraform Init thất bại.")
        return

    # B2: Apply
    print(f"[INFO] Đang triển khai (Apply)...")
    cmd = f'terraform apply -var="aws_profile={profile}" -auto-approve'
    
    try:
        subprocess.run(cmd, shell=True, cwd=TERRAFORM_DIR, check=True)
        print(f"\n[SUCCESS] Đã hoàn tất triển khai Terraform.")
    except subprocess.CalledProcessError:
        print(f"\n[ERROR] Terraform Apply thất bại.")

# --- PHAN 2: PYTHON REMEDIATION (LOGIC CHI TIET) ---

def remediate_cis_2_2(session):
    """[CIS 2.2] Cap nhat Security Contact Information"""
    print_cis_section("CIS 2.2", "CẬP NHẬT THÔNG TIN LIÊN HỆ BẢO MẬT")
    
    print("   [LƯU Ý] Đây là dữ liệu ít thay đổi. Khuyến nghị cập nhật thủ công.")
    
    account = session.client('account')
    try:
        curr = account.get_alternate_contact(AlternateContactType='SECURITY')
        print(f"   -> Hiện tại: Đã cấu hình ({curr['AlternateContact']['EmailAddress']})")
    except ClientError:
        print("   -> Hiện tại: Chưa cấu hình.")

    if input("   => Bạn có muốn cập nhật ngay không? (y/n): ").lower() != 'y':
        print("   [SKIP] Bỏ qua.")
        return

    email = input("   - Email: ").strip()
    name = input("   - Tên/Team: ").strip()
    phone = input("   - SĐT: ").strip()
    title = input("   - Chức danh: ").strip()

    try:
        account.put_alternate_contact(
            AlternateContactType='SECURITY', EmailAddress=email, Name=name, PhoneNumber=phone, Title=title
        )
        print("   [FIXED] Đã cập nhật thành công.")
    except Exception as e:
        print(f"   [LỖI] {e}")

def remediate_cis_2_3(session):
    """[CIS 2.3] Xu ly Access Keys cua Root"""
    print_cis_section("CIS 2.3", "KIỂM TRA & XỬ LÝ ROOT ACCESS KEYS")
    iam = session.client('iam')
    
    try:
        summary = iam.get_account_summary()['SummaryMap']
        if summary.get('AccountAccessKeysPresent', 0) > 0:
            print("   [CẢNH BÁO] Root đang có Access Key!")
            print("   [1] Vô hiệu hóa (Deactivate) - Khuyên dùng")
            print("   [2] Xóa vĩnh viễn (Delete)")
            print("   [0] Bỏ qua")
            
            choice = input("   => Lựa chọn (0/1/2): ").strip()
            if choice == '0': return

            # Can chay bang Root credentials moi list duoc key cua Root
            try:
                paginator = iam.get_paginator('list_access_keys')
                for page in paginator.paginate(UserName='root'): 
                    for key in page['AccessKeyMetadata']:
                        key_id = key['AccessKeyId']
                        if choice == '1':
                            iam.update_access_key(UserName='root', AccessKeyId=key_id, Status='Inactive')
                            print(f"      [FIXED] Đã vô hiệu hóa Key {key_id}.")
                        elif choice == '2':
                            iam.delete_access_key(UserName='root', AccessKeyId=key_id)
                            print(f"      [FIXED] Đã xóa Key {key_id}.")
            except ClientError as e:
                print(f"   [LỖI] Cần đăng nhập bằng Root để thực hiện: {e}")
        else:
            print("   [PASS] Root không có Access Key.")
    except Exception as e:
        print(f"   [LỖI] {e}")

def remediate_cis_2_21(session):
    """[CIS 2.21] Go bo quyen CloudShell FullAccess"""
    print_cis_section("CIS 2.21", "GỠ BỎ QUYỀN CLOUDSHELL FULL ACCESS")
    iam = session.client('iam')
    policy_arn = "arn:aws:iam::aws:policy/AWSCloudShellFullAccess"

    try:
        entities = iam.list_entities_for_policy(PolicyArn=policy_arn)
        total = len(entities['PolicyGroups']) + len(entities['PolicyUsers']) + len(entities['PolicyRoles'])
        
        if total == 0:
            print("   [PASS] Không ai có quyền này.")
            return

        print(f"   [CẢNH BÁO] Phát hiện {total} đối tượng có quyền CloudShell FullAccess.")
        if input("   => Tự động gỡ bỏ (Detach) khỏi tất cả? (y/n): ").lower() == 'y':
            for u in entities['PolicyUsers']:
                iam.detach_user_policy(UserName=u['UserName'], PolicyArn=policy_arn)
                print(f"   -> Đã gỡ khỏi User: {u['UserName']}")
            for g in entities['PolicyGroups']:
                iam.detach_group_policy(GroupName=g['GroupName'], PolicyArn=policy_arn)
                print(f"   -> Đã gỡ khỏi Group: {g['GroupName']}")
            for r in entities['PolicyRoles']:
                iam.detach_role_policy(RoleName=r['RoleName'], PolicyArn=policy_arn)
                print(f"   -> Đã gỡ khỏi Role: {r['RoleName']}")
            print("   [FIXED] Hoàn tất.")
    except Exception as e:
        print(f"   [LỖI] {e}")

# --- LOGIC QUAN LY USER CHI TIET ---

def audit_root_mfa(iam_client):
    print_cis_section("CIS 2.4", "KIỂM TRA MFA CHO TÀI KHOẢN ROOT")
    try:
        summary = iam_client.get_account_summary()['SummaryMap']
        root_mfa = summary.get('AccountMFAEnabled', 0)
        
        if root_mfa == 1:
            print("   [PASS] Tài khoản Root đã bật MFA.")
        else:
            print("   [FAIL] Tài khoản Root CHƯA bật MFA! (Cần bật thủ công ngay)")
    except Exception as e:
        print(f"   [ERROR] Không thể kiểm tra: {e}")

def audit_and_fix_mfa(iam_client, account_id):
    print_cis_section("CIS 2.9", "KIỂM TRA & CƯỠNG CHẾ MFA CHO USER")
    
    users = iam_client.list_users()['Users']
    policy_arn = f"arn:aws:iam::{account_id}:policy/Force_MFA_Policy"
    
    violation_count = 0
    for user in users:
        username = user['UserName']
        try:
            iam_client.get_login_profile(UserName=username) # Check console access
        except:
            continue 
            
        mfa = iam_client.list_mfa_devices(UserName=username)['MFADevices']
        
        if not mfa:
            violation_count += 1
            last_login = user.get('PasswordLastUsed')
            last_active = get_days_since_last_use(last_login)
            
            print(f"   [VI PHẠM] User: {username} | MFA: KHÔNG CÓ | Last Login: {last_active}")
            confirm = input(f"    => Bạn có muốn gán 'Force_MFA_Policy' (Chặn quyền) cho {username}? (y/n): ").lower()
            
            if confirm == 'y':
                try:
                    iam_client.attach_user_policy(UserName=username, PolicyArn=policy_arn)
                    print(f"    [FIXED] Đã gán policy chặn quyền (Force MFA).")
                except Exception as e:
                    print(f"    [ERROR] Không thể gán policy (Cần tạo Policy này trước): {e}")
            else:
                print(f"    [SKIP] Bỏ qua.")
    
    if violation_count == 0:
        print("   [PASS] Tất cả Console Users đều đã bật MFA.")

def audit_and_fix_admin(iam_client):
    print_cis_section("CIS 2.15", "KIỂM TRA QUYỀN ADMINISTRATOR (FULL ACCESS)")
    
    users = iam_client.list_users()['Users']
    violation_count = 0

    for user in users:
        username = user['UserName']
        attached = iam_client.list_attached_user_policies(UserName=username)['AttachedPolicies']
        
        for policy in attached:
            if policy['PolicyName'] == 'AdministratorAccess':
                violation_count += 1
                last_login = user.get('PasswordLastUsed')
                last_active = get_days_since_last_use(last_login)
                
                print(f"   [VI PHẠM] User: {username} | Role: FULL ADMIN | Last Login: {last_active}")
                
                confirm = input(f"    => Hạ cấp xuống 'ReadOnlyAccess'? (y/n): ").lower()
                
                if confirm == 'y':
                    try:
                        iam_client.detach_user_policy(UserName=username, PolicyArn=policy['PolicyArn'])
                        iam_client.attach_user_policy(UserName=username, PolicyArn='arn:aws:iam::aws:policy/ReadOnlyAccess')
                        print(f"    [FIXED] Đã hạ cấp {username} từ Admin -> ReadOnly.")
                    except Exception as e:
                        print(f"    [ERROR] Lỗi xử lý: {e}")
                else:
                    print(f"    [SKIP] Giữ nguyên.")
    
    if violation_count == 0:
        print("   [PASS] Không có User nào được gán AdministratorAccess trực tiếp.")

def audit_direct_policies(iam_client):
    print_cis_section("CIS 2.14", "RÀ SOÁT QUYỀN GÁN TRỰC TIẾP")
    
    users = iam_client.list_users()['Users']
    whitelist = ['Force_MFA_Policy', 'ReadOnlyAccess'] # Policy ngoai le
    
    found = False
    for user in users:
        username = user['UserName']
        attached = iam_client.list_attached_user_policies(UserName=username)['AttachedPolicies']
        suspicious = [p['PolicyName'] for p in attached if p['PolicyName'] not in whitelist]
        
        if suspicious:
             found = True
             print(f"   [INFO] User: {username} | Direct Policies: {', '.join(suspicious)}")
             print("    (Khuyến nghị: Nên gỡ bỏ và gán thông qua Group)")
    
    if not found:
        print("   [PASS] Tuân thủ tốt (Ít gán quyền trực tiếp).")

def audit_access_keys(iam_client):
    print_cis_section("CIS 2.12 & 2.13", "KIỂM TRA ACCESS KEYS")
    
    users = iam_client.list_users()['Users']
    violation_count = 0
    
    for user in users:
        username = user['UserName']
        keys = iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']
        active_keys = [k for k in keys if k['Status'] == 'Active']
        
        # Check so luong
        if len(active_keys) > 1:
            violation_count += 1
            print(f"   [VI PHẠM 2.12] User: {username} có {len(active_keys)} Key (Chỉ được phép 1)")
        
        # Check tuoi tho
        for key in active_keys:
            key_id = key['AccessKeyId']
            age = (datetime.datetime.now(tzutc()) - key['CreateDate']).days
            
            if age > 90:
                violation_count += 1
                print(f"   [VI PHẠM 2.13] User: {username} | Key: {key_id} | Tuổi: {age} ngày (>90)")
                if input("    => Vô hiệu hóa (Deactivate) key này? (y/n): ").lower() == 'y':
                    iam_client.update_access_key(UserName=username, AccessKeyId=key_id, Status='Inactive')
                    print("    [FIXED] Đã vô hiệu hóa.")
                
    if violation_count == 0:
        print("   [PASS] Tất cả User tuân thủ chính sách Access Key.")

# --- CIS 2.17 REMEDIATION (Updated for Terraform Integration) ---
def remediate_cis_2_17(session):
    """
    [CIS 2.17] Ensure IAM instance roles are used for AWS resource access from instances
    Fix: Gắn Role 'CIS_Empty_Instance_Profile' cho instance chưa có Role.
    """
    print_cis_section("CIS 2.17", "GẮN IAM ROLE CHO EC2 INSTANCES (Using Terraform Role)")
    
    regions = get_all_regions(session)
    iam_client = session.client('iam')
    
    # Tên của Instance Profile được tạo bởi Terraform trong file main.tf
    # resource "aws_iam_instance_profile" "cis_empty_instance_profile" { name = "CIS_Empty_Instance_Profile" ... }
    PROFILE_NAME = "CIS_Empty_Instance_Profile"
    
    # Kiểm tra xem Profile đã tồn tại chưa (do Terraform tạo)
    profile_exists = False
    try:
        iam_client.get_instance_profile(InstanceProfileName=PROFILE_NAME)
        profile_exists = True
        print(f"   [CHECK] Đã tìm thấy Instance Profile '{PROFILE_NAME}' (từ Terraform).")
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            print(f"   [CẢNH BÁO] Không tìm thấy Instance Profile '{PROFILE_NAME}'.")
            print("       -> Vui lòng chạy 'Terraform Apply' (Option 1) trước để tạo Role này.")
            return # Dừng nếu chưa có Role
        else:
            print(f"   [ERROR] Lỗi kiểm tra Instance Profile: {e}")
            return

    # Quét và Fix
    if profile_exists:
        for region in regions:
            try:
                ec2 = session.client('ec2', region_name=region)
                # Filter running/stopped instances
                instances = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'stopped']}])
                
                for r in instances['Reservations']:
                    for i in r['Instances']:
                        instance_id = i['InstanceId']
                        # Check IAM Role (IamInstanceProfile attribute)
                        if 'IamInstanceProfile' not in i:
                            print(f"   [VI PHẠM] Instance {instance_id} (Region: {region}) KHÔNG có IAM Role.")
                            print("       -> Rủi ro: Có thể đang dùng Access Key cứng.")
                            
                            choice = input(f"       [?] Gán role '{PROFILE_NAME}' cho instance này? (y/n): ").lower()
                            if choice == 'y':
                                try:
                                    ec2.associate_iam_instance_profile(
                                        InstanceId=instance_id,
                                        IamInstanceProfile={'Name': PROFILE_NAME}
                                    )
                                    print("       [FIXED] Đã gắn Role thành công.")
                                except Exception as e:
                                    print(f"       [ERROR] Gắn Role thất bại: {e}")
            except Exception as e:
                pass

def run_user_remediation(profile):
    """Goi Boto3 de xu ly logic Account & User"""
    print_header(f"NHÓM 2: KHẮC PHỤC CẤU HÌNH & USER (PYTHON) - Profile: {profile}")
    
    try:
        session = boto3.Session(profile_name=profile)
        iam = session.client('iam')
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        
        # 1. Cac muc Account & System (Manual -> Auto)
        remediate_cis_2_2(session)
        remediate_cis_2_3(session)
        remediate_cis_2_21(session)

        # 2. Cac muc User Management (Logic cu)
        audit_root_mfa(iam)
        audit_and_fix_mfa(iam, account_id)
        audit_and_fix_admin(iam)
        audit_direct_policies(iam)
        audit_access_keys(iam)
        
        # 3. [MOI] CIS 2.17 - EC2 IAM Roles (Updated)
        remediate_cis_2_17(session)
        
        print("\n[SUCCESS] Hoàn tất rà soát và khắc phục.")
        
    except Exception as e:
        print(f"[ERROR] Lỗi kết nối AWS: {e}")

# MAIN MENU
def main():
    print("\n--- AWS IAM REMEDIATION TOOL (SECTION 2: IAM) ---")
    profiles = get_aws_profiles()
    
    if not profiles:
        print("Chưa tìm thấy Profile. Đang chuyển sang menu thêm mới...")
        select_profile([])
        return

    selected_profile = select_profile(profiles)
    
    while True:
        print(f"\nĐang làm việc với Profile: {selected_profile}")
        print("  [1] CHIẾN LƯỢC GIÁM SÁT (Terraform):")
        print("      => [CIS 2.7, 2.8, 2.16, 2.19] Cấu hình hệ thống")
        print("      => [CIS 2.3, 2.4, 2.11, 2.12, 2.13, 2.18] Config Rules (Giám sát)")
        print("  [2] CHIẾN LƯỢC KHẮC PHỤC (Python):")
        print("      => [CIS 2.2, 2.3, 2.21] Account & System (Tự động hóa thủ công)")
        print("      => [CIS 2.4, 2.9, 2.12, 2.13, 2.14, 2.15] User Management")
        print("      => [CIS 2.17] IAM Instance Roles (Sử dụng Terraform Role)")
        print("  [3] CHẠY TOÀN BỘ (Full Remediation)")
        print("  [0] Thoát")
        
        ans = input("Lựa chọn của bạn: ").strip()
        
        if ans == '1':
            run_terraform_infrastructure(selected_profile)
        elif ans == '2':
            run_user_remediation(selected_profile)
        elif ans == '3':
            run_terraform_infrastructure(selected_profile)
            run_user_remediation(selected_profile)
        elif ans == '0':
            sys.exit(0)
        else:
            print("Lựa chọn không hợp lệ.")

if __name__ == "__main__":
    main()