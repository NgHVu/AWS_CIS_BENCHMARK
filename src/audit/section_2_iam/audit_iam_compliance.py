import boto3
import datetime
import sys
import time
import csv
import io
import subprocess
from botocore.exceptions import ClientError
from dateutil.tz import tzutc

# Cấu hình giới hạn theo chuẩn CIS
MAX_KEY_AGE_DAYS = 90    # CIS 2.13
UNUSED_DAYS = 45         # CIS 2.11
MIN_PWD_LENGTH = 14      # CIS 2.7
ROOT_USAGE_THRESHOLD = 1 # CIS 2.6 (Cảnh báo nếu root dùng trong 24h qua)

def get_aws_profiles():
    """Lay danh sach profile tu file credentials"""
    try:
        session = boto3.Session()
        profiles = session.available_profiles
        return profiles if profiles else []
    except Exception as e:
        # Truong hop chua co file credentials
        return []

def add_new_profile():
    """Goi lenh aws configure de them profile moi"""
    print("\n--- THÊM PROFILE MỚI ---")
    print("Bạn sẽ cần nhập: Access Key ID, Secret Access Key, Region (ví dụ: us-east-1)")
    
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
        
        # Them tuy chon them profile
        add_option_idx = len(profiles) + 1
        print(f"  [{add_option_idx}] (+) Thêm Profile mới")
    
        p_choice = input("\nChọn Profile muốn kiểm tra (Nhập số): ").strip()
        
        if p_choice.isdigit():
            choice = int(p_choice)
            if 1 <= choice <= len(profiles):
                return profiles[choice - 1]
            elif choice == add_option_idx:
                add_new_profile()
                # Reload danh sach sau khi them
                profiles = get_aws_profiles()
                continue
        
        print("[CẢNH BÁO] Lựa chọn không hợp lệ.")
        
def get_days_from_now(date_val):
    if not date_val: return 9999 # Tra ve so lon neu chua tung su dung
    now = datetime.datetime.now(tzutc())
    delta = now - date_val
    return delta.days

def get_credential_report(iam_client):
    """Tao va lay credential report dang CSV"""
    print(" ... Dang tao Credential Report (co the mat vai giay) ...")
    try:
        while True:
            resp = iam_client.generate_credential_report()
            if resp['State'] == 'COMPLETE':
                break
            time.sleep(2)
        
        response = iam_client.get_credential_report()
        content = response['Content'].decode('utf-8')
        reader = csv.DictReader(io.StringIO(content))
        return list(reader)
    except ClientError as e:
        print(f"[WARNING] Khong the lay Credential Report: {e}")
        return []

def check_root_activity_frequency(session):
    """Kiem tra tan suat hoat dong cua Root trong 24h qua qua CloudTrail"""
    try:
        ct = session.client('cloudtrail')
        # Lay thoi gian 24h truoc
        end_time = datetime.datetime.now(tzutc())
        start_time = end_time - datetime.timedelta(hours=24)
        
        # Tim kiem su kien cua user 'root'
        events = ct.lookup_events(
            LookupAttributes=[{'AttributeKey': 'Username', 'AttributeValue': 'root'}],
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=50 # Gioi han lay 50 su kien gan nhat de dem
        )
        
        count = len(events.get('Events', []))
        return count
    except Exception:
        return -1 # Khong the kiem tra (do quyen hoac chua bat CloudTrail)

def audit_iam_compliance(selected_profile):
    print(f"{'='*60}")
    print(f"   CIS AWS FOUNDATIONS BENCHMARK v6.0.0 - IAM AUDIT")
    print(f"   (Profile: {selected_profile})")
    print(f"{'='*60}\n")

    try:
        session = boto3.Session(profile_name=selected_profile, region_name='us-east-1')
        iam = session.client('iam')
        aa = session.client('accessanalyzer') # CIS 2.19
        account = session.client('account')   # CIS 2.1, 2.2 (Yeu cau region us-east-1 hoac global)
        ec2 = session.client('ec2')           # CIS 2.17 (EC2 Instances)
    except Exception as e:
        print(f"[FATAL ERROR] Khong the tao ket noi voi Profile '{selected_profile}': {e}")
        return

    # --- CHUẨN BỊ DỮ LIỆU ---
    cred_report = get_credential_report(iam)
    # Tim root user trong report
    root_user_report = next((item for item in cred_report if item['user'] == '<root_account>'), None)

    # --- NHÓM 1: TÀI KHOẢN GỐC & CHÍNH SÁCH (Account Level) ---
    print(">>> 1. KIỂM TRA CẤU HÌNH TÀI KHOẢN (Account Level)")
    
    # [CIS 2.1] Maintain current contact details
    try:
        account.get_contact_information()
        print(" [2.1] Maintain Contact Details: [PASS] (Thông tin liên hệ có thể truy xuất)")
    except ClientError as e:
        print(f" [2.1] Maintain Contact Details: [WARNING] (Không thể kiểm tra tự động - {e})")

    # [CIS 2.2] Ensure security contact information is registered
    try:
        account.get_alternate_contact(AlternateContactType='SECURITY')
        print(" [2.2] Security Contact Registered: [PASS]")
    except ClientError as e:
        if 'ResourceNotFoundException' in str(e):
             print(" [2.2] Security Contact Registered: [FAIL] (Chưa đăng ký Security Contact)")
        else:
             print(f" [2.2] Security Contact Registered: [WARNING] (Lỗi quyền hạn: {e})")

    try:
        summary = iam.get_account_summary()['SummaryMap']
        
        # [CIS 2.3] Root Access Keys
        root_keys = summary.get('AccountAccessKeysPresent', 0)
        print(f" [2.3] Root Access Keys: {'[FAIL]' if root_keys > 0 else '[PASS]'}")

        # [CIS 2.4] Root MFA
        root_mfa = summary.get('AccountMFAEnabled', 0)
        print(f" [2.4] Root MFA Enabled: {'[FAIL]' if root_mfa == 0 else '[PASS]'}")
        
        # [CIS 2.6] Eliminate use of 'root' user
        if root_user_report:
            last_used_str = root_user_report.get('password_last_used', 'N/A')
            if last_used_str != 'N/A' and last_used_str != 'no_information':
                last_used_date = datetime.datetime.fromisoformat(last_used_str)
                days_since = get_days_from_now(last_used_date)
                
                if days_since < ROOT_USAGE_THRESHOLD:
                    # Neu dung trong vong 24h, thu dem so hanh dong qua CloudTrail
                    freq = check_root_activity_frequency(session)
                    freq_msg = f"{freq}+ hành động" if freq >= 0 else "không rõ số lượng"
                    print(f" [2.6] Root User Usage: [FAIL] (Vừa sử dụng trong 24h qua: {freq_msg} - Cần hạn chế)")
                else:
                    print(f" [2.6] Root User Usage: [PASS] (Lần cuối sử dụng: {days_since} ngày trước)")
            else:
                print(" [2.6] Root User Usage: [PASS] (Chưa từng đăng nhập Console)")
        else:
            print(" [2.6] Root User Usage: [WARNING] (Không tìm thấy Root trong Report)")

        # [CIS 2.7 & 2.8] Password Policy
        try:
            policy = iam.get_account_password_policy()['PasswordPolicy']
            length = policy.get('MinimumPasswordLength', 0)
            reuse = policy.get('PasswordReusePrevention', 0)
            
            print(f" [2.7] Min Password Length ({length}/{MIN_PWD_LENGTH}): {'[FAIL]' if length < MIN_PWD_LENGTH else '[PASS]'}")
            print(f" [2.8] Password Reuse Prevention: {'[FAIL]' if reuse is None else '[PASS]'}")
        except ClientError:
            print(" [2.7] Min Password Length: [FAIL] (Chưa cấu hình Password Policy)")
            print(" [2.8] Password Reuse Prevention: [FAIL] (Chưa cấu hình Password Policy)")

    except Exception as e:
        print(f"Lỗi kiểm tra Account: {e}")

    # --- NHÓM 2: NGƯỜI DÙNG & KHÓA (User Level) ---
    print("\n>>> 2. KIỂM TRA NGƯỜI DÙNG & ACCESS KEYS (User Level)")
    try:
        users = iam.list_users()['Users']
    except Exception as e:
        print(f"Lỗi lấy danh sách user: {e}")
        users = []
    
    for user in users:
        name = user['UserName']
        user_created = user['CreateDate']
        print(f" -> User: {name}")
        
        # [CIS 2.9] MFA cho user có mật khẩu console
        has_console_access = False
        try:
            iam.get_login_profile(UserName=name) # Check Console Access
            has_console_access = True
            
            mfa = iam.list_mfa_devices(UserName=name)['MFADevices']
            if not mfa:
                print(f"    [2.9] Console MFA: [FAIL] (Có password nhưng không bật MFA)")
            else:
                print(f"    [2.9] Console MFA: [PASS]")
        except ClientError as e:
            if 'NoSuchEntity' in str(e):
                print(f"    [2.9] Console MFA: [PASS] (User này không có mật khẩu đăng nhập Console)")
            else:
                print(f"    [2.9] Console MFA: [WARNING] (Không thể kiểm tra: {e})")

        # [CIS 2.11] Check mật khẩu cũ không dùng (Unused Creds)
        if 'PasswordLastUsed' in user:
            pwd_age = get_days_from_now(user['PasswordLastUsed'])
            if pwd_age > UNUSED_DAYS:
                print(f"    [2.11] Password Unused: [FAIL] ({pwd_age} ngày > {UNUSED_DAYS} ngày)")
            else:
                print(f"    [2.11] Password Unused: [PASS]")
        elif has_console_access:
             print(f"    [2.11] Password Unused: [FAIL] (Có mật khẩu nhưng chưa từng sử dụng)")
        else:
             print(f"    [2.11] Password Unused: [PASS] (Không bật mật khẩu)")
        
        # [CIS 2.12 & 2.13] Check Access Keys
        keys = iam.list_access_keys(UserName=name)['AccessKeyMetadata']
        active_keys = [k for k in keys if k['Status'] == 'Active']
        
        if len(active_keys) > 1:
             print(f"    [2.12] Active Keys Count: [FAIL] ({len(active_keys)} keys > 1)")
        else:
             print(f"    [2.12] Active Keys Count: [PASS]")
        
        if not active_keys:
            print(f"    [2.13] Key Rotation: [PASS] (Không có Access Key nào hoạt động)")
            print(f"    [2.10] Key Created at Setup: [PASS] (Không có Access Key nào hoạt động)")
        else:
            for key in active_keys:
                key_id = key['AccessKeyId']
                key_created = key['CreateDate']
                key_age = get_days_from_now(key_created)
                
                # [CIS 2.13] Key Rotation
                status_2_13 = "[PASS]" if key_age <= MAX_KEY_AGE_DAYS else "[FAIL]"
                print(f"    [2.13] Key {key_id} Age: {status_2_13} ({key_age} ngày)")

                # [CIS 2.10] Key tạo cùng lúc setup
                if has_console_access:
                    time_diff = abs((key_created - user_created).total_seconds())
                    if time_diff < 600: # 10 phut
                        print(f"    [2.10] Key Created at Setup: [FAIL] (Key {key_id} tạo cùng lúc User)")
                    else:
                        print(f"    [2.10] Key Created at Setup: [PASS]")
                else:
                    # User khong co console access -> Nam ngoai pham vi cua 2.10
                    print(f"    [2.10] Key Created at Setup: [PASS] (Service Account (không có password), được phép tạo Key lúc setup)")

                # [CIS 2.11] Key không dùng
                last_used = iam.get_access_key_last_used(AccessKeyId=key_id)
                if 'LastUsedDate' in last_used['AccessKeyLastUsed']:
                    unused_days = get_days_from_now(last_used['AccessKeyLastUsed']['LastUsedDate'])
                    if unused_days > UNUSED_DAYS:
                        print(f"    [2.11] Key {key_id} Unused: [FAIL] (Không sử dụng trong {unused_days} ngày)")
                    else:
                        print(f"    [2.11] Key {key_id} Unused: [PASS]")
                else:
                    if key_age > UNUSED_DAYS:
                        print(f"    [2.11] Key {key_id} Unused: [FAIL] (Tạo {key_age} ngày trước nhưng chưa từng dùng)")
                    else:
                        print(f"    [2.11] Key {key_id} Unused: [PASS] (Key mới tạo, chưa dùng)")

        # [CIS 2.14 & 2.15] Check Policies
        attached_policies = iam.list_attached_user_policies(UserName=name)['AttachedPolicies']
        inline_policies = iam.list_user_policies(UserName=name)['PolicyNames']
        
        if attached_policies or inline_policies:
             print(f"    [2.14] Direct Policy Attachments: [FAIL] (Nên dùng Group thay vì gán trực tiếp)")
        else:
             print(f"    [2.14] Direct Policy Attachments: [PASS]")
        
        has_admin = False
        for p in attached_policies:
            if p['PolicyName'] == 'AdministratorAccess':
                 has_admin = True
                 break
        
        if has_admin:
            print(f"    [2.15] Admin Access: [FAIL] (Full Admin được gán trực tiếp)")
        else:
            print(f"    [2.15] Admin Access: [PASS]")

    # --- NHÓM 3: CẤU HÌNH HỆ THỐNG KHÁC (System Level) ---
    print("\n>>> 3. KIỂM TRA HỆ THỐNG (System Level)")
    
    # [CIS 2.16] Support Role
    try:
        support_policy_arn = "arn:aws:iam::aws:policy/AWSSupportAccess"
        entities = iam.list_entities_for_policy(PolicyArn=support_policy_arn)
        if len(entities['PolicyRoles']) > 0:
             print(f" [2.16] Support Role: [PASS]")
        else:
             print(f" [2.16] Support Role: [FAIL] (Chưa có Role nào gắn policy hỗ trợ)")
    except Exception:
        print(f" [2.16] Support Role: [FAIL]")

    # [CIS 2.17] IAM Instance Roles 
    try:
        # Lọc các instances đang chạy hoặc dừng
        instances = ec2.describe_instances(
            Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'stopped']}]
        )
        
        violation_count_2_17 = 0
        instance_checked_count = 0
        
        for r in instances['Reservations']:
            for i in r['Instances']:
                instance_checked_count += 1
                # Kiem tra thuoc tinh IamInstanceProfile
                if 'IamInstanceProfile' not in i:
                    violation_count_2_17 += 1
                    # In ra ID instance vi pham de de theo doi
                    print(f"    -> [INFO] Instance {i['InstanceId']} chua gan IAM Role.")
        
        if instance_checked_count == 0:
             print(f" [2.17] IAM Instance Roles: [PASS] (Không có EC2 instance nào trong region {session.region_name})")
        elif violation_count_2_17 > 0:
             print(f" [2.17] IAM Instance Roles: [FAIL] (Có {violation_count_2_17}/{instance_checked_count} instance chưa gắn IAM Role)")
        else:
             print(f" [2.17] IAM Instance Roles: [PASS] (Tất cả {instance_checked_count} instance đều có IAM Role)")

    except Exception as e:
        print(f" [2.17] IAM Instance Roles: [WARNING] (Lỗi: {e})")

    # [CIS 2.18] Server Certificates
    try:
        certs = iam.list_server_certificates()['ServerCertificateMetadataList']
        expired_certs = 0
        for c in certs:
            if c['Expiration'] < datetime.datetime.now(tzutc()):
                expired_certs += 1
        print(f" [2.18] Expired SSL Certs: {'[FAIL]' if expired_certs > 0 else '[PASS]'}")
    except Exception as e:
        print(f" [2.18] Expired SSL Certs: [FAIL] ({e})")

    # [CIS 2.19] Access Analyzer
    try:
        analyzers = aa.list_analyzers(type='ORGANIZATION')['analyzers']
        if not analyzers:
             analyzers = aa.list_analyzers(type='ACCOUNT')['analyzers']
        
        active_analyzers = [a for a in analyzers if a['status'] == 'ACTIVE']
        print(f" [2.19] IAM Access Analyzer: {'[PASS]' if active_analyzers else '[FAIL]'}")
    except Exception as e:
         print(f" [2.19] IAM Access Analyzer: [FAIL] (Lỗi hoặc chưa kích hoạt)")

    # [CIS 2.21] Ensure access to AWSCloudShellFullAccess is restricted
    try:
        cs_policy_arn = "arn:aws:iam::aws:policy/AWSCloudShellFullAccess"
        cs_entities = iam.list_entities_for_policy(PolicyArn=cs_policy_arn)
        total_attached = len(cs_entities['PolicyGroups']) + len(cs_entities['PolicyUsers']) + len(cs_entities['PolicyRoles'])
        
        if total_attached > 0:
            print(f" [2.21] CloudShell FullAccess: [FAIL] (Policy đang được gán cho {total_attached} entities - Nên hạn chế)")
        else:
            print(f" [2.21] CloudShell FullAccess: [PASS] (Không có user/role nào dùng FullAccess)")
    except Exception as e:
        print(f" [2.21] CloudShell FullAccess: [WARNING] ({e})")

    print(f"\n{'='*60}")
    print("   HOÀN TẤT QUÁ TRÌNH KIỂM TRA")
    print(f"{'='*60}")

if __name__ == "__main__":
    profiles = get_aws_profiles()
    # Logic moi: Luon goi select_profile ke ca khi chua co profile nao (de hien thi option them moi)
    if not profiles:
        print("Chưa tìm thấy Profile nào trong máy.")
        select_profile([])
    else:
        profile = select_profile(profiles)
        audit_iam_compliance(profile)