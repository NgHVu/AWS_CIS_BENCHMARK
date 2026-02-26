import boto3
import sys
import subprocess
import re
from botocore.exceptions import ClientError, NoCredentialsError

# Cau hinh Region mac dinh
TARGET_REGION = 'ap-southeast-1'

# --- CAC HAM HO TRO (UTILS) ---
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
    
        p_choice = input("\nChọn Profile muốn kiểm tra (Nhập số): ").strip()
        if p_choice.isdigit():
            choice = int(p_choice)
            if 1 <= choice <= len(profiles):
                return profiles[choice - 1]
            elif choice == add_idx:
                add_new_profile()
                profiles = get_aws_profiles()
                continue
        print("[CẢNH BÁO] Lựa chọn không hợp lệ.")

def normalize_pattern(pattern):
    """Loại bỏ khoảng trắng thừa để so sánh pattern chính xác hơn"""
    if not pattern:
        return ""
    return re.sub(r'\s+', '', pattern)

def check_filter_and_alarm(logs_client, cw_client, cis_id, title, filter_pattern):
    """
    Hàm kiểm tra generic cho CIS 5.1 -> 5.15
    """
    # Chuẩn hóa pattern chuẩn để so sánh
    target_pattern = normalize_pattern(filter_pattern)
    found_filter = False
    found_alarm = False
    metric_name = None
    metric_namespace = None

    try:
        # 1. Quét Metric Filters
        paginator = logs_client.get_paginator('describe_metric_filters')
        for page in paginator.paginate():
            for mf in page['metricFilters']:
                current_pattern = normalize_pattern(mf.get('filterPattern', ''))
                
                # So sánh chuỗi pattern
                if target_pattern in current_pattern:
                    found_filter = True
                    if mf['metricTransformations']:
                        metric_name = mf['metricTransformations'][0]['metricName']
                        metric_namespace = mf['metricTransformations'][0]['metricNamespace']
                    break
            if found_filter:
                break

        if not found_filter:
            print(f" [{cis_id}] {title}: [FAIL] (Không tìm thấy Metric Filter khớp pattern)")
            return

        # 2. Kiểm tra Alarm
        alarms = cw_client.describe_alarms_for_metric(
            MetricName=metric_name,
            Namespace=metric_namespace
        )

        if len(alarms['MetricAlarms']) > 0:
            for alarm in alarms['MetricAlarms']:
                if alarm['AlarmActions']:
                    found_alarm = True
                    break
        
        if found_alarm:
            print(f" [{cis_id}] {title}: [PASS]")
        else:
            print(f" [{cis_id}] {title}: [FAIL] (Có Filter nhưng thiếu Alarm/SNS Action)")

    except ClientError as e:
        print(f" [{cis_id}] {title}: [ERROR] {e}")

# ==============================================================================
# LOGIC AUDIT CHÍNH
# ==============================================================================
def audit_monitoring_compliance(selected_profile):
    print(f"\n{'='*60}")
    print(f"   CIS AWS FOUNDATIONS BENCHMARK v6.0.0 - MONITORING AUDIT")
    print(f"   (Profile: {selected_profile} | Region: {TARGET_REGION})")
    print(f"{'='*60}\n")

    try:
        session = boto3.Session(profile_name=selected_profile, region_name=TARGET_REGION)
        logs_client = session.client('logs')
        cw_client = session.client('cloudwatch')
        securityhub = session.client('securityhub')
    except Exception as e:
        print(f"[FATAL ERROR] Khong the tao ket noi: {e}")
        return

    print(">>> KIỂM TRA METRIC FILTERS & ALARMS (SECTION 5)")
    
    # Danh sách các mục kiểm tra
    checks = [
        ("5.1", "Unauthorized API calls", '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") && ($.sourceIPAddress!="delivery.logs.amazonaws.com") && ($.eventName!="HeadBucket") }'),
        ("5.2", "Console sign-in without MFA", '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") }'),
        ("5.3", "Usage of 'root' account", '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }'),
        ("5.4", "IAM policy changes", '{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}'),
        ("5.5", "CloudTrail configuration changes", '{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }'),
        ("5.6", "Console authentication failures", '{ ($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication") }'),
        ("5.7", "Disabling or scheduled deletion of CMKs", '{($.eventSource = kms.amazonaws.com) && (($.eventName=DisableKey)||($.eventName=ScheduleKeyDeletion)) }'),
        ("5.8", "S3 bucket policy changes", '{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }'),
        ("5.9", "AWS Config configuration changes", '{ ($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel)||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder)) }'),
        ("5.10", "Security Group changes", '{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) || ($.eventName = ModifySecurityGroupRules) }'),
        ("5.11", "NACL changes", '{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }'),
        ("5.12", "Network Gateway changes", '{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }'),
        ("5.13", "Route Table changes", '{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }'),
        ("5.14", "VPC changes", '{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }'),
        ("5.15", "AWS Organizations changes", '{ ($.eventSource = organizations.amazonaws.com) && (($.eventName = "AcceptHandshake") || ($.eventName = "AttachPolicy") || ($.eventName = "CreateAccount") || ($.eventName = "CreateOrganizationalUnit") || ($.eventName = "CreatePolicy") || ($.eventName = "DeclineHandshake") || ($.eventName = "DeleteOrganization") || ($.eventName = "DeleteOrganizationalUnit") || ($.eventName = "DeletePolicy") || ($.eventName = "DetachPolicy") || ($.eventName = "DisablePolicyType") || ($.eventName = "EnablePolicyType") || ($.eventName = "InviteAccountToOrganization") || ($.eventName = "LeaveOrganization") || ($.eventName = "MoveAccount") || ($.eventName = "RemoveAccountFromOrganization") || ($.eventName = "UpdatePolicy") || ($.eventName = "UpdateOrganizationalUnit")) }')
    ]

    for cis_id, title, pattern in checks:
        check_filter_and_alarm(logs_client, cw_client, cis_id, title, pattern)

    # 5.16 Security Hub
    print("\n>>> KIỂM TRA SECURITY HUB (5.16)")
    try:
        securityhub.get_enabled_standards()
        print(f" [5.16] Ensure AWS Security Hub is enabled: [PASS]")
    except ClientError as e:
        if e.response['Error']['Code'] == 'InvalidAccessException':
            print(f" [5.16] Ensure AWS Security Hub is enabled: [FAIL] (Chưa kích hoạt)")
        else:
            print(f" [5.16] Error: {e}")

    print(f"\n{'='*60}")
    print("   HOÀN TẤT KIỂM TRA MONITORING")
    print(f"{'='*60}")

if __name__ == "__main__":
    profiles = get_aws_profiles()
    if not profiles:
        print("Chưa tìm thấy Profile nào trong máy.")
        select_profile([])
    else:
        profile = select_profile(profiles)
        audit_monitoring_compliance(profile)