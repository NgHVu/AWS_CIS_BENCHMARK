import boto3
import sys
import os
import subprocess
from botocore.exceptions import ClientError

# Cấu hình Region mặc định
TARGET_REGION = 'ap-southeast-1'

# Đường dẫn đến thư mục Terraform
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TERRAFORM_DIR = os.path.join(BASE_DIR, "../../infrastructure/iam_baseline")

# --- UTILS ---
def get_aws_profiles():
    try:
        session = boto3.Session()
        return session.available_profiles if session.available_profiles else []
    except: return []

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

def get_all_regions(session):
    try:
        ec2 = session.client('ec2', region_name=TARGET_REGION)
        return [r['RegionName'] for r in ec2.describe_regions()['Regions']]
    except:
        return [TARGET_REGION]

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
    print("Mục tiêu: Kích hoạt các luật kiểm tra tự động (AWS Config Rules) cho Networking.")
    print("-" * 70)
    print("  - [CIS 6.1.1] EBS Encryption by Default")
    print("  - [CIS 6.x] Restricted Common Ports (Security Groups Check)")
    print("  - [CIS 6.5] VPC Default Security Group Closed")
    print("  - [CIS 6.7] EC2 IMDSv2 Check")
    print("-" * 70)
    
    if not os.path.isdir(TERRAFORM_DIR):
        print(f"\n[LỖI] Không tìm thấy thư mục Terraform tại: {TERRAFORM_DIR}")
        return

    if input("\n=> Bạn có muốn triển khai hệ thống giám sát này không? (y/n): ").lower() != 'y':
        return

    try:
        print(f"\n[INFO] Đang khởi tạo Terraform...")
        subprocess.run("terraform init", shell=True, cwd=TERRAFORM_DIR, check=True, stdout=subprocess.DEVNULL)
        
        print(f"[INFO] Đang áp dụng cấu hình giám sát...")
        cmd = f'terraform apply -var="aws_profile={profile}" -auto-approve'
        subprocess.run(cmd, shell=True, cwd=TERRAFORM_DIR, check=True)
        print(f"\n[THÀNH CÔNG] Hệ thống giám sát Networking đã được kích hoạt.")
    except subprocess.CalledProcessError:
        print(f"\n[LỖI] Terraform thất bại.")

# ==============================================================================
# PHẦN 2: CHIẾN LƯỢC KHẮC PHỤC TRỰC TIẾP (ACTIVE REMEDIATION - PYTHON)
# ==============================================================================

def remediate_6_1_1_ebs_encryption(ec2_client, region):
    """[CIS 6.1.1] Ensure EBS volume encryption is enabled in all regions"""
    print_cis_section("CIS 6.1.1", f"EBS ENCRYPTION DEFAULT ({region})")
    try:
        status = ec2_client.get_ebs_encryption_by_default()
        if not status['EbsEncryptionByDefault']:
            print(f"   [VI PHẠM] Chưa bật mã hóa mặc định.")
            if input(f"     => Bật ngay cho region {region}? (y/n): ").lower() == 'y':
                ec2_client.enable_ebs_encryption_by_default()
                print("     [FIXED] Đã bật thành công.")
        else:
            print("   [PASS] Đã bật.")
    except ClientError as e:
        print(f"   [ERROR] {e}")

def remediate_security_groups_ingress(ec2_client, region):
    """
    [CIS 6.1.2, 6.3, 6.4] Restrict SSH/RDP/CIFS from 0.0.0.0/0
    """
    print_cis_section("CIS 6.x", f"RESTRICT RISKY PORTS (22, 3389, 445) - ({region})")
    risky_ports = [22, 3389, 445]
    
    try:
        sgs = ec2_client.describe_security_groups(Filters=[
            {'Name': 'ip-permission.cidr', 'Values': ['0.0.0.0/0']},
            {'Name': 'ip-permission.ipv6-cidr', 'Values': ['::/0']}
        ])['SecurityGroups']

        violation_count = 0
        for sg in sgs:
            for perm in sg['IpPermissions']:
                from_p = perm.get('FromPort')
                to_p = perm.get('ToPort')
                proto = perm.get('IpProtocol')
                
                is_risk = False
                if proto == '-1': is_risk = True
                elif from_p is not None and to_p is not None:
                    for rp in risky_ports:
                        if from_p <= rp <= to_p:
                            is_risk = True
                            break
                
                if is_risk:
                    bad_ipv4 = [r for r in perm.get('IpRanges', []) if r['CidrIp'] == '0.0.0.0/0']
                    bad_ipv6 = [r for r in perm.get('Ipv6Ranges', []) if r.get('CidrIpv6') == '::/0']
                    
                    if bad_ipv4 or bad_ipv6:
                        violation_count += 1
                        print(f"   [VI PHẠM] SG: {sg['GroupId']} ({sg['GroupName']})")
                        print(f"       Rule: Proto {proto}, Port {from_p}-{to_p}")
                        
                        if input("       [?] Xóa (Revoke) rule này? (y/n): ").lower() == 'y':
                            try:
                                revoke_args = {
                                    'GroupId': sg['GroupId'],
                                    'IpPermissions': [{
                                        'IpProtocol': proto,
                                        'FromPort': from_p,
                                        'ToPort': to_p,
                                        'IpRanges': bad_ipv4,
                                        'Ipv6Ranges': bad_ipv6
                                    }]
                                }
                                if not bad_ipv4: del revoke_args['IpPermissions'][0]['IpRanges']
                                if not bad_ipv6: del revoke_args['IpPermissions'][0]['Ipv6Ranges']
                                
                                ec2_client.revoke_security_group_ingress(**revoke_args)
                                print("       [FIXED] Đã xóa rule.")
                            except Exception as e:
                                print(f"       [ERROR] {e}")

        if violation_count == 0:
            print("   [PASS] Không tìm thấy SG vi phạm.")

    except ClientError as e:
        print(f"   [ERROR] {e}")

def remediate_6_2_nacl(ec2_client, region):
    """
    [CIS 6.2] Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote admin ports
    """
    print_cis_section("CIS 6.2", f"NACL INGRESS CHECK ({region})")
    try:
        nacls = ec2_client.describe_network_acls()['NetworkAcls']
        risky_ports = [22, 3389]
        
        violation_found = False
        for nacl in nacls:
            for entry in nacl['Entries']:
                # Chỉ kiểm tra Inbound (Egress=False) và Allow
                if not entry['Egress'] and entry['RuleAction'] == 'allow':
                    cidr = entry.get('CidrBlock')
                    ipv6 = entry.get('Ipv6CidrBlock')
                    
                    if cidr == '0.0.0.0/0' or ipv6 == '::/0':
                        proto = entry.get('Protocol')
                        port_range = entry.get('PortRange')
                        
                        is_risk = False
                        if proto == '-1': is_risk = True
                        elif port_range:
                            for rp in risky_ports:
                                if port_range['From'] <= rp <= port_range['To']:
                                    is_risk = True
                                    break
                        
                        if is_risk:
                            violation_found = True
                            print(f"   [VI PHẠM] NACL {nacl['NetworkAclId']} (Rule #{entry['RuleNumber']}) cho phép {cidr or ipv6} vào Admin Ports.")
                            print("       Lưu ý: NACL là stateless. Xóa rule này có thể làm mất kết nối nếu không có rule thay thế.")
                            if input("       [?] Xóa rule này? (y/n): ").lower() == 'y':
                                try:
                                    ec2_client.delete_network_acl_entry(
                                        NetworkAclId=nacl['NetworkAclId'],
                                        RuleNumber=entry['RuleNumber'],
                                        Egress=False
                                    )
                                    print("       [FIXED] Đã xóa rule NACL.")
                                except Exception as e:
                                    print(f"       [ERROR] Không thể xóa: {e}")
        if not violation_found:
            print("   [PASS] Không tìm thấy NACL vi phạm.")

    except ClientError as e:
        print(f"   [ERROR] {e}")

def remediate_6_5_default_sg(ec2_client, region):
    """[CIS 6.5] Ensure default security group restricts all traffic"""
    print_cis_section("CIS 6.5", f"DEFAULT SECURITY GROUP ({region})")
    try:
        # Lấy tất cả SG có tên là 'default'
        default_sgs = ec2_client.describe_security_groups(
            Filters=[{'Name': 'group-name', 'Values': ['default']}]
        )['SecurityGroups']

        for sg in default_sgs:
            # Check Inbound rules
            inbound_rules = sg['IpPermissions']
            outbound_rules = sg['IpPermissionsEgress']
            
            # Theo CIS, default SG phải không có rule inbound/outbound nào
            if inbound_rules or outbound_rules:
                print(f"   [VI PHẠM] Default SG {sg['GroupId']} (VPC {sg['VpcId']}) có rules.")
                if input("     => Xóa TẤT CẢ rules của Default SG này? (y/n): ").lower() == 'y':
                    try:
                        if inbound_rules:
                            ec2_client.revoke_security_group_ingress(GroupId=sg['GroupId'], IpPermissions=inbound_rules)
                        if outbound_rules:
                            ec2_client.revoke_security_group_egress(GroupId=sg['GroupId'], IpPermissions=outbound_rules)
                        print("     [FIXED] Đã làm sạch Default SG.")
                    except Exception as e:
                        print(f"     [ERROR] Không thể xóa: {e}")
            else:
                print(f"   [PASS] Default SG {sg['GroupId']} đã sạch (No rules).")

    except ClientError as e:
        print(f"   [ERROR] {e}")

def remediate_6_7_imdsv2(ec2_client, region):
    """[CIS 6.7] Ensure EC2 Metadata Service only allows IMDSv2"""
    print_cis_section("CIS 6.7", f"IMDSv2 ENFORCEMENT ({region})")
    try:
        instances = ec2_client.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
        count = 0
        for r in instances['Reservations']:
            for i in r['Instances']:
                meta = i.get('MetadataOptions', {})
                if meta.get('HttpTokens') != 'required':
                    count += 1
                    print(f"   [VI PHẠM] Instance {i['InstanceId']} đang dùng IMDSv1.")
                    if input("     => Chuyển sang IMDSv2 (Token Required)? (y/n): ").lower() == 'y':
                        ec2_client.modify_instance_metadata_options(
                            InstanceId=i['InstanceId'],
                            HttpTokens='required',
                            HttpEndpoint='enabled'
                        )
                        print("     [FIXED] Đã update.")
        
        if count == 0:
            print("   [PASS] Tất cả instance đã tuân thủ IMDSv2.")
            
    except ClientError as e:
        print(f"   [ERROR] {e}")

def run_python_remediation(profile):
    print_header(f"KHẮC PHỤC TRỰC TIẾP (PYTHON) - Profile: {profile}")
    session = boto3.Session(profile_name=profile)
    
    print(f"Đang lấy danh sách Region...")
    regions = get_all_regions(session)
    print(f"Sẽ quét trên {len(regions)} regions: {', '.join(regions)}")

    for region in regions:
        try:
            ec2 = session.client('ec2', region_name=region)
            remediate_6_1_1_ebs_encryption(ec2, region)
            remediate_security_groups_ingress(ec2, region)
            remediate_6_2_nacl(ec2, region) # Đã bổ sung
            remediate_6_5_default_sg(ec2, region)
            remediate_6_7_imdsv2(ec2, region)
        except Exception as e:
            print(f"[CRITICAL ERROR] Region {region}: {e}")

    print("\n[SUCCESS] Hoàn tất quá trình khắc phục Networking.")

# --- MAIN MENU ---
def main():
    print("\n--- AWS NETWORKING REMEDIATION TOOL (CIS v6.0.0) ---")
    profiles = get_aws_profiles()
    
    if not profiles:
        print("Chưa tìm thấy Profile. Đang chuyển sang menu thêm mới...")
        select_profile([])
        return

    selected_profile = select_profile(profiles)
    
    while True:
        print(f"\nĐang làm việc với Profile: {selected_profile}")
        print("  [1] CHIẾN LƯỢC GIÁM SÁT (Terraform):")
        print("      => [CIS 6.x] Kích hoạt Config Rules (Ports, EBS, IMDSv2, Default SG)")
        print("  [2] CHIẾN LƯỢC KHẮC PHỤC (Python):")
        print("      => [CIS 6.1.1] Bật EBS Encryption Default")
        print("      => [CIS 6.x] Xóa Rule SG nguy hiểm (SSH/RDP 0.0.0.0/0)")
        print("      => [CIS 6.2] Kiểm tra & Xóa NACL nguy hiểm")
        print("      => [CIS 6.5] Làm sạch Default SG")
        print("      => [CIS 6.7] Bắt buộc IMDSv2")
        print("  [3] CHẠY TOÀN BỘ (Full Remediation)")
        print("  [0] Thoát")
        
        ans = input("\nLựa chọn của bạn: ").strip()
        
        if ans == '1':
            apply_monitoring_guardrails(selected_profile)
        elif ans == '2':
            run_python_remediation(selected_profile)
        elif ans == '3':
            apply_monitoring_guardrails(selected_profile)
            run_python_remediation(selected_profile)
        elif ans == '0':
            sys.exit(0)
        else:
            print("Lựa chọn không hợp lệ.")

if __name__ == "__main__":
    main()