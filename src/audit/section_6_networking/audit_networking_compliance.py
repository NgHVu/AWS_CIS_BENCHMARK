import boto3
import sys
import subprocess
from botocore.exceptions import ClientError

# Cau hinh Region mac dinh (Networking la Regional)
TARGET_REGION = 'ap-southeast-1'

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
    print(f"Bạn sẽ cần nhập: Access Key, Secret Key, Region (Ví dụ: {TARGET_REGION})")
    profile_name = input("Nhập tên cho Profile mới (ví dụ: dev-env): ").strip()
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
            if 1 <= choice <= len(profiles):
                return profiles[choice - 1]
            elif choice == add_idx:
                add_new_profile()
                profiles = get_aws_profiles()
                continue
        print("[CẢNH BÁO] Lựa chọn không hợp lệ.")

# --- LOGIC AUDIT NETWORKING ---
def audit_networking_compliance(selected_profile):
    print(f"{'='*60}")
    print(f"   CIS AWS FOUNDATIONS BENCHMARK v6.0.0 - NETWORKING AUDIT")
    print(f"   (Profile: {selected_profile} | Region: {TARGET_REGION})")
    print(f"{'='*60}\n")

    try:
        session = boto3.Session(profile_name=selected_profile, region_name=TARGET_REGION)
        ec2 = session.client('ec2')
    except Exception as e:
        print(f"[FATAL ERROR] Lỗi kết nối AWS: {e}")
        return

    # --- 1. EBS ENCRYPTION (CIS 6.1.1) ---
    print(">>> 1. KIỂM TRA EBS VOLUME ENCRYPTION (CIS 6.1.1)")
    try:
        status = ec2.get_ebs_encryption_by_default()
        is_enabled = status['EbsEncryptionByDefault']
        if is_enabled:
            print(f" [PASS] EBS Encryption by Default: BẬT (An toàn)")
        else:
            print(f" [FAIL] EBS Encryption by Default: TẮT (Cần bật để mã hóa ổ cứng tạo mới)")
    except Exception as e:
        print(f" [ERROR] Không thể kiểm tra EBS: {e}")

    # --- 2. SECURITY GROUPS (CIS 6.1.2, 6.3, 6.4, 6.5) ---
    print("\n>>> 2. KIỂM TRA SECURITY GROUPS")
    try:
        sgs = ec2.describe_security_groups()['SecurityGroups']
        
        # Bien co theo doi trang thai tung muc
        cis_status = {
            '6.1.2': True, # CIFS (445)
            '6.3': True,   # SSH/RDP IPv4
            '6.4': True,   # SSH/RDP IPv6
            '6.5': True    # Default SG
        }

        for sg in sgs:
            sg_name = sg['GroupName']
            sg_id = sg['GroupId']
            permissions = sg['IpPermissions']
            
            # [CIS 6.5] Check Default SG
            if sg_name == 'default':
                inbound_rules = len(permissions)
                outbound_rules = len(sg['IpPermissionsEgress'])
                if inbound_rules > 0 or outbound_rules > 0:
                    print(f" -> [CIS 6.5] Default SG '{sg_id}': [FAIL] (Đang có rules, nên để trống)")
                    cis_status['6.5'] = False
                continue # Default SG khong can check cac rule khac vi ban than no co rule la da fail 6.5 roi

            # Check Open Ports for 6.1.2, 6.3, 6.4
            for rule in permissions:
                ip_ranges = rule.get('IpRanges', [])     # IPv4
                ipv6_ranges = rule.get('Ipv6Ranges', []) # IPv6
                from_port = rule.get('FromPort', -1)
                to_port = rule.get('ToPort', -1)
                ip_proto = rule.get('IpProtocol')

                # Ham kiem tra xem port co nam trong range rule khong
                def check_port_match(p_check, p_from, p_to, proto):
                    if proto == '-1': return True # All traffic
                    if p_from is None: return False
                    return p_from <= p_check <= p_to

                # [CIS 6.1.2] Check CIFS (445)
                if check_port_match(445, from_port, to_port, ip_proto):
                    is_open_445 = any(r['CidrIp'] == '0.0.0.0/0' for r in ip_ranges) or any(r.get('CidrIpv6') == '::/0' for r in ipv6_ranges)
                    if is_open_445:
                        print(f" -> [CIS 6.1.2] SG '{sg_name}' ({sg_id}): [FAIL] Mở port 445 (CIFS) ra Public")
                        cis_status['6.1.2'] = False

                # [CIS 6.3] Check Admin Ports IPv4 (22, 3389)
                for port in [22, 3389]:
                    if check_port_match(port, from_port, to_port, ip_proto):
                        if any(r['CidrIp'] == '0.0.0.0/0' for r in ip_ranges):
                             port_name = 'SSH' if port == 22 else 'RDP'
                             print(f" -> [CIS 6.3] SG '{sg_name}' ({sg_id}): [FAIL] Mở port {port} ({port_name}) IPv4 ra Public")
                             cis_status['6.3'] = False

                # [CIS 6.4] Check Admin Ports IPv6 (22, 3389)
                for port in [22, 3389]:
                    if check_port_match(port, from_port, to_port, ip_proto):
                        if any(r.get('CidrIpv6') == '::/0' for r in ipv6_ranges):
                             port_name = 'SSH' if port == 22 else 'RDP'
                             print(f" -> [CIS 6.4] SG '{sg_name}' ({sg_id}): [FAIL] Mở port {port} ({port_name}) IPv6 ra Public")
                             cis_status['6.4'] = False

        # In tong hop ket qua
        print(f" [CIS 6.1.2] Chặn CIFS (445) Public: {'[PASS]' if cis_status['6.1.2'] else '[FAIL]'}")
        print(f" [CIS 6.3] Chặn Admin Ports (IPv4): {'[PASS]' if cis_status['6.3'] else '[FAIL]'}")
        print(f" [CIS 6.4] Chặn Admin Ports (IPv6): {'[PASS]' if cis_status['6.4'] else '[FAIL]'}")
        print(f" [CIS 6.5] Default Security Group: {'[PASS]' if cis_status['6.5'] else '[FAIL]'}")

    except Exception as e:
        print(f" [ERROR] Lỗi kiểm tra Security Groups: {e}")

    # --- 3. NACL (CIS 6.2) ---
    print("\n>>> 3. KIỂM TRA NETWORK ACLs (CIS 6.2)")
    try:
        nacls = ec2.describe_network_acls()['NetworkAcls']
        nacl_violation = False
        
        for nacl in nacls:
            nacl_id = nacl['NetworkAclId']
            entries = nacl['Entries']
            
            for rule in entries:
                # Chi check Inbound (Egress=False) va Allow
                if not rule['Egress'] and rule['RuleAction'] == 'allow':
                    cidr = rule.get('CidrBlock')
                    cidr_v6 = rule.get('Ipv6CidrBlock')
                    
                    # Check open public
                    if cidr == '0.0.0.0/0' or cidr_v6 == '::/0':
                        proto = rule['Protocol']
                        port_range = rule.get('PortRange')
                        
                        # Proto -1 (All) hoac TCP/UDP chua cac port 22/3389
                        is_risky = False
                        if proto == '-1':
                            is_risky = True
                        elif port_range:
                            # Check 22 (SSH)
                            if port_range['From'] <= 22 <= port_range['To']: is_risky = True
                            # Check 3389 (RDP)
                            if port_range['From'] <= 3389 <= port_range['To']: is_risky = True
                        
                        if is_risky:
                            print(f" -> NACL '{nacl_id}': [FAIL] Rule #{rule['RuleNumber']} cho phép Admin Ports từ {cidr or cidr_v6}")
                            nacl_violation = True

        if not nacl_violation:
            print(" [PASS] Không có NACL nào cho phép Ingress 0.0.0.0/0 vào cổng quản trị.")
        else:
            print(" [FAIL] Có NACL vi phạm (Xem chi tiết ở trên).")

    except Exception as e:
        print(f" [ERROR] Lỗi kiểm tra NACL: {e}")

    # --- 4. EC2 IMDSv2 (CIS 6.7) ---
    print("\n>>> 4. KIỂM TRA EC2 METADATA (CIS 6.7)")
    try:
        instances = ec2.describe_instances()['Reservations']
        count = 0
        all_pass = True
        for res in instances:
            for ins in res['Instances']:
                if ins['State']['Name'] == 'terminated': continue
                count += 1
                iid = ins['InstanceId']
                name = next((t['Value'] for t in ins.get('Tags', []) if t['Key'] == 'Name'), iid)
                
                meta = ins.get('MetadataOptions', {})
                http_tokens = meta.get('HttpTokens') # 'required' or 'optional'
                
                if http_tokens == 'required':
                    print(f" -> EC2 '{name}': [PASS] IMDSv2 Enabled")
                else:
                    print(f" -> EC2 '{name}': [FAIL] IMDSv1 Enabled (Cần bắt buộc dùng Token)")
                    all_pass = False
        
        if count == 0:
            print(" (Không có EC2 Instance nào đang chạy)")
        elif all_pass:
            print(" [PASS] Tất cả EC2 đều bắt buộc dùng IMDSv2.")

    except Exception as e:
        print(f" [ERROR] Lỗi kiểm tra EC2: {e}")

    # --- 5. VPC PEERING (CIS 6.6 - Manual Check) ---
    print("\n>>> 5. KIỂM TRA VPC PEERING ROUTES (CIS 6.6 - Hỗ trợ)")
    try:
        peerings = ec2.describe_vpc_peering_connections()['VpcPeeringConnections']
        active_peers = [p for p in peerings if p['Status']['Code'] == 'active']
        
        if not active_peers:
            print(" [PASS] Không có VPC Peering Connection nào đang hoạt động.")
        else:
            print(f" [INFO] Tìm thấy {len(active_peers)} kết nối Peering. Đang kiểm tra Route Table...")
            # Liet ke Route Table co duong di qua Peering
            rts = ec2.describe_route_tables()['RouteTables']
            for rt in rts:
                rt_id = rt['RouteTableId']
                for r in rt['Routes']:
                    if r.get('VpcPeeringConnectionId'):
                        dest = r.get('DestinationCidrBlock') or r.get('DestinationIpv6CidrBlock')
                        print(f" -> RouteTable '{rt_id}': Route tới {dest} qua Peering {r['VpcPeeringConnectionId']}")
            print(" (Lưu ý: Hãy kiểm tra thủ công xem các Route trên có tuân thủ nguyên tắc Least Access không)")

    except Exception as e:
        print(f" [ERROR] Lỗi kiểm tra Peering: {e}")

    print(f"\n{'='*60}")
    print("   HOÀN TẤT KIỂM TRA NETWORKING")
    print(f"{'='*60}")

if __name__ == "__main__":
    profiles = get_aws_profiles()
    if not profiles:
        print("Chưa tìm thấy Profile nào trong máy.")
        select_profile([])
    else:
        profile = select_profile(profiles)
        audit_networking_compliance(profile)