# Tự động hóa Bảo mật AWS: CIS Foundations Benchmark v6.0.0

![AWS](https://img.shields.io/badge/AWS-%23FF9900.svg?style=for-the-badge&logo=amazon-aws&logoColor=white)
![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![Terraform](https://img.shields.io/badge/terraform-%235835CC.svg?style=for-the-badge&logo=terraform&logoColor=white)
![Security](https://img.shields.io/badge/Security-DevSecOps-blue)

## 📌 Tổng quan Dự án
Dự án này triển khai một bộ khung (framework) đánh giá và khắc phục bảo mật tự động cho môi trường Amazon Web Services (AWS), tuân thủ nghiêm ngặt bộ tiêu chuẩn bảo mật quốc tế **CIS Amazon Web Services Foundations Benchmark v6.0.0**.

Mục tiêu chính của dự án là giảm thiểu bề mặt tấn công, ngăn chặn các lỗi cấu hình sai sót phổ biến trên đám mây, đồng thời đảm bảo tính Bí mật, Toàn vẹn và Sẵn sàng (CIA) của hệ thống tài nguyên.

## 🏗 Kiến trúc & Phương pháp thực hiện
Thay vì phụ thuộc vào một công cụ duy nhất, dự án áp dụng phương pháp **Tự động hóa Đa lớp (Hybrid Multi-Layer Automation)** nhằm bao quát toàn bộ vòng đời bảo mật:

1. **Lớp Kiểm tra (Assessment/Audit):** * Sử dụng kịch bản **Python (Boto3)** và **AWS CLI** để truy vấn API của AWS nhằm xác định trạng thái tuân thủ (Đạt/Vi phạm) của từng dịch vụ.
2. **Lớp Khắc phục (Remediation):** * Áp dụng **Terraform (Infrastructure as Code - IaC)** để khai báo và áp đặt các cấu hình bảo mật nền tảng (ví dụ: bật CloudTrail, mã hóa EBS mặc định).
   * Kết hợp các kịch bản **Python/Boto3** để chủ động sửa các lỗi cấu hình cụ thể chưa được quản lý bởi IaC.
3. **Lớp Giám sát liên tục (Continuous Monitoring):** * Tích hợp **AWS Config Rules** và **CloudWatch Alarms** (dựa trên CloudTrail logs) để tự động phát hiện và cảnh báo theo thời gian thực về các thay đổi cấu hình bất thường.

## 🚀 Tính năng nổi bật & Phạm vi
Hệ thống tự động hóa bao phủ cả hai cấp độ bảo mật Level 1 (Cơ bản) và Level 2 (Nâng cao) trải dài trên 5 nhóm dịch vụ cốt lõi của AWS:

* **Quản lý Danh tính & Truy cập (IAM):** Thiết lập chính sách mật khẩu, bắt buộc sử dụng MFA, bảo vệ tài khoản Root, và dọn dẹp các khóa truy cập/chứng danh cũ.
* **Lưu trữ (S3, RDS, EFS):** Bắt buộc mã hóa dữ liệu tại chỗ (Encryption-at-rest), tự động chặn truy cập công khai (Block Public Access), và phân loại dữ liệu nhạy cảm bằng Macie.
* **Ghi nhật ký (Logging):** Cấu hình CloudTrail tập trung toàn vùng, kích hoạt Server Access Logging cho S3, và bật xác thực tệp nhật ký.
* **Giám sát (Monitoring):** Tự động tạo CloudWatch Metric Filters và Alarms cho các lệnh gọi API quan trọng và các lần xác thực Console thất bại.
* **Mạng (Networking):** Kích hoạt VPC Flow Logs, loại bỏ các quy tắc Inbound không giới hạn (0.0.0.0/0) cho cổng SSH/RDP, và bắt buộc sử dụng IMDSv2 cho máy chủ EC2.

## 🛠 Công nghệ sử dụng
* **Nền tảng đám mây:** Amazon Web Services (AWS)
* **Ngôn ngữ Lập trình & Thư viện:** Python 3.x, SDK Boto3
* **Giao diện Dòng lệnh:** AWS CLI v2
* **Cơ sở hạ tầng dưới dạng mã (IaC):** Terraform

## 📊 Kết quả Dự án
Dự án đã triển khai thành công việc kiểm toán và khắc phục tự động theo các tiêu chuẩn của CIS Benchmark với kết quả cụ thể như sau:
* **Tỷ lệ tự động hóa quá trình Kiểm tra (Audit):** 63/63 khuyến nghị (Đạt 100%).
* **Tỷ lệ tự động hóa quá trình Khắc phục (Remediation):** 61/63 khuyến nghị (Đạt ~96%).

## ⚙️ Hướng dẫn Cài đặt & Chạy thử nghiệm

### Điều kiện tiên quyết
* Đã cài đặt AWS CLI v2 và cấu hình thông tin xác thực (`aws configure`) với quyền IAM phù hợp.
* Đã cài đặt Python 3.x và thư viện `boto3`.
* Đã cài đặt Terraform (dành cho lớp khắc phục tự động).

### Cách thức sử dụng

```bash
# Ví dụ: Chạy kịch bản kiểm tra tự động cho IAM
python src/audit/section_2_iam/audit_iam_compliance.py

# Ví dụ: Chạy kịch bản khắc phục tự động cho IAM
python src/remediation/iam_remediation_tool.py


