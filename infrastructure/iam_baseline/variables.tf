variable "aws_region" {
  description = "AWS Region dung de trien khai tai nguyen (Vi du: us-east-1)"
  type        = string
  default     = "ap-southeast-1"
}

variable "aws_profile" {
  description = "Ten AWS Profile duoc cau hinh trong file credentials"
  type        = string
}