# Demo Infrastructure with Security Issues
# This file contains intentional vulnerabilities for the AutoMCP demo
# The pipeline will detect and fix these automatically

resource "aws_security_group" "demo" {
  name_prefix = "demo-sg"
  description = "Security group for demo - INSECURE: Allows all traffic"

  # ISSUE 1: Overly permissive ingress rule (will be fixed to 10.0.0.0/8)
  ingress {
    description = "Allow all inbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

#tmp
  # ISSUE 2: Overly permissive egress (this is actually okay for egress, but demo focuses on ingress)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # ISSUE 3: Missing mandatory tags
  # The AI fix will add: Environment = "dev", Project = "demo"
  # Uncomment these to see the demo work (no issues found)
  # tags = {
  #   Environment = "dev"
  #   Project     = "demo"
  # }
}

# Optional: S3 bucket without encryption (for extended demo)
resource "aws_s3_bucket" "demo" {
  bucket = "hackathon-demo-bucket-${random_id.suffix.hex}"

  # ISSUE 4: Server-side encryption not enabled by default
  # The demo will suggest adding server_side_encryption_configuration
}

resource "random_id" "suffix" {
  byte_length = 4
}

# Demo EC2 instance with missing security best practices
resource "aws_instance" "demo" {
  ami           = "ami-12345678"  # Placeholder AMI
  instance_type = "t2.micro"

  security_groups = [aws_security_group.demo.name]

  # ISSUE 5: Missing common tags like Environment
  # Will be auto-tagged
}

# tmp
