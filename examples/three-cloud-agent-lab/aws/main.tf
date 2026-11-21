terraform {
  required_version = ">= 1.6"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.80" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "image" {
  description = "The shared lab image, pinned by digest: docker.io/<org>/<repo>@sha256:<digest>."
  type        = string
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { purpose = "agent-bom-lab", ttl = "destroy-same-day" }
  }
}

resource "random_id" "suffix" {
  byte_length = 3
}

locals {
  name = "abom-lab-${random_id.suffix.hex}"
}

# Planted: "training data" bucket readable by anyone.
resource "aws_s3_bucket" "training" {
  bucket        = "${local.name}-training-data"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "training" {
  bucket                  = aws_s3_bucket.training.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "public_read" {
  bucket     = aws_s3_bucket.training.id
  depends_on = [aws_s3_bucket_public_access_block.training]
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.training.arn}/*"
    }]
  })
}

data "aws_iam_policy_document" "ecs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

# Planted: the agent's task role can do anything to any bucket.
resource "aws_iam_role" "agent" {
  name               = "${local.name}-agent"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_iam_role_policy" "agent_s3_all" {
  role = aws_iam_role.agent.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "s3:*", Resource = "*" }]
  })
}

resource "aws_iam_role" "execution" {
  name               = "${local.name}-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

resource "aws_security_group" "agent" {
  name   = "${local.name}-agent"
  vpc_id = data.aws_vpc.default.id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ecs_cluster" "lab" {
  name = local.name
}

resource "aws_ecs_task_definition" "agent" {
  family                   = "${local.name}-agent"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  task_role_arn            = aws_iam_role.agent.arn
  execution_role_arn       = aws_iam_role.execution.arn
  container_definitions = jsonencode([{
    name      = "agent"
    image     = var.image
    essential = true
    # Planted: a model key in plain environment configuration (placeholder value).
    environment = [
      { name = "OPENAI_API_KEY", value = "lab-placeholder-not-a-real-key" },
      { name = "TRAINING_BUCKET", value = aws_s3_bucket.training.bucket },
    ]
  }])
}

resource "aws_ecs_service" "agent" {
  name            = "agent"
  cluster         = aws_ecs_cluster.lab.id
  task_definition = aws_ecs_task_definition.agent.arn
  desired_count   = 1
  launch_type     = "FARGATE"
  network_configuration {
    subnets          = data.aws_subnets.default.ids
    security_groups  = [aws_security_group.agent.id]
    assign_public_ip = true
  }
}

output "cluster" {
  value = aws_ecs_cluster.lab.name
}

output "training_bucket" {
  value = aws_s3_bucket.training.bucket
}
