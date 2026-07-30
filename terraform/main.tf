terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  default = "ap-south-1"
}

variable "alert_email" {
  description = "Email address subscribed to the CloudShield SNS alert topic"
  type        = string
}

# --- SNS topic for real-time alerts ---
resource "aws_sns_topic" "cloudshield_alerts" {
  name = "cloudshield-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.cloudshield_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# --- Lambda execution role ---
resource "aws_iam_role" "lambda_exec" {
  name = "cloudshield-lambda-exec"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "lambda_sns_publish" {
  name = "cloudshield-lambda-sns-publish"
  role = aws_iam_role.lambda_exec.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["sns:Publish"]
      Resource = aws_sns_topic.cloudshield_alerts.arn
    }]
  })
}

# --- Lambda function ---
# Build the zip with: cd lambda && zip -r ../lambda.zip .
resource "aws_lambda_function" "detector" {
  function_name    = "cloudshield-detector"
  role              = aws_iam_role.lambda_exec.arn
  handler           = "lambda_function.handler"
  runtime           = "python3.12"
  filename          = "../lambda.zip"
  source_code_hash  = filebase64sha256("../lambda.zip")
  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.cloudshield_alerts.arn
    }
  }
}

# --- EventBridge rule -> Lambda target ---
resource "aws_cloudwatch_event_rule" "security_events" {
  name = "cloudshield-security-events"
  event_pattern = jsonencode({
    source = ["aws.cloudtrail"]
    detail = {
      eventName = [
        "ConsoleLogin", "CreateUser", "DeleteUser",
        "AttachUserPolicy", "CreateAccessKey",
        "StopInstances", "DeleteBucket"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  rule = aws_cloudwatch_event_rule.security_events.name
  arn  = aws_lambda_function.detector.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.security_events.arn
}

output "sns_topic_arn" {
  value = aws_sns_topic.cloudshield_alerts.arn
}
