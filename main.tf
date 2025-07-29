#Sends emails when notified by CloudWatch alarms.

resource "aws_sns_topic" "console_login_alerts" {
  name = "console-login-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.console_login_alerts.arn
  protocol  = "email"
  endpoint  = "brajesh540@gmail.com" # Change to your team's email address
}
#Enable and Configure AWS CloudTrail
#Records all management events (including ConsoleLogin) in all regions.

resource "aws_s3_bucket" "cloudtrail" {
  bucket = "my-cloudtrail-logs-bucket-brajesh"

}

resource "aws_s3_bucket_acl" "cloudtrail_acl" {
  bucket = aws_s3_bucket.cloudtrail.id
  acl    = "private"
}
resource "aws_cloudtrail" "main" {
  name                          = "main"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true
  depends_on                    = [aws_s3_bucket.cloudtrail]
  cloud_watch_logs_group_arn  = aws_cloudwatch_log_group.cloudtrail.arn
  cloud_watch_logs_role_arn   = aws_iam_role.cloudtrail_to_cw.arn
}

#Send CloudTrail Logs to CloudWatch Logs
#Allows metric filters and alarms to be used.

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name = "/aws/cloudtrail/logs"
}

resource "aws_iam_role" "cloudtrail_to_cw" {
  name = "cloudtrail-to-cloudwatch"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_role.json
}

data "aws_iam_policy_document" "cloudtrail_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "cloudtrail_to_cw_policy" {
  name = "cloudtrail-to-cw-policy"
  role = aws_iam_role.cloudtrail_to_cw.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Effect   = "Allow"
        Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
      }
    ]
  })
}
#Create a CloudWatch Log Metric Filter for Console Login Success
#Detects successful AWS Console logins from CloudTrail logs.

resource "aws_cloudwatch_log_metric_filter" "console_login_success" {
  name           = "console-login-success"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ ($.eventName = \"ConsoleLogin\") && ($.responseElements.ConsoleLogin = \"Success\") }"

  metric_transformation {
    name      = "ConsoleLoginSuccessCount"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}
#Create a CloudWatch Alarm Triggered by Login Events
#Alarm triggers on metric indicating a successful login.

resource "aws_cloudwatch_metric_alarm" "console_login_alarm" {
  alarm_name          = "ConsoleLoginSuccessAlarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = aws_cloudwatch_log_metric_filter.console_login_success.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.console_login_success.metric_transformation[0].namespace
  period              = 300
  statistic           = "Sum"
  threshold           = 1

  alarm_description = "Alarm for successful AWS Console logins."
  actions_enabled   = true
  alarm_actions     = [aws_sns_topic.console_login_alerts.arn]
}