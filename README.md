# Goal
Detect new publicly accessible S3 buckets.

# Categorization
These detections are are categorized as [Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/).

# Strategy Abstract
The strategy will function as follows: 

* Monitor the “PutBucketPolicy” API call from CloudTrail events on a schedule.
* Alert on the AllUsers and AuthenticatedUsers filter.
* Since the dataset for GUI and CLI yields different values, two separate rules had to be created.

# Technical Context
Amazon S3 is a highly scalable cloud storage service that can be used to store and retrieve any amount of data, at any time, from anywhere on the web. Organizations tend to store huge amounts of data from web applications and mobile apps making this an attractive target for adversaries. 

Monitoring sensitive API calls against S3 buckets in addition to using a configuration checker tool is needed to gain complete visibility over the this ADS. 

# Blind Spots and Assumptions
This strategy relies on the following assumptions: 

* CloudTrail logging is turned on.
* CloudTrail data is available at scheduled time of the detection (latency etc.).

A blind spot will occur if any of the assumptions are violated. For instance, the following would result in a false negative:
* CloudTrail logging is disabled during the time when the public was made public.

# False Positives
The detection does not have any known false positives, however, it is possible the bucket was made public for legitimate reasons (see below) even though the action violates AWS best practices:

* Cloud engineer was testing a dev tool and closes the public permissions within shortly afterwards.
* Cloud engineer needed to share bucket objects with trusted entities outside the account and makes the bucket public for a few days. A [presigned URL with S3](https://docs.aws.amazon.com/AmazonS3/latest/dev/ShareObjectPreSignedURL.html) should have been used.


# Priority
The priority is set to high under all conditions.

# Validation
Validation can occur for this ADS by running the detector against the data set provided.

# Response
In the event that this alert fires, the following response procedures are recommended:

* Determine the severity by contextualizing AWS account, bucket, and the permission. If production account bucket with customer data is made public READ and WRITE access, severity would be critical. 
* Analyze the CloudTrail event to determine if this was authorized activity.
* Determine if the API call source was authorized to perform this action. If the source has no previous history of invoking this API and relation to S3 service, there may be a user compromise. 
* Determine if this bucket should be public. Remediate public permissions as soon as possible to limit data leakage.
* Determine if data loss occurred by reviewing S3 Access Logs for the bucket during the duration public was available publicly.
* Discuss hardening solutions to prevent this happening in the future. See [Configuring block public access settings for your account](https://docs.aws.amazon.com/AmazonS3/latest/userguide/configuring-block-public-access-account.html) for more details.
* Implement auto-remediation. Here's an example using [AWS Config](https://aws.amazon.com/blogs/mt/aws-config-auto-remediation-s3-compliance/)

# Additional Resources

* [Remediating a Compromised S3 Bucket](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-s3)
* [S3 Security best practices](https://docs.aws.amazon.com/AmazonS3/latest/dev/security-best-practices.html)
