package hipaa.s3_public_access_block_test

import data.hipaa.s3_public_access_block

test_pass_all_blocked {
  count(s3_public_access_block.deny) == 0 with input as {
    "resource_changes": [{
      "address": "aws_s3_bucket_public_access_block.uploads",
      "type":    "aws_s3_bucket_public_access_block",
      "change":  {
        "actions": ["create"],
        "after": {
          "bucket":                  "my-phi-bucket",
          "block_public_acls":       true,
          "block_public_policy":     true,
          "ignore_public_acls":      true,
          "restrict_public_buckets": true,
        },
      },
    }],
  }
}

test_fail_public_acls_not_blocked {
  count(s3_public_access_block.deny) == 1 with input as {
    "resource_changes": [{
      "address": "aws_s3_bucket_public_access_block.bad",
      "type":    "aws_s3_bucket_public_access_block",
      "change":  {
        "actions": ["create"],
        "after": {
          "bucket":                  "bad-bucket",
          "block_public_acls":       false,
          "block_public_policy":     true,
          "ignore_public_acls":      true,
          "restrict_public_buckets": true,
        },
      },
    }],
  }
}

# ─────────────────────────────────────────────────────────────────────────────
package hipaa.kms_key_rotation_test

import data.hipaa.kms_key_rotation

test_pass_rotation_enabled {
  count(kms_key_rotation.deny) == 0 with input as {
    "resource_changes": [{
      "address": "aws_kms_key.phi",
      "type":    "aws_kms_key",
      "change":  {
        "actions": ["create"],
        "after": { "enable_key_rotation": true },
      },
    }],
  }
}

test_fail_rotation_disabled {
  count(kms_key_rotation.deny) == 1 with input as {
    "resource_changes": [{
      "address": "aws_kms_key.bad",
      "type":    "aws_kms_key",
      "change":  {
        "actions": ["create"],
        "after": { "enable_key_rotation": false },
      },
    }],
  }
}

# ─────────────────────────────────────────────────────────────────────────────
package hipaa.lambda_vpc_test

import data.hipaa.lambda_vpc

test_pass_lambda_in_vpc {
  count(lambda_vpc.deny) == 0 with input as {
    "resource_changes": [{
      "address": "aws_lambda_function.intake",
      "type":    "aws_lambda_function",
      "change":  {
        "actions": ["create"],
        "after": {
          "function_name": "intake",
          "vpc_config": [{
            "subnet_ids":         ["subnet-aaa", "subnet-bbb"],
            "security_group_ids": ["sg-111"],
          }],
        },
      },
    }],
  }
}

test_fail_lambda_no_vpc {
  count(lambda_vpc.deny) >= 1 with input as {
    "resource_changes": [{
      "address": "aws_lambda_function.intake",
      "type":    "aws_lambda_function",
      "change":  {
        "actions": ["create"],
        "after": {
          "function_name": "intake",
          "vpc_config":    [],
        },
      },
    }],
  }
}

# ─────────────────────────────────────────────────────────────────────────────
package hipaa.cloudtrail_integrity_test

import data.hipaa.cloudtrail_integrity

test_pass_trail_valid {
  count(cloudtrail_integrity.deny) == 0 with input as {
    "resource_changes": [{
      "address": "aws_cloudtrail.mgmt",
      "type":    "aws_cloudtrail",
      "change":  {
        "actions": ["create"],
        "after": {
          "enable_log_file_validation": true,
          "is_multi_region_trail":      true,
        },
      },
    }],
  }
}

test_fail_no_log_validation {
  count(cloudtrail_integrity.deny) >= 1 with input as {
    "resource_changes": [{
      "address": "aws_cloudtrail.bad",
      "type":    "aws_cloudtrail",
      "change":  {
        "actions": ["create"],
        "after": {
          "enable_log_file_validation": false,
          "is_multi_region_trail":      true,
        },
      },
    }],
  }
}

test_fail_single_region {
  count(cloudtrail_integrity.deny) >= 1 with input as {
    "resource_changes": [{
      "address": "aws_cloudtrail.bad2",
      "type":    "aws_cloudtrail",
      "change":  {
        "actions": ["create"],
        "after": {
          "enable_log_file_validation": true,
          "is_multi_region_trail":      false,
        },
      },
    }],
  }
}
