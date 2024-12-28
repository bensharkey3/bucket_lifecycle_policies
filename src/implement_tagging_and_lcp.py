import boto3
from botocore.exceptions import ClientError
import json
import os


def create_s3_client() -> boto3.client:
    """creates s3 client with mfa taken"""
    if os.environ.get("AWS_EXECUTION_ENV") is not None:
        s3_client = boto3.client("s3")
        return s3_client

    else:
        session = boto3.Session()
        mfa_serial = session._session.full_config["profiles"]["default"]["mfa_serial"]
        mfa_token = input("Please enter your 6 digit MFA code:")

        sts = session.client("sts")
        MFA_validated_token = sts.get_session_token(
            SerialNumber=mfa_serial, TokenCode=mfa_token
        )

        s3_client = boto3.client(
            "s3",
            aws_session_token=MFA_validated_token["Credentials"]["SessionToken"],
            aws_secret_access_key=MFA_validated_token["Credentials"]["SecretAccessKey"],
            aws_access_key_id=MFA_validated_token["Credentials"]["AccessKeyId"],
        )
        return s3_client


def load_tags_from_config(config_file) -> dict:
    """loads tags for multiple buckets from bucket_tags_config.json and loads the tags as a dict"""
    with open(config_file, "r") as file:
        config_data = json.load(file)

    bucket_tags = {}
    for bucket_name, tags in config_data.items():
        bucket_tags[bucket_name] = [
            {"Key": key, "Value": value} for key, value in tags.items()
        ]
    return bucket_tags


def apply_bucket_tags(s3_client, bucket_name, tags) -> None:
    """apply tags to all buckets in bucket_tags_config.json file. will remove all existing tags"""
    try:
        tag_set = {"TagSet": tags}
        s3_client.put_bucket_tagging(Bucket=bucket_name, Tagging=tag_set)
        print(f"Tags applied successfully to bucket: {bucket_name}")
    except Exception as e:
        print(f"Error applying tags to bucket {bucket_name}: {e}")


def create_lifecycle_policy_tag(s3_client) -> None:
    """create a lifecycle policy tag based on the concat of other tags, will replac eif already exists"""
    allowed_tag_keys = {
        "Environment",
        "FileType",
        "Classification",
        "RetentionCategory",
    }

    try:
        # list all buckets
        buckets = s3_client.list_buckets()["Buckets"]
        print(f"Found {len(buckets)} buckets.")

        for bucket in buckets:
            bucket_name = bucket["Name"]
            print(f"\nProcessing bucket - Create Lifecycle Policy Tag: {bucket_name}")

            try:
                # get existing tags for the bucket
                tags_response = s3_client.get_bucket_tagging(Bucket=bucket_name)
                tag_set = tags_response.get("TagSet", [])

                # filter tags based on allowed keys
                filtered_tags = [
                    tag for tag in tag_set if tag["Key"] in allowed_tag_keys
                ]

                # skip if there are no filtered tags
                if not filtered_tags:
                    print(f"No filtered tags on bucket {bucket_name}. Skipping.")
                    continue

                # sort filtered tags by key in alphabetical order
                sorted_tags = sorted(filtered_tags, key=lambda tag: tag["Key"])

                # concatenate LifecyclePolicyConfig tag values
                concatenated_value = "_".join(f"{tag['Value']}" for tag in sorted_tags)
                print(f"LifecyclePolicyConfig tag value: {concatenated_value}")

                # replace the existing LifecyclePolicyConfig tag if it exists
                updated_tags = [
                    tag for tag in tag_set if tag["Key"] != "LifecyclePolicyConfig"
                ] + [{"Key": "LifecyclePolicyConfig", "Value": concatenated_value}]

                # apply updated tag to the bucket
                s3_client.put_bucket_tagging(
                    Bucket=bucket_name, Tagging={"TagSet": updated_tags}
                )
                print(f"Updated tags applied to bucket {bucket_name}")

            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchTagSet":
                    print(f"No filtered tags found on bucket {bucket_name}. Skipping.")
                else:
                    print(f"Error processing bucket {bucket_name}: {e}")

    except ClientError as e:
        print(f"Error listing buckets: {e}")


def load_lifecycle_configs(config_file) -> dict:
    """loads lifecycle configurations from json file, used within the assign_lifecycle_policies function"""
    with open(config_file, "r") as file:
        return json.load(file)


def apply_lifecycle_policy(s3_client, bucket_name, lifecycle_config) -> None:
    """applies a lifecycle configuration to a bucket, used within the assign_lifecycle_policies function"""
    try:
        s3_client.put_bucket_lifecycle_configuration(
            Bucket=bucket_name, LifecycleConfiguration=lifecycle_config
        )
        print(f"Lifecycle policy applied to bucket: {bucket_name}")
    except ClientError as e:
        print(f"Error applying lifecycle policy to bucket {bucket_name}: {e}")


def assign_lifecycle_policies(s3_client, config_file) -> None:
    """assign lifecycle policies to buckets based on the LifecyclePolicyConfig tag"""
    lifecycle_configs = load_lifecycle_configs(config_file)

    try:
        buckets = s3_client.list_buckets()["Buckets"]
        print(f"Found {len(buckets)} buckets.")

        for bucket in buckets:
            bucket_name = bucket["Name"]
            print(f"\nProcessing bucket - Assign Lifecycle Policy: {bucket_name}")

            try:
                # get tags on the bucket
                tags_response = s3_client.get_bucket_tagging(Bucket=bucket_name)
                tag_set = tags_response.get("TagSet", [])

                # find the LifecyclePolicyConfig tag
                policy_tag = next(
                    (
                        tag["Value"]
                        for tag in tag_set
                        if tag["Key"] == "LifecyclePolicyConfig"
                    ),
                    None,
                )

                # if tag matches a lifecycle config in json file, apply the lifecycle configuration
                if policy_tag and policy_tag in lifecycle_configs:
                    lifecycle_config = lifecycle_configs[policy_tag]
                    apply_lifecycle_policy(s3_client, bucket_name, lifecycle_config)
                else:
                    print(f"No matching lcp tag for bucket: {bucket_name}. Skipping.")

            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchTagSet":
                    print(f"No tags found on bucket {bucket_name}. Skipping.")
                else:
                    print(f"Error processing bucket {bucket_name}: {e}")

    except ClientError as e:
        print(f"Error listing buckets: {e}")


# def get_buckets_missing_tags(s3_client) -> list:
#     """returns a list of bucket names that are missing one or more lifecycle policy tags
#     """
#     print('running func: get_buckets_missing_tags')
#     required_tags = {"Environment", "FileType", "Classification", "RetentionCategory"}
#     buckets_missing_tags = []

#     # Get the list of buckets
#     response = s3_client.list_buckets()
#     bucket_list = [bucket['Name'] for bucket in response.get('Buckets', [])]

#     for bucket in bucket_list:
#         try:
#             tag_response = s3_client.get_bucket_tagging(Bucket=bucket)
#             tags = {tag['Key']: tag['Value'] for tag in tag_response.get('TagSet', [])}
#         except s3_client.exceptions.ClientError as e:
#             if e.response['Error']['Code'] == 'NoSuchTagSet':
#                 tags = {}
#             else:
#                 raise

#         if not required_tags.issubset(tags.keys()):
#             buckets_missing_tags.append(bucket)
#     return buckets_missing_tags


# def write_buckets_missing_tags_to_file_in_s3(s3_client, buckets_missing_tags) -> None:
#     """writes a file to s3 containing the list of buckets that dont have tags
#     """
#     print('running func: write_buckets_missing_tags_to_file_in_s3')

#     data_str = '\n'.join(buckets_missing_tags)
#     timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
#     filename = f'buckets_without_lifecycle_tags/bucket_list_{timestamp}.txt'

#     # upload file to s3
#     s3_client.put_object(Bucket=bucket_name, Key=filename, Body=data_str)


def main():
    s3_client = create_s3_client()

    bucket_tags_config_file = os.path.join(
        os.path.dirname(__file__), "bucket_tags_config.json"
    )
    bucket_tags = load_tags_from_config(config_file=bucket_tags_config_file)
    for bucket_name, tags in bucket_tags.items():
        apply_bucket_tags(s3_client, bucket_name, tags)

    create_lifecycle_policy_tag(s3_client)

    lifecycle_config_file = os.path.join(
        os.path.dirname(__file__), "lifecycle_config.json"
    )
    assign_lifecycle_policies(s3_client, lifecycle_config_file)

    # buckets_missing_tags = get_buckets_missing_tags(s3_client)
    # write_buckets_missing_tags_to_file_in_s3(s3_client, buckets_missing_tags)


# if __name__ == '__main__':
#     main()


def lambda_handler(event, context):
    main()
