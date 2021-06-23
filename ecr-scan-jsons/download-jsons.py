import boto3
import os
import json  
import datetime

client = boto3.client('ecr', region_name = 'us-west-2')

ecr_images = [
    {
        "repositoryName": "pr-pytorch-training",
        "imageTag": "1.8.1-cpu-py36-ubuntu18.04-pr-1177-2021-06-23-02-22-32"
    },
    {
        "repositoryName": "pr-tensorflow-training",
        "imageTag": "2.4.1-cpu-py37-ubuntu18.04-pr-1177-2021-06-23-02-22-38"
    },
    {
        "repositoryName": "pr-mxnet-training",
        "imageTag": "1.8.0-cpu-py37-ubuntu16.04-pr-1177-2021-06-23-02-22-31"
    }
]

existing_files_in_folder = os.listdir()
json_extracted = 0

def myconverter(o):
    if isinstance(o, datetime.datetime):
        return o.__str__()


def get_image_scan_findings(ecr_client=client, repoName=None, imgId=None):
    return ecr_client.describe_image_scan_findings(
        repositoryName=repoName, 
        imageId=imgId
    )

def get_package_name(finding):
    for attribute in finding["attributes"]:
        if attribute['key'] == 'package_name':
            return attribute['value']

def get_untrimmed_ignore_dict(original_scan_findings):
    medium_finding_count = 0
    result_dict = {}
    for finding in original_scan_findings["imageScanFindings"]["findings"]:
        if finding["severity"] == "MEDIUM":
            medium_finding_count += 1
            package_name = get_package_name(finding)
            if package_name not in result_dict:
                result_dict[package_name] = []
            result_dict[package_name].append(finding)
    return result_dict

    print(medium_finding_count)

for image in ecr_images:
    filename = f"{image['repositoryName']}-{image['imageTag']}.json"
    if filename in existing_files_in_folder:
        continue

    scan_findings = get_image_scan_findings(
        ecr_client=client, 
        repoName=image['repositoryName'], 
        imgId={"imageTag": image['imageTag']})

    with open(filename, "w") as outfile: 
        json.dump(scan_findings, outfile, indent=4, default=myconverter)
    json_extracted += 1

    untrimmed_ignore_dict = get_untrimmed_ignore_dict(scan_findings)
    ignore_json_filename = f"./untrimmed-ignore-jsons/{image['repositoryName']}-{image['imageTag']}-ignore.json"

    with open(ignore_json_filename, "w") as outfile: 
        json.dump(untrimmed_ignore_dict, outfile, indent=4, default=myconverter)


print(f"Extracted Json Count = {json_extracted}")