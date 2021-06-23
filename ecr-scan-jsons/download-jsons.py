import boto3
import os
import json  
import datetime

client = boto3.client('ecr', region_name = 'us-west-2')

ecr_images = [
    {
        "repositoryName": '',
        "imageTag": ''
    }
]

existing_files_in_folder = os.listdir()
json_extracted = 0

def myconverter(o):
    if isinstance(o, datetime.datetime):
        return o.__str__()


for image in ecr_images:
    filename = f"{image['repositoryName']}-{image['imageTag']}.json"
    if filename in existing_files_in_folder:
        continue

    result = client.describe_image_scan_findings(
        repositoryName=image['repositoryName'], 
        imageId={"imageTag": image['imageTag']}
    )

    with open(filename, "w") as outfile: 
        json.dump(result, outfile, indent=4, default=myconverter)
    json_extracted += 1

print(f"Extracted Json Count = {json_extracted}")