"""
Copyright 2019-2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License"). You
may not use this file except in compliance with the License. A copy of
the License is located at

    http://aws.amazon.com/apache2.0/

or in the "license" file accompanying this file. This file is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.
"""
import os
import re
import json
import logging
import sys
import boto3
import constants

from botocore.exceptions import ClientError
from invoke.context import Context

from codebuild_environment import get_cloned_folder_path
from config import is_build_enabled
from safety_report_generator import SafetyReportGenerator

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)
LOGGER.addHandler(logging.StreamHandler(sys.stdout))
LOGGER.addHandler(logging.StreamHandler(sys.stderr))


def download_s3_file(bucket_name, filepath, local_file_name):
    """

    :param bucket_name: string
    :param filepath: string
    :param local_file_name: string
    :return:
    """
    _s3 = boto3.Session().resource("s3")

    try:
        _s3.Bucket(bucket_name).download_file(filepath, local_file_name)
    except ClientError as e:
        LOGGER.error("Error: Cannot read file from s3 bucket.")
        LOGGER.error("Exception: {}".format(e))
        raise


def download_file(remote_url: str, link_type: str):
    """
    Fetch remote files and save with provided local_path name
    :param link_type: string
    :param remote_url: string
    :return: file_name: string
    """
    LOGGER.info(f"Downloading {remote_url}")

    file_name = os.path.basename(remote_url).strip()
    LOGGER.info(f"basename: {file_name}")

    if link_type in ["s3"] and remote_url.startswith("s3://"):
        match = re.match(r"s3:\/\/(.+?)\/(.+)", remote_url)
        if match:
            bucket_name = match.group(1)
            bucket_key = match.group(2)
            LOGGER.info(f"bucket_name: {bucket_name}")
            LOGGER.info(f"bucket_key: {bucket_key}")
            download_s3_file(bucket_name, bucket_key, file_name)
        else:
            raise ValueError(f"Regex matching on s3 URI failed.")
    else:
        ctx = Context()
        ctx.run(f"curl -O {remote_url}")

    return file_name


def build_setup(framework, device_types=[], image_types=[], py_versions=[]):
    """
    Setup the appropriate environment variables depending on whether this is a PR build
    or a dev build

    Parameters:
        framework: str
        device_types: [str]
        image_types: [str]
        py_versions: [str]

    Returns:
        None
    """

    # Set necessary environment variables
    to_build = {
        "device_types": constants.DEVICE_TYPES,
        "image_types": constants.IMAGE_TYPES,
        "py_versions": constants.PYTHON_VERSIONS,
    }
    build_context = os.environ.get("BUILD_CONTEXT")
    enable_build = is_build_enabled()

    if build_context == "PR":
        pr_number = os.getenv("PR_NUMBER")
        LOGGER.info(f"pr number: {pr_number}")

    if device_types:
        to_build["device_types"] = constants.DEVICE_TYPES.intersection(set(device_types))

    if image_types:
        to_build["image_types"] = constants.IMAGE_TYPES.intersection(set(image_types))

    if py_versions:
        to_build["py_versions"] = constants.PYTHON_VERSIONS.intersection(set(py_versions))

    for device_type in to_build["device_types"]:
        for image_type in to_build["image_types"]:
            for py_version in to_build["py_versions"]:
                env_variable = f"{framework.upper()}_{device_type.upper()}_{image_type.upper()}_{py_version.upper()}"
                if enable_build or build_context != "PR":
                    os.environ[env_variable] = "true"


def fetch_dlc_images_for_test_jobs(images, use_latest_additional_tag=False):
    """
    use the JobParamters.run_test_types values to pass on image ecr urls to each test type.
    :param images: list
    :return: dictionary
    """
    DLC_IMAGES = {"sagemaker": [], "ecs": [], "eks": [], "ec2": [], "sanity": [], "autopr": []}

    build_enabled = is_build_enabled()

    for docker_image in images:
        if not docker_image.is_test_promotion_enabled:
            continue
        use_preexisting_images = (
            not build_enabled
        ) and docker_image.build_status == constants.NOT_BUILT
        if docker_image.build_status == constants.SUCCESS or use_preexisting_images:
            ecr_url_to_test = docker_image.ecr_url
            if use_latest_additional_tag and len(docker_image.additional_tags) > 0:
                ecr_url_to_test = f"{docker_image.repository}:{docker_image.additional_tags[-1]}"

            # Set up tests on all platforms
            for test_platform in DLC_IMAGES:
                DLC_IMAGES[test_platform].append(ecr_url_to_test)

    for test_type in DLC_IMAGES:
        test_images = DLC_IMAGES[test_type]
        if test_images:
            DLC_IMAGES[test_type] = list(set(test_images))
    return DLC_IMAGES


def write_to_json_file(file_name, content):
    with open(file_name, "w") as fp:
        json.dump(content, fp)


def set_test_env(images, use_latest_additional_tag=False, images_env="DLC_IMAGES", **kwargs):
    """
    Util function to write a file to be consumed by test env with necessary environment variables

    ENV variables set by os do not persist, as a new shell is instantiated for post_build steps

    :param images: List of image objects
    :param images_env: Name for the images environment variable
    :param env_file: File to write environment variables to
    :param kwargs: other environment variables to set
    """
    test_envs = []

    test_images_dict = fetch_dlc_images_for_test_jobs(
        images, use_latest_additional_tag=use_latest_additional_tag
    )

    # dumping the test_images to dict that can be used in src/start_testbuilds.py
    write_to_json_file(constants.TEST_TYPE_IMAGES_PATH, test_images_dict)

    LOGGER.debug(f"Utils Test Type Images: {test_images_dict}")

    if kwargs:
        for key, value in kwargs.items():
            test_envs.append({"name": key, "value": value, "type": "PLAINTEXT"})

    write_to_json_file(constants.TEST_ENV_PATH, test_envs)


def get_safety_scan_allowlist_path(image_uri):
    """
    Retrieves the safety_scan_allowlist_path for each image_uri.

    :param image_uri: str, consists of f"{image_repo}:{image_tag}"
    :return: string, safety scan allowlist path for the image
    """
    from test.test_utils import get_ecr_scan_allowlist_path

    os_scan_allowlist_path = get_ecr_scan_allowlist_path(image_uri)
    safety_scan_allowlist_path = os_scan_allowlist_path.replace(".os_", ".py_")
    return safety_scan_allowlist_path


def get_safety_ignore_dict_from_image_specific_safety_allowlists(image_uri):
    """
    Image specific safety allowlists exist parallel to the os_scan_allowlists and allow us to allowlist vulnerabilities
    in a more granular way. This method helps fetch the contents of the image specific allowlist and ignore them during
    safety scans.

    :param image_uri: str, consists of f"{image_repo}:{image_tag}"
    :return: dict[str,str], image specific safety scan allowlist which is a key-value pair of "vulnerability_id" and "reason"
    """
    safety_scan_allowlist_path = get_safety_scan_allowlist_path(image_uri)
    if not os.path.exists(safety_scan_allowlist_path):
        LOGGER.info(
            f"No image specific safety scan allowlist found at {safety_scan_allowlist_path}"
        )
        return {}
    with open(safety_scan_allowlist_path, "r") as f:
        ignore_dict_from_image_specific_allowlist = json.load(f)
    return ignore_dict_from_image_specific_allowlist


def get_safety_ignore_dict(image_uri, framework, python_version, job_type):
    """
    Get a dict of known safety check issue IDs to ignore, if specified in file ../data/ignore_ids_safety_scan.json.

    :param image_uri: str, consists of f"{image_repo}:{image_tag}"
    :param framework: str, framework like tensorflow, mxnet etc.
    :param python_version: str, py2 or py3
    :param job_type: str, type of training job. Can be "training"/"inference"
    :return: dict, key is the ignored vulnerability id and value is the reason to ignore it
    """
    if job_type == "inference":
        job_type = (
            "inference-eia"
            if "eia" in image_uri
            else "inference-neuron"
            if "neuron" in image_uri
            else "inference"
        )

    if job_type == "training":
        job_type = (
            "training-neuronx"
            if "neuronx" in image_uri
            else "training-neuron"
            if "neuron" in image_uri
            else "training"
        )

    if "habana" in image_uri:
        framework = f"habana_{framework}"

    if "graviton" in image_uri:
        framework = f"graviton_{framework}"

    ignore_data_file = os.path.join(
        os.sep, get_cloned_folder_path(), "data", "ignore_ids_safety_scan.json"
    )
    with open(ignore_data_file) as f:
        ignore_safety_ids = json.load(f)
    ignore_dict = ignore_safety_ids.get(framework, {}).get(job_type, {}).get(python_version, {})

    ## Find common vulnerabilites and add it to the ignore dict
    common_ignore_list_file = os.path.join(
        os.sep, get_cloned_folder_path(), "data", "common-safety-ignorelist.json"
    )
    with open(common_ignore_list_file) as f:
        common_ids_to_ignore = json.load(f)
    for common_id, reason in common_ids_to_ignore.items():
        if common_id not in ignore_dict:
            ignore_dict[common_id] = reason

    ignore_dict_from_image_specific_allowlist = (
        get_safety_ignore_dict_from_image_specific_safety_allowlists(image_uri)
    )
    ignore_dict.update(ignore_dict_from_image_specific_allowlist)
    return ignore_dict


def generate_safety_report_for_image(image_uri, image_info, storage_file_path=None):
    """
    Generate safety scan reports for an image and store it at the location specified

    :param image_uri: str, consists of f"{image_repo}:{image_tag}"
    :param image_info: dict, should consist of 3 keys - "framework", "python_version" and "image_type".
    :param storage_file_path: str, looks like "storage_location.json"
    :return: list[dict], safety report generated by SafetyReportGenerator
    """
    ctx = Context()
    docker_run_cmd = f"docker run -id --entrypoint='/bin/bash' {image_uri} "
    container_id = ctx.run(f"{docker_run_cmd}", hide=True, warn=True).stdout.strip()
    install_safety_cmd = "pip install 'safety>=2.2.0'"
    docker_exec_cmd = f"docker exec -i {container_id}"
    ctx.run(f"{docker_exec_cmd} {install_safety_cmd}", hide=True, warn=True)
    ignore_dict = get_safety_ignore_dict(
        image_uri, image_info["framework"], image_info["python_version"], image_info["image_type"]
    )
    safety_report_generator_object = SafetyReportGenerator(container_id, ignore_dict=ignore_dict)
    safety_scan_output = safety_report_generator_object.generate()
    ctx.run(f"docker rm -f {container_id}", hide=True, warn=True)
    if storage_file_path:
        with open(storage_file_path, "w", encoding="utf-8") as f:
            json.dump(safety_scan_output, f, indent=4)
    if is_APatch_build():
        ignore_dict_from_image_specific_allowlist = (
            get_safety_ignore_dict_from_image_specific_safety_allowlists(image_uri)
        )
        future_ignore_dict = ignore_dict_from_image_specific_allowlist
        if safety_report_generator_object.new_ignored_vulnerabilities:
            future_ignore_dict.update(safety_report_generator_object.new_ignored_vulnerabilities)
            LOGGER.info(
                f"[Safety Allowlist] Future Ignore Dict: {future_ignore_dict} for {image_uri}"
            )
            tag_set = [
                {
                    "Key": "upload_path",
                    "Value": get_safety_scan_allowlist_path(image_uri),
                },
                {"Key": "image_uri", "Value": image_uri.replace("-pre-push", "")},
            ]
            process_data_upload_to_pr_creation_bucket(
                image_uri=image_uri.replace("-pre-push", ""),
                json_upload_data=future_ignore_dict,
                tag_set=tag_set,
            )

    return safety_scan_output


def get_label_prefix_customer_type(image_tag):
    """
    Return customer type from image tag, to be used as label prefix

    @param image_tag: image tag
    @return: ec2 or sagemaker
    """
    if "-ec2" in image_tag:
        return "ec2"

    # Older images are not tagged with ec2 or sagemaker. Assuming that lack of ec2 tag implies sagemaker.
    return "sagemaker"


def is_APatch_build():
    """
    Returns True if image builder is working for image patch.
    :return: <bool> True or False
    """
    return os.getenv("APatch", "False").lower() == "true"


def process_data_upload_to_pr_creation_bucket(image_uri, json_upload_data, tag_set=None):
    """
    This method uploads the given `json_upload_data` to the s3 path obtained from get_unique_s3_path_for_uploading_data_to_pr_creation_bucket method.
    It also attaches the TagSet to the object as specified by tag_set argument that looks like:
        tag_set = [
                {
                    'Key': 'upload_path',
                    'Value': 'abcd123',
                },
            ]

    :param image_uri: str, image uri
    :param json_upload_data: dict/list, JSON format data that can be uploaded to the s3 object
    :param tag_set: List[Dict], as described above
    :return: str, s3 file path
    """
    s3_filepath = get_unique_s3_path_for_uploading_data_to_pr_creation_bucket(image_uri)
    s3_resource = boto3.resource("s3")
    s3object = s3_resource.Object(constants.PR_CREATION_DATA_HELPER_BUCKET, s3_filepath)
    s3_client = s3_resource.meta.client
    s3object.put(Body=(bytes(json.dumps(json_upload_data).encode("UTF-8"))))
    if tag_set:
        s3_client.put_object_tagging(
            Bucket=constants.PR_CREATION_DATA_HELPER_BUCKET,
            Key=s3_filepath,
            Tagging={"TagSet": tag_set},
        )


def get_unique_s3_path_for_uploading_data_to_pr_creation_bucket(image_uri: str):
    """
    Uses the current commit id and the image_uri to form the unique s3 path for uploading the data to the pr-creation-bucket
    """
    commit = os.getenv("CODEBUILD_RESOLVED_SOURCE_VERSION", "temp")
    object_name = image_uri.replace(":", "-").replace("/", "-")
    return f"{commit}/{object_name}.json"


def get_core_packages_path(image_uri, python_version=None):
    """
    Retrieves the safety_scan_allowlist_path for each image_uri.

    :param image_uri: str, consists of f"{image_repo}:{image_tag}"
    :return: string, safety scan allowlist path for the image
    """
    from test.test_utils import get_ecr_scan_allowlist_path

    os_scan_allowlist_path = get_ecr_scan_allowlist_path(image_uri, python_version)
    core_packages_path = os_scan_allowlist_path.replace(".os_scan_allowlist.", ".core_packages.")
    return core_packages_path
