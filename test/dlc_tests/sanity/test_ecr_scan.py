import json
import os
from time import sleep
import boto3

import pytest
import traceback

from invoke import run, Context
from packaging.version import Version
from packaging.specifiers import SpecifierSet
from test import test_utils

from test.test_utils import (
    LOGGER,
    EnhancedJSONEncoder,
    get_account_id_from_image_uri,
    get_framework_and_version_from_tag,
    get_repository_and_tag_from_image_uri,
    get_repository_local_path,
    ECR_SCAN_HELPER_BUCKET,
    is_canary_context,
    get_all_the_tags_of_an_image_from_ecr,
    is_image_available_locally,
    login_to_ecr_registry,
    get_region_from_image_uri,
    ECR_ENHANCED_SCANNING_REPO_NAME,
    ECR_ENHANCED_REPO_REGION,
    is_generic_image,
    get_allowlist_path_for_enhanced_scan_from_env_variable,
    get_ecr_scan_allowlist_path,
)
from test.test_utils import ecr as ecr_utils
from test.test_utils.security import (
    CVESeverity,
    ECRBasicScanVulnerabilityList,
    ECREnhancedScanVulnerabilityList,
    conduct_failure_routine,
    process_failure_routine_summary_and_store_data_in_s3,
    run_scan,
    fetch_other_vulnerability_lists,
    get_target_image_uri_using_current_uri_and_target_repo,
    wait_for_enhanced_scans_to_complete,
)
from src.config import is_ecr_scan_allowlist_feature_enabled

ALLOWLIST_FEATURE_ENABLED_IMAGES = {"mxnet": SpecifierSet(">=1.8.0,<1.9.0")}


def is_image_covered_by_allowlist_feature(image):
    """
    This method checks if the allowlist feature has been enabled for the image

    :param image: str, Image URI
    """
    image_framework, image_version = get_framework_and_version_from_tag(image)
    if image_framework not in ALLOWLIST_FEATURE_ENABLED_IMAGES or any(
        substring in image for substring in ["example"]
    ):
        return False
    if Version(image_version) in ALLOWLIST_FEATURE_ENABLED_IMAGES[image_framework]:
        return True
    return False


def get_minimum_sev_threshold_level(image):
    """
    This method gets the value for minimum threshold level. This threshold level determines the
    vulnerability severity above which we want to raise an alarm.

    :param image: str Image URI for which threshold has to be set
    """
    if is_generic_image():
        return "HIGH"
    if is_image_covered_by_allowlist_feature(image):
        return "MEDIUM"
    return "HIGH"


def conduct_preprocessing_of_images_before_running_ecr_scans(image, ecr_client, sts_client, region):
    """
    Conducts the following steps before starting any kind of ecr test:
        1. Pulls the image in case it is not existing locally.
        2. Pulls all the additional tags of the image.
        3. In case the test_account_id != image_account_id it reuploads the pulled images to the test_account_id for conducting the tests.
           Therafter, it replaces the original image uri with the new one, to the one that points to the image in test_account_id, and returns
           new image id.

    :param image: str, Image URI for image to be tested
    :param ecr_client: boto3 Client for ECR
    :param sts_client: boto3 Client for STS
    :param region: str, Name of region where test is executed
    :return image: str, Image URI for image to be tested. If test_account_id is same as image_accout_id, the image uri remains same as input param
                        otherwise, a new image uri is returned.
    """
    test_account_id = sts_client.get_caller_identity().get("Account")
    image_account_id = get_account_id_from_image_uri(image)
    image_region = get_region_from_image_uri(image)
    image_repo_name, original_image_tag = get_repository_and_tag_from_image_uri(image)
    additional_image_tags = get_all_the_tags_of_an_image_from_ecr(ecr_client, image)

    if not is_image_available_locally(image):
        LOGGER.info(f"Image {image} not available locally!! Pulling the image...")
        login_to_ecr_registry(Context(), image_account_id, image_region)
        run(f"docker pull {image}")
        if not is_image_available_locally(image):
            raise RuntimeError("Image shown as not available even after pulling")

    for additional_tag in additional_image_tags:
        image_uri_with_new_tag = image.replace(original_image_tag, additional_tag)
        run(f"docker tag {image} {image_uri_with_new_tag}", hide=True)

    if image_account_id != test_account_id:
        original_image = image
        target_image_repo_name = f"beta-{image_repo_name}"
        for additional_tag in additional_image_tags:
            image_uri_with_new_tag = original_image.replace(original_image_tag, additional_tag)
            new_image_uri = ecr_utils.reupload_image_to_test_ecr(
                image_uri_with_new_tag, target_image_repo_name, region
            )
            if image_uri_with_new_tag == original_image:
                image = new_image_uri

    return image


def helper_function_for_leftover_vulnerabilities_from_enhanced_scanning(image, python_version=None):
    """
    Acts as a helper function that conducts enhanced scan on an image URI and then returns the list of leftover vulns
    after removing the allowlisted vulns.
    1. Upload image to the ECR Enhanced Scanning Testing Repo.
    2. Wait for the scans to complete - takes approx 10 minutes for big images. Once the scan is complete,
        the scan status changes to ACTIVE
    3. If the status does not turn to ACTIVE, raise a TimeOut Error
    4. Read the ecr_scan_results and remove the allowlisted vulnerabilities from it
    5. Return the leftover list

    :param image: str Image URI for image to be tested
    :param python_version: str, This parameter is used for extracting allowlist for canary image uris that do not have a python version in it.
    :return: ECREnhancedScanVulnerabilityList Object with leftover vulnerability data
    :return: ecr_enhanced_repo_uri, String for the image uri in the enhanced scanning repo
    """
    ecr_enhanced_repo_uri = get_target_image_uri_using_current_uri_and_target_repo(
        image,
        target_repository_name=ECR_ENHANCED_SCANNING_REPO_NAME,
        target_repository_region=ECR_ENHANCED_REPO_REGION,
        append_tag="ENHSCAN",
    )

    # ecr_enhanced_repo_uri for Huggingface Neuron images tends to be greater than 128 in length and leads to docker tag failures.
    # The if condition below edits the tag to use short names instead of long ones.
    if all(temp_string in image for temp_string in ["huggingface", "neuron"]):
        ecr_enhanced_repo_uri = ecr_enhanced_repo_uri.replace("-huggingface-", "-hf-")
        ecr_enhanced_repo_uri = ecr_enhanced_repo_uri.replace("-pytorch-", "-pt-")
        ecr_enhanced_repo_uri = ecr_enhanced_repo_uri.replace("-tensorflow-", "-tf-")

    run(f"docker tag {image} {ecr_enhanced_repo_uri}", hide=True)
    ecr_utils.reupload_image_to_test_ecr(
        ecr_enhanced_repo_uri,
        ECR_ENHANCED_SCANNING_REPO_NAME,
        ECR_ENHANCED_REPO_REGION,
        pull_image=False,
    )

    ecr_client_for_enhanced_scanning_repo = boto3.client(
        "ecr", region_name=ECR_ENHANCED_REPO_REGION
    )
    wait_for_enhanced_scans_to_complete(
        ecr_client_for_enhanced_scanning_repo, ecr_enhanced_repo_uri
    )
    LOGGER.info(f"finished wait_for_enhanced_scans_to_complete, {image}")
    sleep(1 * 60)

    scan_results = ecr_utils.get_all_ecr_enhanced_scan_findings(
        ecr_client=ecr_client_for_enhanced_scanning_repo, image_uri=ecr_enhanced_repo_uri
    )
    scan_results = json.loads(json.dumps(scan_results, cls=EnhancedJSONEncoder))

    minimum_sev_threshold = get_minimum_sev_threshold_level(image)
    ecr_image_vulnerability_list = ECREnhancedScanVulnerabilityList(
        minimum_severity=CVESeverity[minimum_sev_threshold]
    )
    ecr_image_vulnerability_list.construct_allowlist_from_ecr_scan_result(scan_results)

    image_scan_allowlist = ECREnhancedScanVulnerabilityList(
        minimum_severity=CVESeverity[minimum_sev_threshold]
    )

    try:
        # Derive Image Scan Allowlist Path
        if is_generic_image():
            image_scan_allowlist_path = get_allowlist_path_for_enhanced_scan_from_env_variable()
        else:
            image_scan_allowlist_path = get_ecr_scan_allowlist_path(image, python_version=python_version)
        LOGGER.info(f"[Allowlist] Trying to locate Allowlist at PATH: {image_scan_allowlist_path}")
        # Check if image Scan Allowlist Path exists
        if os.path.exists(image_scan_allowlist_path):
            image_scan_allowlist.construct_allowlist_from_file(image_scan_allowlist_path)
            LOGGER.info(
                f"[Allowlist] Using allowlist at location {image_scan_allowlist_path} to skip {image_scan_allowlist.get_summarized_info()}"
            )
    except:
        LOGGER.info(f"[Allowlist] Image scan allowlist path could not be derived for {image}")
        traceback.print_exc()

    remaining_vulnerabilities = ecr_image_vulnerability_list - image_scan_allowlist
    LOGGER.info(f"ECR Enhanced Scanning test completed for image: {image}")
    return remaining_vulnerabilities, ecr_enhanced_repo_uri


def get_ignorable_vulnerabilities(vulnerability_list_object: ECREnhancedScanVulnerabilityList, image_uri: str):
    ## For every OS vulnerability, see if an attempt was made to fix that package - this data can be received from upgradable dict
    ## Check if none of the underlying packages is upgradable and then add to the allowlist (confirm if recommended version will have esm in it)
    ## If any of the package is upgradable, check if an attempt was made to upgrade it and if the upgrade successful.
    impacted_os_packages = set()
    impacted_py_packages = set()
    for package_name, package_cve_list in vulnerability_list_object.vulnerability_list.items():
        for cve in package_cve_list:
            if cve.package_details.package_manager == "OS":
                impacted_os_packages.add(package_name)
            elif cve.package_details.package_manager == "PYTHONPKG":
                impacted_py_packages.add(package_name)
    
    docker_run_cmd = f"docker run -v {get_repository_local_path()}:/deep-learning-containers  -id --entrypoint='/bin/bash' {image_uri} "
    container_id = run(f"{docker_run_cmd}").stdout.strip()
    docker_exec_cmd = f"docker exec -i {container_id}"
    container_setup_cmd = "apt-get update"
    run(f"{docker_exec_cmd} {container_setup_cmd}", hide=True)
    save_file_name = f"""{image_uri.replace("/","_").replace(":","_")}-apt-results.json"""
    ## TODO: Remove
    impacted_os_packages.add("imagemagick")
    script_run_cmd = f"""python /deep-learning-containers/miscellaneous_scripts/extract_apt_patch_data.py --impacted-packages {",".join(list(impacted_os_packages))} --save-result-path /deep-learning-containers/{save_file_name} --mode_type generate"""
    run(f"{docker_exec_cmd} {script_run_cmd}", hide=True)
    new_apt_patch_evaluation_data = {}
    new_apt_patch_evaluation_data_location = os.path.join(get_repository_local_path(), save_file_name)
    if os.path.exists:
        with open(new_apt_patch_evaluation_data_location, "r") as readfile:
            new_apt_patch_evaluation_data = json.load(readfile)
    embedded_apt_patch_evaluation_data = {}
    display_embdedded_patch_eval_data_cmd = "cat /opt/aws/dlc/patch-details/os_summary.json"
    display_output = run(f"{docker_exec_cmd} {display_embdedded_patch_eval_data_cmd}", warn=True)
    if display_output.ok:
        embedded_apt_patch_evaluation_data = json.loads(display_output.stdout.strip())

    ignore_package_data_message = {}
    for package in impacted_os_packages:
        if package not in new_apt_patch_evaluation_data.get("upgradable_packages_data_for_impacted_packages", {}):
            ignore_package_data_message[package] = "Package and its binaries cannot be upgraded further."
            if package in embedded_apt_patch_evaluation_data.get("upgradable_packages_data_for_impacted_packages", {}):
                package_related_binaries = sorted(embedded_apt_patch_evaluation_data["upgradable_packages_data_for_impacted_packages"][package])
                ignore_package_data_message[package] = f"""{ignore_package_data_message[package]} Packages: {",".join(package_related_binaries)} have been upgraded."""

    print("*****")
    print(impacted_os_packages)
    print(impacted_py_packages)
    print(new_apt_patch_evaluation_data)
    print(embedded_apt_patch_evaluation_data)
    print(ignore_package_data_message)
    print("*****")


@pytest.mark.usefixtures("sagemaker")
@pytest.mark.model("N/A")
@pytest.mark.integration("ECR Enhanced Scans on Images")
def test_ecr_enhanced_scan(image, ecr_client, sts_client, region):
    """
    Run ECR Enhanced Scan Tool on an image being tested, and raise Error if vulnerabilities found
    1. Use helper_function_for_leftover_vulnerabilities_from_enhanced_scanning to get the list of vulnerabilities
    2. In case any vulnerability is remaining after removal, raise an error

    :param image: str Image URI for image to be tested
    :param ecr_client: boto3 Client for ECR
    :param sts_client: boto3 Client for STS
    :param region: str Name of region where test is executed
    """
    LOGGER.info(f"Running test_ecr_enhanced_scan for image {image}")
    image = conduct_preprocessing_of_images_before_running_ecr_scans(
        image, ecr_client, sts_client, region
    )

    remaining_vulnerabilities, _ = helper_function_for_leftover_vulnerabilities_from_enhanced_scanning(image)
    if remaining_vulnerabilities:
        ## TODO: Revert these changes before merging into Master
        LOGGER.info(
            f"Total of {len(remaining_vulnerabilities.vulnerability_list)} vulnerabilities need to be fixed on {image}:\n"
            f"{json.dumps(remaining_vulnerabilities.vulnerability_list, cls= test_utils.EnhancedJSONEncoder)}"
        )
        get_ignorable_vulnerabilities(remaining_vulnerabilities, image)
        # assert (
        #     "PYTHONPKG"
        #     not in f"{json.dumps(remaining_vulnerabilities.vulnerability_list, cls= test_utils.EnhancedJSONEncoder)}"
        # ), "PYTHONPKG vulnerability exists."

        assert not remaining_vulnerabilities.vulnerability_list, (
            f"Total of {len(remaining_vulnerabilities.vulnerability_list)} vulnerabilities need to be fixed on {image}:\n"
            f"{json.dumps(remaining_vulnerabilities.vulnerability_list, cls= test_utils.EnhancedJSONEncoder)}"
        )
