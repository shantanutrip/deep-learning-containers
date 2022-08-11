import json
import os
import boto3

import pytest

from invoke import run, Context
from packaging.version import Version
from packaging.specifiers import SpecifierSet
from test import test_utils

from test.test_utils import (
    LOGGER,
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
    get_new_image_uri_using_current_uri_and_new_repo,
    wait_for_enhanced_scans_to_complete,
    get_ecr_scan_allowlist_path
)
from src.config import is_ecr_scan_allowlist_feature_enabled

ALLOWLIST_FEATURE_ENABLED_IMAGES = {"mxnet": SpecifierSet(">=1.8.0,<1.9.0")}


@pytest.mark.usefixtures("sagemaker")
@pytest.mark.model("N/A")
@pytest.mark.canary("Run security test regularly on production images")
def test_security(image):
    repo_name, image_tag = image.split("/")[-1].split(":")
    container_name = f"{repo_name}-{image_tag}-security"

    run(
        f"docker run -itd --name {container_name} "
        f"--mount type=bind,src=$(pwd)/container_tests,target=/test"
        f" --entrypoint='/bin/bash' "
        f"{image}",
        echo=True,
    )
    try:
        docker_exec_cmd = f"docker exec -i {container_name}"
        run(f"{docker_exec_cmd} python /test/bin/security_checks.py ")
    finally:
        run(f"docker rm -f {container_name}", hide=True)


def is_image_covered_by_allowlist_feature(image):
    """
    This method checks if the allowlist feature has been enabled for the image

    :param image: str, Image URI
    """
    image_framework, image_version = get_framework_and_version_from_tag(image)
    if image_framework not in ALLOWLIST_FEATURE_ENABLED_IMAGES or any(substring in image for substring in ["example"]):
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
    if is_image_covered_by_allowlist_feature(image):
        return "MEDIUM"
    return "HIGH"


def conduct_preprocessing(image, ecr_client, sts_client, region):
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
            new_image_uri = ecr_utils.reupload_image_to_test_ecr(image_uri_with_new_tag, target_image_repo_name, region)
            if image_uri_with_new_tag == original_image:
                image = new_image_uri

    return image


@pytest.mark.usefixtures("sagemaker")
@pytest.mark.model("N/A")
@pytest.mark.canary("Run ECR Scan test regularly on production images")
@pytest.mark.integration("check OS dependencies")
def test_ecr_basic_scan(image, ecr_client, sts_client, region):
    """
    Run ECR Scan Tool on an image being tested, and raise Error if vulnerabilities found
    1. Start Scan.
    2. For 5 minutes (Run DescribeImages):
       (We run this for 5 minutes because the Scan is expected to complete in about 2 minutes, though no
        analysis has been performed on exactly how long the Scan takes for a DLC image. Therefore we also
        have a 3 minute buffer beyond the expected amount of time taken.)
    3.1. If imageScanStatus == COMPLETE: exit loop
    3.2. If imageScanStatus == IN_PROGRESS or AttributeNotFound(imageScanStatus): continue loop
    3.3. If imageScanStatus == FAILED: raise RuntimeError
    4. If DescribeImages.imageScanStatus != COMPLETE: raise TimeOutError
    5. assert imageScanFindingsSummary.findingSeverityCounts.HIGH/CRITICAL == 0

    :param image: str Image URI for image to be tested
    :param ecr_client: boto3 Client for ECR
    :param sts_client: boto3 Client for STS
    :param region: str Name of region where test is executed
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
            new_image_uri = ecr_utils.reupload_image_to_test_ecr(image_uri_with_new_tag, target_image_repo_name, region)
            if image_uri_with_new_tag == original_image:
                image = new_image_uri

    minimum_sev_threshold = get_minimum_sev_threshold_level(image)
    LOGGER.info(f"Severity threshold level is {minimum_sev_threshold}")

    run_scan(ecr_client, image)
    scan_results = ecr_utils.get_ecr_image_scan_results(ecr_client, image, minimum_vulnerability=minimum_sev_threshold)
    scan_results = ecr_utils.populate_ecr_scan_with_web_scraper_results(image, scan_results)
    ecr_image_vulnerability_list = ECRBasicScanVulnerabilityList(minimum_severity=CVESeverity[minimum_sev_threshold])
    ecr_image_vulnerability_list.construct_allowlist_from_ecr_scan_result(scan_results)

    remaining_vulnerabilities = ecr_image_vulnerability_list

    if not is_image_covered_by_allowlist_feature(image):
        if is_canary_context():
            pytest.skip("Skipping the test on the canary.")

        common_ecr_scan_allowlist = ECRBasicScanVulnerabilityList(minimum_severity=CVESeverity[minimum_sev_threshold])
        common_ecr_scan_allowlist_path = os.path.join(
            os.sep, get_repository_local_path(), "data", "common-ecr-scan-allowlist.json"
        )
        if os.path.exists(common_ecr_scan_allowlist_path):
            common_ecr_scan_allowlist.construct_allowlist_from_file(common_ecr_scan_allowlist_path)

        remaining_vulnerabilities = remaining_vulnerabilities - common_ecr_scan_allowlist

        if remaining_vulnerabilities:
            assert not remaining_vulnerabilities.vulnerability_list, (
                f"The following vulnerabilities need to be fixed on {image}:\n"
                f"{json.dumps(remaining_vulnerabilities.vulnerability_list, indent=4)}"
            )
        return

    upgraded_image_vulnerability_list, image_scan_allowlist = fetch_other_vulnerability_lists(
        image, ecr_client, minimum_sev_threshold
    )
    s3_bucket_name = ECR_SCAN_HELPER_BUCKET

    ## In case new vulnerabilities (fixable or non-fixable) are found, then conduct failure routine
    newly_found_vulnerabilities = ecr_image_vulnerability_list - image_scan_allowlist
    # In case there is no new vulnerability but the allowlist is outdated
    vulnerabilities_that_can_be_fixed = image_scan_allowlist - upgraded_image_vulnerability_list

    if newly_found_vulnerabilities or vulnerabilities_that_can_be_fixed:
        failure_routine_summary = conduct_failure_routine(
            image,
            image_scan_allowlist,
            ecr_image_vulnerability_list,
            upgraded_image_vulnerability_list,
            s3_bucket_name,
        )
        (
            s3_filename_for_fixable_list,
            s3_filename_for_non_fixable_list,
        ) = process_failure_routine_summary_and_store_data_in_s3(failure_routine_summary, s3_bucket_name)
        prepend_message = (
            "Found new vulnerabilities in image." if newly_found_vulnerabilities else "Allowlist is outdated."
        )
        display_message = (
            prepend_message
            + " "
            + (
                f"""Found {len(failure_routine_summary["fixable_vulnerabilities"])} fixable vulnerabilites """
                f"""and {len(failure_routine_summary["non_fixable_vulnerabilities"])} non fixable vulnerabilites. """
                f"""Refer to files s3://{s3_bucket_name}/{s3_filename_for_fixable_list}, s3://{s3_bucket_name}/{s3_filename_for_non_fixable_list}, """
                f"""s3://{s3_bucket_name}/{failure_routine_summary["s3_filename_for_current_image_ecr_scan_list"]} and s3://{s3_bucket_name}/{failure_routine_summary["s3_filename_for_allowlist"]}."""
            )
        )
        if is_canary_context():
            LOGGER.error(display_message)
            pytest.skip("Skipping the test failure on the canary.")
        else:
            raise RuntimeError(display_message)


@pytest.mark.usefixtures("sagemaker")
@pytest.mark.model("N/A")
@pytest.mark.integration("ECR Enhanced Scans on Images")
def test_ecr_enhanced_scan(image, ecr_client, sts_client, region):
    LOGGER.info(f"Running test_ecr_enhanced_scan for image {image}")
    image = conduct_preprocessing(image, ecr_client, sts_client, region)

    new_uri = get_new_image_uri_using_current_uri_and_new_repo(
        image,
        new_repository_name=ECR_ENHANCED_SCANNING_REPO_NAME,
        new_repository_region=ECR_ENHANCED_REPO_REGION,
        append_tag="ENHSCAN",
    )

    run(f"docker tag {image} {new_uri}", hide=True)
    ecr_utils.reupload_image_to_test_ecr(
        new_uri, ECR_ENHANCED_SCANNING_REPO_NAME, ECR_ENHANCED_REPO_REGION, pull_image=False
    )

    ecr_client_for_enhanced_scanning_repo=boto3.client('ecr',region_name=ECR_ENHANCED_REPO_REGION)
    wait_for_enhanced_scans_to_complete(ecr_client_for_enhanced_scanning_repo, new_uri)

    scan_results = ecr_utils.get_all_ecr_enhanced_scan_findings(ecr_client=ecr_client_for_enhanced_scanning_repo, image_uri=new_uri)
    scan_results = json.loads(json.dumps(scan_results, default=ecr_utils.ecr_json_serializer)) 
    
    minimum_sev_threshold = get_minimum_sev_threshold_level(image)
    ecr_image_vulnerability_list = ECREnhancedScanVulnerabilityList(minimum_severity=CVESeverity[minimum_sev_threshold])
    ecr_image_vulnerability_list.construct_allowlist_from_ecr_scan_result(scan_results)

    remaining_vulnerabilities = ecr_image_vulnerability_list
    
    image_scan_allowlist_path = get_ecr_scan_allowlist_path(image)
    image_scan_allowlist = ECREnhancedScanVulnerabilityList(minimum_severity=CVESeverity[minimum_sev_threshold])
    if os.path.exists(image_scan_allowlist_path):
        image_scan_allowlist.construct_allowlist_from_file(image_scan_allowlist_path)
    
    remaining_vulnerabilities = remaining_vulnerabilities - image_scan_allowlist

    if remaining_vulnerabilities:
        assert not remaining_vulnerabilities.vulnerability_list, (
            f"The following vulnerabilities need to be fixed on {image}:\n"
            f"{json.dumps(remaining_vulnerabilities.vulnerability_list, indent=4)}"
        )

    LOGGER.info(f"New URI found {new_uri}")
    LOGGER.info(f"Completed processing for {image}")
    LOGGER.info(f"Len of scanned results {len(scan_results)}")
