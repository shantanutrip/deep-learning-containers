from abc import abstractmethod
import os
import json
import copy, collections
import boto3
import dataclasses, json

from invoke import run, Context
from time import sleep, time
from enum import IntEnum
from test import test_utils
from test.test_utils import LOGGER, ecr as ecr_utils
from dataclasses import dataclass
from typing import Any


class EnhancedJSONEncoder(json.JSONEncoder):
    """
    EnhancedJSONEncoder is required to dump dataclass objects as JSON.
    """

    def default(self, o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        return super().default(o)


@dataclass
class VulnerablePackageDetails:
    """
    VulnerablePackageDetails dataclass is used to represent the "package_details" for 
    a single vulnerability in Allowlist format.
    """

    file_path: str
    name: str
    package_manager: str
    version: str
    release: str

    def __init__(
        self,
        name: str,
        version: str,
        filePath: str = None,
        packageManager: str = None,
        release: str = None,
        *args: Any,
        **kwargs: Any,
    ):
        self.file_path = filePath
        self.name = name
        self.package_manager = packageManager
        self.version = version
        self.release = release


@dataclass
class AllowListFormatVulnerability:
    """
    AllowlistFormatVulnerability represents how the data looks for a single vulnerability in the allowlist format.
    The data from the ECR Ehanced Results are deserialized into AllowListFormatVulnerability dataclass. In 
    other words, vulnerabilities from the ecr format are are directly deserialized into vulnerabilities in Allowlist
    format using AllowlistFormatVulnerability dataclass.
    """

    description: str
    vulnerability_id: str
    name: str
    package_name: str
    package_details: VulnerablePackageDetails
    remediation: dict
    cvss_v3_score: float
    cvss_v30_score: float
    cvss_v2_score: float
    cvss_v3_severity: str
    source_url: str
    source: str
    severity: str
    status: str
    title: str

    def __init__(
        self,
        description: str,
        packageVulnerabilityDetails: dict,
        remediation: dict,
        severity: str,
        status: str,
        title: str,
        *args: Any,
        **kwargs: Any,
    ):
        self.description = description
        self.vulnerability_id = packageVulnerabilityDetails["vulnerabilityId"]
        self.name = packageVulnerabilityDetails["vulnerabilityId"]
        self.package_name = None
        self.package_details = None
        self.remediation = remediation
        self.source_url = packageVulnerabilityDetails["sourceUrl"]
        self.source = packageVulnerabilityDetails["source"]
        self.severity = severity
        self.status = status
        self.title = title
        self.cvss_v3_score = self.get_cvss_score(packageVulnerabilityDetails, score_version="3.1")
        self.cvss_v30_score = self.get_cvss_score(packageVulnerabilityDetails, score_version="3.0")
        self.cvss_v2_score = self.get_cvss_score(packageVulnerabilityDetails, score_version="2.0")
        self.cvss_v3_severity = self.get_cvss_v3_severity(self.cvss_v3_score)

    def get_cvss_score(self, packageVulnerabilityDetails: dict, score_version: str = "3.1"):
        for cvss_score in packageVulnerabilityDetails["cvss"]:
            if cvss_score["version"] == score_version:
                return float(cvss_score["baseScore"])
        return 0.0

    ## Taken from https://nvd.nist.gov/vuln-metrics/cvss and section 5 of first.org/cvss/specification-document
    def get_cvss_v3_severity(self, cvss_v3_score: float):
        if cvss_v3_score >= 9.0:
            return "CRITICAL"
        elif cvss_v3_score >= 7.0:
            return "HIGH"
        elif cvss_v3_score >= 4.0:
            return "MEDIUM"
        elif cvss_v3_score >= 0.1:
            return "LOW"
        return "UNDEFINED"  # Used to represent None Severity as well

    def set_package_details_and_name(self, package_details: VulnerablePackageDetails):
        self.package_details = package_details
        self.package_name = self.package_details.name


class ECRScanFailureException(Exception):
    """
    Base class for other exceptions
    """

    pass


class CVESeverity(IntEnum):
    UNDEFINED = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class ScanVulnerabilityList:
    """
    ScanVulnerabilityList is a class that reads and stores a vulnerability list in the Allowlist format. The format in which 
    the allowlist JSON files are stored on the DLC repo is referred as the Allowlist Format. This class allows easy comparison
    of 2 Allowlist formatted vulnerability lists and defines methods to convert ECR Scan Lists to Allowlist Format lists that 
    can be stored within the class itself.
    """

    def __init__(self, minimum_severity=CVESeverity["MEDIUM"]):
        self.vulnerability_list = {}
        self.minimum_severity = minimum_severity

    @abstractmethod
    def are_vulnerabilities_equivalent(self, vulnerability_1, vulnerability_2):
        pass

    @abstractmethod
    def get_vulnerability_package_name_from_allowlist_formatted_vulnerability(self, vulnerability):
        pass

    @abstractmethod
    def construct_allowlist_from_allowlist_formatted_vulnerabilities(self, allowlist_formatted_vulnerability_list):
        pass

    def get_flattened_vulnerability_list(self):
        """
        Returns the vulnerability list in the flattened format. For eg., if a vulnerability list looks like
        {"k1":[{"a":"b"},{"c":"d"}], "k2":[{"e":"f"},{"g":"h"}]}, it would return the following:
        [{"a":"b"},{"c":"d"},{"e":"f"},{"g":"h"}]

        :return: List(dict)
        """
        if self.vulnerability_list:
            return [
                vulnerability
                for package_vulnerabilities in self.vulnerability_list.values()
                for vulnerability in package_vulnerabilities
            ]
        return []

    def get_sorted_vulnerability_list(self):
        """
        This method is specifically made to sort the vulnerability list which is actually a dict 
        and has the following structure:
        {
            "packge_name1":[
                {"name":"cve-id1", "uri":"http.." ..},
                {"name":"cve-id2", "uri":"http.." ..}
            ],
            "packge_name2":[
                {"name":"cve-id1", "uri":"http.." ..},
                {"name":"cve-id2", "uri":"http.." ..}
            ]
        }
        We want to first sort the innermost list of dicts based on the "name" of each dict and then we sort the
        outermost dict based on keys i.e. package_name1 and package_name2.
        Note: We do not change the actual vulnerability list.
        :return: dict, sorted vulnerability list
        """
        copy_dict = copy.deepcopy(self.vulnerability_list)
        for key, list_of_dict in copy_dict.items():
            uniquified_list = test_utils.uniquify_list_of_dict(list_of_dict)
            uniquified_list.sort(key=lambda dict_element: dict_element["name"])
            copy_dict[key] = uniquified_list
        return dict(sorted(copy_dict.items()))

    def save_vulnerability_list(self, path):
        if self.vulnerability_list:
            sorted_vulnerability_list = self.get_sorted_vulnerability_list()
            with open(path, "w") as f:
                json.dump(sorted_vulnerability_list, f, indent=4)
        else:
            raise ValueError("self.vulnerability_list is empty.")

    def __contains__(self, vulnerability):
        """
        Check if an input vulnerability exists on the allow-list

        :param vulnerability: dict JSON object consisting of information about the vulnerability in the format
                              presented by the ECR Scan Tool
        :return: bool True if the vulnerability is allowed on the allow-list.
        """
        package_name = self.get_vulnerability_package_name_from_allowlist_formatted_vulnerability(vulnerability)
        if package_name not in self.vulnerability_list:
            return False
        for allowed_vulnerability in self.vulnerability_list[package_name]:
            if self.are_vulnerabilities_equivalent(vulnerability, allowed_vulnerability):
                return True
        return False

    def __cmp__(self, other):
        """
        Compare two ScanVulnerabilityList objects for equivalence

        :param other: Another ScanVulnerabilityList object
        :return: True if equivalent, False otherwise
        """
        if not other or not other.vulnerability_list:
            return not self.vulnerability_list

        if sorted(self.vulnerability_list.keys()) != sorted(other.vulnerability_list.keys()):
            return False

        for package_name, package_vulnerabilities in self.vulnerability_list.items():
            if len(self.vulnerability_list[package_name]) != len(other.vulnerability_list[package_name]):
                return False
            for v1, v2 in zip(
                self.get_sorted_vulnerability_list()[package_name], other.get_sorted_vulnerability_list()[package_name]
            ):
                if not self.are_vulnerabilities_equivalent(v1, v2):
                    return False
        return True

    def __sub__(self, other):
        """
        Difference between ScanVulnerabilityList objects

        :param other: Another ScanVulnerabilityList object
        :return: List of vulnerabilities that exist in self, but not in other
        """
        if not self.vulnerability_list:
            return None
        if not other or not other.vulnerability_list:
            return self
        missing_vulnerabilities = [
            vulnerability
            for package_vulnerabilities in self.vulnerability_list.values()
            for vulnerability in package_vulnerabilities
            if vulnerability not in other
        ]
        if not missing_vulnerabilities:
            return None

        difference = type(self)(minimum_severity=self.minimum_severity)
        difference.construct_allowlist_from_allowlist_formatted_vulnerabilities(missing_vulnerabilities)
        return difference

    def __add__(self, other):
        """
        Does Union between ScanVulnerabilityList objects

        :param other: Another ScanVulnerabilityList object
        :return: Union of vulnerabilites exisiting in self and other
        """
        flattened_vulnerability_list_self = self.get_flattened_vulnerability_list()
        flattened_vulnerability_list_other = other.get_flattened_vulnerability_list()
        all_vulnerabilities = flattened_vulnerability_list_self + flattened_vulnerability_list_other
        if not all_vulnerabilities:
            return None
        union_vulnerabilities = test_utils.uniquify_list_of_dict(all_vulnerabilities)

        union = type(self)(minimum_severity=self.minimum_severity)
        union.construct_allowlist_from_allowlist_formatted_vulnerabilities(union_vulnerabilities)
        return union


class ECRBasicScanVulnerabilityList(ScanVulnerabilityList):
    """
    A child class of ScanVulnerabilityList that is specifically made to deal with ECR Basic Scans.
    """

    def get_vulnerability_package_name_from_allowlist_formatted_vulnerability(self, vulnerability):
        """
        Get Package Name from a vulnerability JSON object. 
        For ECR Basic Scans, the format of the vulnerability is same in ecr format and allowlist format, so this function 
        can be used interchangeably.

        :param vulnerability: dict JSON object consisting of information about the vulnerability in the Allowlist format data
        which is same as ECR Scan Tool data for ECR Basic Scanning.
        :return: str package name
        """
        for attribute in vulnerability["attributes"]:
            if attribute["key"] == "package_name":
                return attribute["value"]
        return None

    def construct_allowlist_from_file(self, file_path):
        """
        Read JSON file and prepare the object with all allowed vulnerabilities

        :param file_path: Path to the allow-list JSON file.
        :return: dict self.vulnerability_list
        """
        with open(file_path, "r") as f:
            file_allowlist = json.load(f)
        for package_name, package_vulnerability_list in file_allowlist.items():
            for vulnerability in package_vulnerability_list:
                if CVESeverity[vulnerability["severity"]] >= self.minimum_severity:
                    if package_name not in self.vulnerability_list:
                        self.vulnerability_list[package_name] = []
                    self.vulnerability_list[package_name].append(vulnerability)
        return self.vulnerability_list

    def construct_allowlist_from_allowlist_formatted_vulnerabilities(self, allowlist_formatted_vulnerability_list):
        """
        Read a vulnerability list and construct the vulnerability_list

        :param vulnerability_list: list ECR Scan Result results
        :return: dict self.vulnerability_list
        """
        for vulnerability in allowlist_formatted_vulnerability_list:
            package_name = self.get_vulnerability_package_name_from_allowlist_formatted_vulnerability(vulnerability)
            if package_name not in self.vulnerability_list:
                self.vulnerability_list[package_name] = []
            if CVESeverity[vulnerability["severity"]] >= self.minimum_severity:
                self.vulnerability_list[package_name].append(vulnerability)
        return self.vulnerability_list

    def construct_allowlist_from_ecr_scan_result(self, ecr_format_vulnerability_list):
        """
        Read a vulnerability list and construct the vulnerability_list
        For Basic Scan, the ecr scan vulnerabilities and the allowlist vulnerabilities have the same format
        and hence we can use the same function.

        :param vulnerability_list: list ECR Scan Result results
        :return: dict self.vulnerability_list
        """
        return self.construct_allowlist_from_allowlist_formatted_vulnerabilities(ecr_format_vulnerability_list)

    def are_vulnerabilities_equivalent(self, vulnerability_1, vulnerability_2):
        """
        Check if two vulnerability JSON objects are equivalent

        :param vulnerability_1: dict JSON object consisting of information about the vulnerability in the format
                                presented by the ECR Scan Tool
        :param vulnerability_2: dict JSON object consisting of information about the vulnerability in the format
                                presented by the ECR Scan Tool
        :return: bool True if the two input objects are equivalent, False otherwise
        """
        if (vulnerability_1["name"], vulnerability_1["severity"]) == (
            vulnerability_2["name"],
            vulnerability_2["severity"],
        ):
            # Do not compare package_version, because this may have been obtained at the time the CVE was first observed
            # on the ECR Scan, which would result in unrelated version updates causing a mismatch while the CVE still
            # applies on both vulnerabilities.
            if all(
                attribute in vulnerability_2["attributes"]
                for attribute in vulnerability_1["attributes"]
                if not attribute["key"] == "package_version"
            ):
                return True
        return False


class ECREnhancedScanVulnerabilityList(ScanVulnerabilityList):
    """
    A child class of ScanVulnerabilityList that is specifically made to deal with ECR Enhanced Scans.
    """

    def get_vulnerability_package_name_from_allowlist_formatted_vulnerability(self, vulnerability):
        """
        Get Package Name from a vulnerability JSON object
        :param vulnerability: dict JSON object consisting of information about the vulnerability in the Allowlist Format.
        :return: str package name
        """
        return vulnerability["package_name"]

    def construct_allowlist_from_file(self, file_path):
        """
        Read JSON file that has the vulnerability data saved in the Allowlist format itself and prepare the object with 
        all the vulnerabilities in the Allowlist format as well.

        :param file_path: Path to the allow-list JSON file.
        :return: dict self.vulnerability_list
        """
        with open(file_path, "r") as f:
            file_allowlist = json.load(f)
        for _, package_vulnerability_list in file_allowlist.items():
            self.construct_allowlist_from_allowlist_formatted_vulnerabilities(package_vulnerability_list)
        return self.vulnerability_list

    def construct_allowlist_from_allowlist_formatted_vulnerabilities(self, allowlist_formatted_vulnerability_list):
        """
        Read a vulnerability list in the AllowListFormat and construct the vulnerability_list in the same format.

        :param vulnerability_list: list ECR Scan Result results
        :return: dict self.vulnerability_list
        """
        for vulnerability in allowlist_formatted_vulnerability_list:
            package_name = self.get_vulnerability_package_name_from_allowlist_formatted_vulnerability(vulnerability)
            if CVESeverity[vulnerability["cvss_v3_severity"]] < self.minimum_severity:
                continue
            if package_name not in self.vulnerability_list:
                self.vulnerability_list[package_name] = []
            self.vulnerability_list[package_name].append(vulnerability)
        return self.vulnerability_list

    def construct_allowlist_from_ecr_scan_result(self, ecr_format_vulnerability_list):
        """
        Read an ECR formatted vulnerability list and construct the Allowlist Formatted vulnerability_list

        :param vulnerability_list: list ECR Scan Result results
        :return: dict self.vulnerability_list
        """
        for ecr_format_vulnerability in ecr_format_vulnerability_list:
            for vulnerable_package in ecr_format_vulnerability["packageVulnerabilityDetails"]["vulnerablePackages"]:
                allowlist_format_vulnerability_object = AllowListFormatVulnerability(**ecr_format_vulnerability)
                vulnerable_package_object = VulnerablePackageDetails(**vulnerable_package)
                allowlist_format_vulnerability_object.set_package_details_and_name(vulnerable_package_object)
                if CVESeverity[allowlist_format_vulnerability_object.cvss_v3_severity] < self.minimum_severity:
                    continue
                if allowlist_format_vulnerability_object.package_name not in self.vulnerability_list:
                    self.vulnerability_list[allowlist_format_vulnerability_object.package_name] = []
                self.vulnerability_list[allowlist_format_vulnerability_object.package_name].append(
                    json.loads(json.dumps(allowlist_format_vulnerability_object, cls=EnhancedJSONEncoder))
                )
        self.vulnerability_list = self.get_sorted_vulnerability_list()
        return self.vulnerability_list

    def are_vulnerabilities_equivalent(self, vulnerability_1, vulnerability_2):
        """
        Check if two vulnerability JSON objects are equivalent

        :param vulnerability_1: dict, JSON object consisting of information about the vulnerability in the Allowlist Format
        :param vulnerability_2: dict, JSON object consisting of information about the vulnerability in the Allowlist Format
        :return: bool True if the two input objects are equivalent, False otherwise
        """
        ## Ignore version key in package_details as it might represent the version of the package existing in the image
        ## and might differ from  image to image, even when the vulnerability is same.
        if test_utils.check_if_two_dictionaries_are_equal(
            vulnerability_1["package_details"], vulnerability_2["package_details"], ignore_keys=["version"]
        ):
            return test_utils.check_if_two_dictionaries_are_equal(
                vulnerability_1, vulnerability_2, ignore_keys=["package_details"]
            )
        return False


def get_ecr_vulnerability_package_version(vulnerability):
    """
    Get Package Version from a vulnerability JSON object

    :param vulnerability: dict JSON object consisting of information about the vulnerability in the format
                          presented by the ECR Scan Tool
    :return: str package version
    """
    for attribute in vulnerability["attributes"]:
        if attribute["key"] == "package_version":
            return attribute["value"]
    return None


def get_ecr_scan_allowlist_path(image_uri):
    dockerfile_location = test_utils.get_dockerfile_path_for_image(image_uri)
    image_scan_allowlist_path = dockerfile_location + ".os_scan_allowlist.json"
    if test_utils.is_covered_by_e3_sm_split(image_uri) and test_utils.is_e3_sm_in_same_dockerfile(image_uri):
        if test_utils.is_e3_image(image_uri):
            image_scan_allowlist_path = image_scan_allowlist_path.replace("Dockerfile", "Dockerfile.e3")
        else:
            image_scan_allowlist_path = image_scan_allowlist_path.replace("Dockerfile", "Dockerfile.sagemaker")

    # Each example image (tied to CUDA version/OS version/other variants) can have its own list of vulnerabilities,
    # which means that we cannot have just a single allowlist for all example images for any framework version.
    if "example" in image_uri:
        image_scan_allowlist_path = dockerfile_location + ".example.os_scan_allowlist.json"
    return image_scan_allowlist_path


def _save_lists_in_s3(save_details, s3_bucket_name):
    """
    This method takes in a list of filenames and the data corresponding to each filename and stores it in 
    the s3 bucket.

    :param save_details: list[(string, list)], a lists of tuples wherein each tuple has a filename and the corresponding data.
    :param s3_bucket_name: string, name of the s3 bucket
    """
    s3_client = boto3.client("s3")
    for filename, data in save_details:
        with open(filename, "w") as outfile:
            json.dump(data, outfile, indent=4)
        s3_client.upload_file(Filename=filename, Bucket=s3_bucket_name, Key=filename)


def get_new_image_uri_using_current_uri_and_new_repo(image, new_repository_name, new_repository_region, append_tag=""):
    """
    This function helps formulate a new image uri for a given image such that the new uri retains
    the old uri info (i.e. old repo name and old repo tag).

    :param image: str, image uri
    :param new_repository_name: str, name of new repository
    :param new_repository_region: str, region of new repository
    :param append_tag: str, string that needs to be appended at the end of the tag
    :return: str, new image uri
    """
    sts_client = boto3.client("sts", region_name=new_repository_region)
    account_id = sts_client.get_caller_identity().get("Account")
    registry = ecr_utils.get_ecr_registry(account_id, new_repository_region)
    original_image_repository, original_image_tag = test_utils.get_repository_and_tag_from_image_uri(image)
    if append_tag:
        upgraded_image_tag = f"{original_image_repository}-{original_image_tag}-{append_tag}"
    else:
        upgraded_image_tag = f"{original_image_repository}-{original_image_tag}"
    new_image_uri = f"{registry}/{new_repository_name}:{upgraded_image_tag}"
    return new_image_uri


def run_upgrade_on_image_and_push(image, new_image_uri):
    """
    Creates a container for the image being tested. Runs apt update and upgrade on the container
    and the commits the container as new_image_uri. This new image is then pushed to the ECR. 

    :param image: str
    :param new_image_uri: str
    """
    max_attempts = 10
    ctx = Context()
    docker_run_cmd = f"docker run -id --entrypoint='/bin/bash' {image}"
    container_id = ctx.run(f"{docker_run_cmd}", hide=True).stdout.strip()
    apt_command = "apt-get update && apt-get upgrade"
    docker_exec_cmd = f"docker exec -i {container_id}"
    attempt_count = 0
    apt_ran_successfully_flag = False
    # When a command or application is updating the system or installing a new software, it locks the dpkg file (Debian package manager).
    # Since we have multiple processes running for the tests, there are cases when one of the process locks the dpkg file
    # In this scenario, we get error: ‘E: Could not get lock /var/lib/dpkg/lock’ while running apt-get update
    # That is why we need multiple tries to ensure that it succeeds in one of the tries.
    # More info: https://itsfoss.com/could-not-get-lock-error/
    while True:
        run_output = ctx.run(f"{docker_exec_cmd} {apt_command}", hide=True, warn=True)
        attempt_count += 1
        if not run_output.ok:
            test_utils.LOGGER.info(
                f"Attempt no. {attempt_count} on image: {image}"
                f"Could not run apt update and upgrade. \n"
                f"Stdout is {run_output.stdout} \n"
                f"Stderr is {run_output.stderr} \n"
                f"Failed status is {run_output.exited}"
            )
            sleep(2 * 60)
        elif run_output.ok:
            apt_ran_successfully_flag = True
            break
        if attempt_count == max_attempts:
            break
    if not apt_ran_successfully_flag:
        raise RuntimeError(
            f"Could not run apt update and upgrade on image: {image}. \n"
            f"Stdout is {run_output.stdout} \n"
            f"Stderr is {run_output.stderr} \n"
            f"Failed status is {run_output.exited}"
        )
    ctx.run(f"docker commit {container_id} {new_image_uri}", hide=True)
    ctx.run(f"docker rm -f {container_id}", hide=True)
    ctx.run(f"docker push {new_image_uri}", hide=True)


def _invoke_lambda(function_name, payload_dict={}):
    """
    Asyncronously Invokes the passed lambda.

    :param function_name: str, name of the lambda function
    :param payload_dict: dict, payload to be sent to the lambda
    """
    lambda_client = boto3.client("lambda", region_name=test_utils.DEFAULT_REGION)
    response = lambda_client.invoke(
        FunctionName=function_name, InvocationType="Event", LogType="Tail", Payload=json.dumps(payload_dict)
    )
    status_code = response.get("StatusCode")
    if status_code != 202:
        raise ValueError("Lambda call not made properly. Status code returned {status_code}")


def get_apt_package_name(ecr_package_name):
    """
    Few packages have different names in the ecr scan and actual apt. This function returns an
    apt name of an ecr package.
    :param ecr_package_name: str, name of the package in ecr scans
    :param apt_package_name: str, name of the package in apt
    """
    name_mapper = {
        "cyrus-sasl2": "libsasl2-2",
        "glibc": "libc6",
        "libopenmpt": "libopenmpt-dev",
        "fribidi": "libfribidi-dev",
    }
    return name_mapper.get(ecr_package_name, ecr_package_name)


def create_and_save_package_list_to_s3(old_filepath, new_packages, new_filepath, s3_bucket_name):
    """
    This method conducts the union of packages present in the original apt-get-upgrade
    list and new list of packages passed as an argument. It makes a new file and stores
    the results in it.
    :param old_filpath: str, path of original file
    :param new_packages: list[str], consists of list of packages
    :param new_filpath: str, path of new file that will have the results of union
    :param s3_bucket_name: string, name of the s3 bucket
    """
    file1 = open(old_filepath, "r")
    lines = file1.readlines()
    current_packages = [line.strip() for line in lines]
    package_list = current_packages
    new_packages = [get_apt_package_name(new_package) for new_package in new_packages]
    union_of_old_and_new_packages = set(package_list).union(set(new_packages))
    unified_package_list = list(union_of_old_and_new_packages)
    unified_package_list.sort()
    unified_package_list_for_storage = [f"{package_name}\n" for package_name in unified_package_list]
    file1.close()
    run(f"rm -rf {new_filepath}")
    with open(new_filepath, "w") as file2:
        file2.writelines(unified_package_list_for_storage)
    s3_client = boto3.client("s3")
    s3_client.upload_file(Filename=new_filepath, Bucket=s3_bucket_name, Key=new_filepath)


def save_scan_vulnerability_list_object_to_s3_in_json_format(
    image, scan_vulnerability_list_object, append_tag, s3_bucket_name
):
    """
    Saves the vulnerability list in the s3 bucket. It uses image to decide the name of the file on 
    the s3 bucket.

    :param image: str, image uri 
    :param vulnerability_list: ScanVulnerabilityList
    :param s3_bucket_name: string, name of the s3 bucket
    :return: str, name of the file as stored on s3
    """
    processed_image_uri = image.replace(".", "-").replace("/", "-").replace(":", "-")
    file_name = f"{processed_image_uri}-{append_tag}.json"
    scan_vulnerability_list_object.save_vulnerability_list(file_name)
    s3_client = boto3.client("s3")
    s3_client.upload_file(Filename=file_name, Bucket=s3_bucket_name, Key=file_name)
    return file_name


def get_vulnerabilites_fixable_by_upgrade(
    image_allowlist, ecr_image_vulnerability_list, upgraded_image_vulnerability_list
):
    """
    Finds out the vulnerabilities that are fixable by apt-get update and apt-get upgrade.

    :param image_allowlist: ScanVulnerabilityList, Vulnerabities that are present in the respective allowlist in the DLC git repo.
    :param ecr_image_vulnerability_list: ScanVulnerabilityList, Vulnerabities recently detected WITHOUT running apt-upgrade on the originally released image.
    :param upgraded_image_vulnerability_list: ScanVulnerabilityList, Vulnerabilites exisiting in the image WITH apt-upgrade run on it.
    :return: ScanVulnerabilityList/NONE, either ScanVulnerabilityList object or None if no fixable vulnerability
    """
    fixable_ecr_image_scan_vulnerabilites = ecr_image_vulnerability_list - upgraded_image_vulnerability_list
    fixable_allowlist_vulnerabilites = image_allowlist - upgraded_image_vulnerability_list
    vulnerabilities_fixable_by_upgrade = None
    if fixable_ecr_image_scan_vulnerabilites and fixable_allowlist_vulnerabilites:
        vulnerabilities_fixable_by_upgrade = fixable_ecr_image_scan_vulnerabilites + fixable_allowlist_vulnerabilites
    elif fixable_ecr_image_scan_vulnerabilites:
        vulnerabilities_fixable_by_upgrade = fixable_ecr_image_scan_vulnerabilites
    elif fixable_allowlist_vulnerabilites:
        vulnerabilities_fixable_by_upgrade = fixable_allowlist_vulnerabilites
    return vulnerabilities_fixable_by_upgrade


def conduct_failure_routine(
    image, image_allowlist, ecr_image_vulnerability_list, upgraded_image_vulnerability_list, s3_bucket_for_storage
):
    """
    This method conducts the entire process that is supposed to be followed when ECR test fails. It finds all
    the fixable and non fixable vulnerabilities and all the packages that can be upgraded and finally invokes
    the Auto-Secure lambda for further processing.

    :param image: str, image uri
    :param image_allowlist: ScanVulnerabilityList, Vulnerabities that are present in the respective allowlist in the DLC git repo.
    :param ecr_image_vulnerability_list: ScanVulnerabilityList, Vulnerabities recently detected WITHOUT running apt-upgrade on the originally released image.
    :param upgraded_image_vulnerability_list: ScanVulnerabilityList, Vulnerabilites exisiting in the image WITH apt-upgrade run on it.
    :param s3_bucket_for_storage: s3 name of the bucket that would be used for saving all the important data that needs to be stored during failure routine.
    :return: dict, a dictionary consisting of the entire summary of the steps run within this method.
    """
    s3_filename_for_allowlist = save_scan_vulnerability_list_object_to_s3_in_json_format(
        image, upgraded_image_vulnerability_list, "allowlist", s3_bucket_for_storage
    )
    s3_filename_for_current_image_ecr_scan_list = save_scan_vulnerability_list_object_to_s3_in_json_format(
        image, ecr_image_vulnerability_list, "current-ecr-scanlist", s3_bucket_for_storage
    )
    original_filepath_for_allowlist = get_ecr_scan_allowlist_path(image)
    edited_files = [{"s3_filename": s3_filename_for_allowlist, "github_filepath": original_filepath_for_allowlist}]
    vulnerabilities_fixable_by_upgrade = get_vulnerabilites_fixable_by_upgrade(
        image_allowlist, ecr_image_vulnerability_list, upgraded_image_vulnerability_list
    )
    newly_found_non_fixable_vulnerabilites = upgraded_image_vulnerability_list - image_allowlist
    fixable_list = {}
    if vulnerabilities_fixable_by_upgrade:
        fixable_list = vulnerabilities_fixable_by_upgrade.vulnerability_list
    apt_upgrade_list_filename = f"apt-upgrade-list-{test_utils.get_processor_from_image_uri(image)}.txt"
    s3_filename_for_apt_upgrade_list = s3_filename_for_allowlist.replace("allowlist.json", apt_upgrade_list_filename)
    original_filepath_for_apt_upgrade_list = os.path.join(
        os.path.dirname(original_filepath_for_allowlist), apt_upgrade_list_filename
    )
    new_package_list = fixable_list if isinstance(fixable_list, list) else list(fixable_list.keys())
    create_and_save_package_list_to_s3(
        original_filepath_for_apt_upgrade_list,
        new_package_list,
        s3_filename_for_apt_upgrade_list,
        s3_bucket_for_storage,
    )
    edited_files.append(
        {"s3_filename": s3_filename_for_apt_upgrade_list, "github_filepath": original_filepath_for_apt_upgrade_list}
    )
    newly_found_non_fixable_list = {}
    if newly_found_non_fixable_vulnerabilites:
        newly_found_non_fixable_list = newly_found_non_fixable_vulnerabilites.vulnerability_list
    message_body = {
        "edited_files": edited_files,
        "fixable_vulnerabilities": fixable_list,
        "non_fixable_vulnerabilities": newly_found_non_fixable_list,
    }
    ## TODO: Make the conditions below as if test_utils.is_canary_context() and test_utils.is_time_for_invoking_ecr_scan_failure_routine_lambda() and os.getenv("REGION") == test_utils.DEFAULT_REGION:
    ## to make sure that we just invoke the ECR_SCAN_FAILURE_ROUTINE_LAMBDA once everyday
    if test_utils.is_canary_context() and os.getenv("REGION") == test_utils.DEFAULT_REGION:
        # boto3.Session().region_name == test_utils.DEFAULT_REGION helps us invoke the ECR_SCAN_FAILURE_ROUTINE_LAMBDA
        # from just 1 account
        _invoke_lambda(function_name=test_utils.ECR_SCAN_FAILURE_ROUTINE_LAMBDA, payload_dict=message_body)
    return_dict = copy.deepcopy(message_body)
    return_dict["s3_filename_for_allowlist"] = s3_filename_for_allowlist
    return_dict["s3_filename_for_current_image_ecr_scan_list"] = s3_filename_for_current_image_ecr_scan_list
    return return_dict


def process_failure_routine_summary_and_store_data_in_s3(failure_routine_summary, s3_bucket_name):
    """
    This method is especially constructed to process the failure routine summary that is generated as a result of 
    calling conduct_failure_routine. It extracts lists and calls the save lists function to store them in the s3
    bucket.

    :param failure_routine_summary: dict, dictionary returned as an outcome of conduct_failure_routine method
    :param s3_bucket_name: string, name of the s3 bucket
    :return s3_filename_for_fixable_list: string, filename in the s3 bucket for the fixable vulnerabilities
    :return s3_filename_for_non_fixable_list: string, filename in the s3 bucket for the non-fixable vulnerabilities
    """
    s3_filename_for_allowlist = failure_routine_summary["s3_filename_for_allowlist"]
    s3_filename_for_fixable_list = s3_filename_for_allowlist.replace(
        "allowlist.json", "fixable-vulnerability-list.json"
    )
    s3_filename_for_non_fixable_list = s3_filename_for_allowlist.replace(
        "allowlist.json", "non-fixable-vulnerability-list.json"
    )
    save_details = []
    save_details.append((s3_filename_for_fixable_list, failure_routine_summary["fixable_vulnerabilities"]))
    save_details.append((s3_filename_for_non_fixable_list, failure_routine_summary["non_fixable_vulnerabilities"]))
    _save_lists_in_s3(save_details, s3_bucket_name)
    return s3_filename_for_fixable_list, s3_filename_for_non_fixable_list


def run_scan(ecr_client, image):
    scan_status = None
    start_time = time()
    ecr_utils.start_ecr_image_scan(ecr_client, image)
    while (time() - start_time) <= 600:
        scan_status, scan_status_description = ecr_utils.get_ecr_image_scan_status(ecr_client, image)
        if scan_status == "FAILED" or scan_status not in [None, "IN_PROGRESS", "COMPLETE"]:
            raise ECRScanFailureException(f"ECR Scan failed for {image} with description: {scan_status_description}")
        if scan_status == "COMPLETE":
            break
        sleep(1)
    if scan_status != "COMPLETE":
        raise TimeoutError(f"ECR Scan is still in {scan_status} state. Exiting.")


def wait_for_enhanced_scans_to_complete(ecr_client, image):
    """
    For Continuous Enhanced scans, the images will go through `SCAN_ON_PUSH` when they are uploaded for the 
    first time. During that time, their state will be shown as `PENDING`. From next time onwards, their status will show 
    itself as `ACTIVE`.

    :param ecr_client: boto3 Client for ECR
    :param image: str, Image URI for image being scanned
    """
    scan_status = None
    scan_status_description = ""
    start_time = time()
    while (time() - start_time) <= 1200:
        try:
            scan_status, scan_status_description = ecr_utils.get_ecr_image_enhanced_scan_status(ecr_client, image)
        except ecr_client.exceptions.ScanNotFoundException as e:
            LOGGER.info(e.response)
            LOGGER.info(
                "It takes sometime for the newly uploaded image to show its scan status, hence the error handling"
            )
        if scan_status == "ACTIVE":
            break
        sleep(1 * 60)
    if scan_status != "ACTIVE":
        raise TimeoutError(
            f"ECR Scan is still in {scan_status} state with description: {scan_status_description}. Exiting."
        )


def fetch_other_vulnerability_lists(image, ecr_client, minimum_sev_threshold):
    """
    For a given image it fetches all the other vulnerability lists except the vulnerability list formed by the
    ecr scan of the current image. In other words, for a given image it fetches upgraded_image_vulnerability_list and
    image_scan_allowlist.

    :param image: str Image URI for image to be tested
    :param ecr_client: boto3 Client for ECR
    :param minimum_sev_threshold: string, determines the minimum severity threshold for ScanVulnerabilityList objects. Can take values HIGH or MEDIUM.
    :return upgraded_image_vulnerability_list: ScanVulnerabilityList, Vulnerabilites exisiting in the image WITH apt-upgrade run on it.
    :return image_allowlist: ScanVulnerabilityList, Vulnerabities that are present in the respective allowlist in the DLC git repo.
    """
    new_image_uri_for_upgraded_image = get_new_image_uri_using_current_uri_and_new_repo(
        image,
        new_repository_name=test_utils.UPGRADE_ECR_REPO_NAME,
        new_repository_region=os.getenv("REGION", test_utils.DEFAULT_REGION),
        append_tag="upgraded",
    )
    run_upgrade_on_image_and_push(image, new_image_uri_for_upgraded_image)
    run_scan(ecr_client, new_image_uri_for_upgraded_image)
    scan_results_with_upgrade = ecr_utils.get_ecr_image_scan_results(
        ecr_client, new_image_uri_for_upgraded_image, minimum_vulnerability=minimum_sev_threshold
    )
    scan_results_with_upgrade = ecr_utils.populate_ecr_scan_with_web_scraper_results(
        new_image_uri_for_upgraded_image, scan_results_with_upgrade
    )
    upgraded_image_vulnerability_list = ECRBasicScanVulnerabilityList(
        minimum_severity=CVESeverity[minimum_sev_threshold]
    )
    upgraded_image_vulnerability_list.construct_allowlist_from_ecr_scan_result(scan_results_with_upgrade)
    image_scan_allowlist = ECRBasicScanVulnerabilityList(minimum_severity=CVESeverity[minimum_sev_threshold])
    image_scan_allowlist_path = get_ecr_scan_allowlist_path(image)
    if os.path.exists(image_scan_allowlist_path):
        image_scan_allowlist.construct_allowlist_from_file(image_scan_allowlist_path)
    return upgraded_image_vulnerability_list, image_scan_allowlist
