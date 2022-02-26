import os
import time
import re
from inspect import signature
import boto3
import logging
import sys
import uuid

from retrying import retry
from fabric import Connection
from botocore.config import Config
from botocore.exceptions import ClientError
from invoke import run

from test.test_utils import is_pr_context, is_mainline_context, get_synapseai_version_from_tag
from . import DEFAULT_REGION, UL_AMI_LIST, LOGGER, BENCHMARK_RESULTS_S3_BUCKET

EC2_INSTANCE_ROLE_NAME = "ec2TestInstanceRole"

# List of instance types for which if instance spin-up fails, the test is skipped instead of failing.
ICE_SKIP_INSTANCE_LIST = ["p3dn.24xlarge"]

# List of instance types which are too powerful for minor tests
HEAVY_INSTANCE_LIST = ["p3dn.24xlarge", "p4d.24xlarge"]

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.StreamHandler(sys.stdout))
LOGGER.setLevel(logging.INFO)

def filter_only_multi_gpu(instance_type_list):
    filtered_list = [
        instance_type for instance_type in instance_type_list if get_instance_num_gpus(instance_type=instance_type) > 1
    ]
    return filtered_list


def filter_only_single_gpu(instance_type_list):
    filtered_list = [
        instance_type for instance_type in instance_type_list if get_instance_num_gpus(instance_type=instance_type) == 1
    ]
    return filtered_list


def filter_not_heavy_instance_types(instance_type_list):
    filtered_list = [
        instance_type for instance_type in instance_type_list if instance_type not in HEAVY_INSTANCE_LIST
    ]
    return filtered_list


def get_ec2_instance_type(default, processor, filter_function=lambda x: x, efa=False, arch_type=""):
    """
    Get EC2 instance type from associated EC2_[CPU|GPU]_INSTANCE_TYPE env variable, or set it to a default
    for contexts where the variable is not present (i.e. PR, Nightly, local testing)

    :param default: Default instance type to use - Should never be p3dn
    :param processor: "cpu" or "gpu"
    :param filter_function: filter_function(instance_type_list) A function that takes the list to be generated by
    the logic of the get_ec2_instance_type function, and filters the list to only produce "acceptable" instances.
    For example, this can be a function that only returns multi-gpu instance types from a given list of instance types.

    :return: one item list of instance type -- this is used to parametrize tests, and parameter is required to be
    a list.
    """
    allowed_processors = ("cpu", "gpu", "neuron", "hpu")
    if processor not in allowed_processors:
        raise RuntimeError(
            f"Aborting EC2 test run. Unrecognized processor type {processor}. "
            f"Please choose from {allowed_processors}"
        )
    if default in HEAVY_INSTANCE_LIST and not efa:
        raise RuntimeError(f"Default instance type should never be one of {HEAVY_INSTANCE_LIST}, but it is {default}")
    instance_type = os.getenv(f"EC2_{processor.upper()}_INSTANCE_TYPE")
    if arch_type == "graviton":
        instance_type = os.getenv(f"EC2_{processor.upper()}_{arch_type.upper()}_INSTANCE_TYPE")
    if not instance_type and is_mainline_context():
        return []

    instance_list = filter_function([instance_type] if instance_type else [])
    if not instance_list:
        instance_list = [default]
    return instance_list


def get_ec2_accelerator_type(default, processor):
    """
    Get EC2 instance type from associated EC2_EIA_INSTANCE_TYPE env variable, or set it to a default
    for contexts where the variable is not present (i.e. PR, Nightly, local testing)

    :param default: Default accelerator instance type to use
    :param processor: "eia"

    :return: one item list of instance type -- this is used to parametrize tests, and parameter is required to be
    a list.
    """
    allowed_processors = ("eia",)
    if processor not in allowed_processors:
        raise RuntimeError(
            f"Aborting EC2 test run. Unrecognized processor type {processor}. "
            f"Please choose from {allowed_processors}"
        )
    accelerator_type = os.getenv(f"EC2_{processor.upper()}_INSTANCE_TYPE")
    if not accelerator_type:
        if is_mainline_context():
            return []
        return [default]
    return [accelerator_type]


def launch_instance(
    ami_id,
    instance_type,
    ei_accelerator_type,
    ec2_key_name=None,
    region=DEFAULT_REGION,
    user_data=None,
    iam_instance_profile_name=None,
    instance_name="",
):
    """
    Launch an instance
    :param ami_id: AMI ID to be used for launched instance
    :param instance_type: Instance type of launched instance
    :param region: Region where instance will be launched
    :param user_data: Script to run when instance is launched as a str
    :param iam_instance_profile_arn: EC2 Role to be attached
    :param instance_name: Tag to display as Name on EC2 Console
    :return: <dict> Information about the instance that was launched
    """
    if not ami_id:
        raise Exception("No ami_id provided")
    if not ec2_key_name:
        raise Exception("Ec2 Key name must be provided")
    client = boto3.Session(region_name=region).client("ec2")

    # Construct the dictionary with the arguments for API call
    arguments_dict = {
        "KeyName": ec2_key_name,
        "ImageId": ami_id,
        "InstanceType": instance_type,
        "MaxCount": 1,
        "MinCount": 1,
        "TagSpecifications": [
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": f"CI-CD {instance_name}"}],},
        ],
        "BlockDeviceMappings": [{"DeviceName": "/dev/sda1", "Ebs": {"VolumeSize": 70,}}]
    }
    if user_data:
        arguments_dict["UserData"] = user_data
    if iam_instance_profile_name:
        arguments_dict["IamInstanceProfile"] = {"Name": iam_instance_profile_name}
    if ei_accelerator_type:
        arguments_dict["ElasticInferenceAccelerators"] = ei_accelerator_type
        availability_zones = {
            "us-west": ["us-west-2a", "us-west-2b", "us-west-2c"],
            "us-east": ["us-east-1a", "us-east-1b", "us-east-1c"],
        }
        for a_zone in availability_zones[region]:
            arguments_dict["Placement"] = {"AvailabilityZone": a_zone}
            try:
                response = client.run_instances(**arguments_dict)
                if response and len(response["Instances"]) >= 1:
                    break
            except ClientError as e:
                print(f"Failed to launch in {a_zone} with Error: {e}")
                continue
    else:
        response = client.run_instances(**arguments_dict)

    if not response or len(response["Instances"]) < 1:
        raise Exception(
            "Unable to launch the instance. \
                         Did not return any response"
        )

    return response["Instances"][0]


def get_ec2_client(region):
    return boto3.client("ec2", region_name=region, config=Config(retries={"max_attempts": 10}))


def get_instance_from_id(instance_id, region=DEFAULT_REGION):
    """
    Get instance information using instance ID
    :param instance_id: Instance ID to be queried
    :param region: Region where query will be performed
    :return: <dict> Information about instance with matching instance ID
    """
    if not instance_id:
        raise Exception("No instance id provided")
    client = boto3.Session(region_name=region).client("ec2")
    instance = client.describe_instances(InstanceIds=[instance_id])
    if not instance:
        raise Exception(
            "Unable to launch the instance. \
                         Did not return any reservations object"
        )
    return instance["Reservations"][0]["Instances"][0]


@retry(stop_max_attempt_number=16, wait_fixed=60000)
def get_public_ip(instance_id, region=DEFAULT_REGION):
    """
    Get Public IP of instance using instance ID
    :param instance_id: Instance ID to be queried
    :param region: Region where query will be performed
    :return: <str> IP Address of instance with matching instance ID
    """
    instance = get_instance_from_id(instance_id, region)
    if not instance["PublicIpAddress"]:
        raise Exception("IP address not yet available")
    return instance["PublicIpAddress"]


@retry(stop_max_attempt_number=16, wait_fixed=60000)
def get_public_ip_from_private_dns(private_dns, region=DEFAULT_REGION):
    """
    Get Public IP of instance using private DNS
    :param private_dns:
    :param region:
    :return: <str> IP Address of instance with matching private DNS
    """
    client = boto3.Session(region_name=region).client("ec2")
    response = client.describe_instances(Filters={"Name": "private-dns-name", "Value": [private_dns]})
    return response.get("Reservations")[0].get("Instances")[0].get("PublicIpAddress")


@retry(stop_max_attempt_number=16, wait_fixed=60000)
def get_instance_user(instance_id, region=DEFAULT_REGION):
    """
    Get "ubuntu" or "ec2-user" based on AMI used to launch instance
    :param instance_id: Instance ID to be queried
    :param region: Region where query will be performed
    :return: <str> user name
    """
    instance = get_instance_from_id(instance_id, region)
    user = "ubuntu" if instance["ImageId"] in UL_AMI_LIST else "ec2-user"
    return user


def get_instance_state(instance_id, region=DEFAULT_REGION):
    """
    Get state of instance using instance ID
    :param instance_id: Instance ID to be queried
    :param region: Region where query will be performed
    :return: <str> State of instance with matching instance ID
    """
    instance = get_instance_from_id(instance_id, region)
    return instance["State"]["Name"]


@retry(stop_max_attempt_number=16, wait_fixed=60000)
def check_instance_state(instance_id, state="running", region=DEFAULT_REGION):
    """
    Compares the instance state with the state argument.
    Retries 8 times with 120 seconds gap between retries.
    :param instance_id: Instance ID to be queried
    :param state: Expected instance state
    :param region: Region where query will be performed
    :return: <str> State of instance with matching instance ID
    """
    instance_state = get_instance_state(instance_id, region)
    if state != instance_state:
        raise Exception(f"Instance {instance_id} not in {state} state")
    return instance_state


def get_system_state(instance_id, region=DEFAULT_REGION):
    """
    Returns health checks state for instances
    :param instance_id: Instance ID to be queried
    :param region: Region where query will be performed
    :return: <tuple> System state and Instance state of instance with matching instance ID
    """
    if not instance_id:
        raise Exception("No instance id provided")
    client = boto3.Session(region_name=region).client("ec2")
    response = client.describe_instance_status(InstanceIds=[instance_id])
    if not response:
        raise Exception(
            "Unable to launch the instance. \
                         Did not return any reservations object"
        )
    instance_status_list = response["InstanceStatuses"]
    if not instance_status_list:
        raise Exception(
            "Unable to launch the instance. \
                         Did not return any reservations object"
        )
    if len(instance_status_list) < 1:
        raise Exception(
            "The instance id seems to be incorrect {}. \
                         reservations seems to be empty".format(
                instance_id
            )
        )

    instance_status = instance_status_list[0]
    return (
        instance_status["SystemStatus"]["Status"],
        instance_status["InstanceStatus"]["Status"],
    )


@retry(stop_max_attempt_number=96, wait_fixed=10000)
def check_system_state(instance_id, system_status="ok", instance_status="ok", region=DEFAULT_REGION):
    """
    Compares the system state (Health Checks).
    Retries 96 times with 10 seconds gap between retries
    :param instance_id: Instance ID to be queried
    :param system_status: Expected system state
    :param instance_status: Expected instance state
    :param region: Region where query will be performed
    :return: <tuple> System state and Instance state of instance with matching instance ID
    """
    instance_state = get_system_state(instance_id, region=region)
    if system_status != instance_state[0] or instance_status != instance_state[1]:
        raise Exception(
            "Instance {} not in \
                         required state".format(
                instance_id
            )
        )
    return instance_state


def terminate_instance(instance_id, region=DEFAULT_REGION):
    """
    Terminate EC2 instances with matching instance ID
    :param instance_id: Instance ID to be terminated
    :param region: Region where instance is located
    """
    if not instance_id:
        raise Exception("No instance id provided")
    client = boto3.Session(region_name=region).client("ec2")
    response = client.terminate_instances(InstanceIds=[instance_id])
    if not response:
        raise Exception("Unable to terminate instance. No response received.")
    instances_terminated = response["TerminatingInstances"]
    if not instances_terminated:
        raise Exception("Failed to terminate instance.")
    if instances_terminated[0]["InstanceId"] != instance_id:
        raise Exception("Failed to terminate instance. Unknown error.")


def get_instance_type_details(instance_type, region=DEFAULT_REGION):
    """
    Get instance type details for a given instance type
    :param instance_type: Instance type to be queried
    :param region: Region where query will be performed
    :return: <dict> Information about instance type
    """
    client = boto3.client("ec2", region_name=region)
    response = client.describe_instance_types(InstanceTypes=[instance_type])
    if not response or not response["InstanceTypes"]:
        raise Exception("Unable to get instance details. No response received.")
    if response["InstanceTypes"][0]["InstanceType"] != instance_type:
        raise Exception(
            f"Bad response received. Requested {instance_type} "
            f"but got {response['InstanceTypes'][0]['InstanceType']}"
        )
    return response["InstanceTypes"][0]


def get_instance_details(instance_id, region=DEFAULT_REGION):
    """
    Get instance details for instance with given instance ID
    :param instance_id: Instance ID to be queried
    :param region: Region where query will be performed
    :return: <dict> Information about instance with matching instance ID
    """
    if not instance_id:
        raise Exception("No instance id provided")
    instance = get_instance_from_id(instance_id, region=region)
    if not instance:
        raise Exception("Could not find instance")

    return get_instance_type_details(instance["InstanceType"], region=region)


@retry(stop_max_attempt_number=30, wait_fixed=10000)
def get_instance_num_cpus(instance_id, region=DEFAULT_REGION):
    """
    Get number of VCPUs on instance with given instance ID
    :param instance_id: Instance ID to be queried
    :param region: Region where query will be performed
    :return: <int> Number of VCPUs on instance with matching instance ID
    """
    instance_info = get_instance_details(instance_id, region=region)
    return instance_info["VCpuInfo"]["DefaultVCpus"]


@retry(stop_max_attempt_number=30, wait_fixed=10000)
def get_instance_memory(instance_id, region=DEFAULT_REGION):
    """
    Get total RAM available on instance with given instance ID
    :param instance_id: Instance ID to be queried
    :param region: Region where query will be performed
    :return: <int> Total RAM available on instance with matching instance ID
    """
    instance_info = get_instance_details(instance_id, region=region)
    return instance_info["MemoryInfo"]["SizeInMiB"]

@retry(stop_max_attempt_number=30, wait_fixed=10000)
def get_instance_num_inferentias(instance_id=None, instance_type=None, region=DEFAULT_REGION):
    """
    Get total number of neurons on instance with given instance ID
    :param instance_id: Instance ID to be queried
    :param instance_type: Instance Type to be queried
    :param region: Region where query will be performed
    :return: <int> Number of neurons on instance with matching instance ID
    """
    assert instance_id or instance_type, "Input must be either instance_id or instance_type"
    instance_info = (
        get_instance_type_details(instance_type, region=region)
        if instance_type
        else get_instance_details(instance_id, region=region)
    )
    return sum(neuron_type["Count"] for neuron_type in instance_info["InferenceAcceleratorInfo"]["Accelerators"] if neuron_type["Name"]=="Inferentia")

@retry(stop_max_attempt_number=30, wait_fixed=10000)
def get_instance_num_gpus(instance_id=None, instance_type=None, region=DEFAULT_REGION):
    """
    Get total number of GPUs on instance with given instance ID
    :param instance_id: Instance ID to be queried
    :param instance_type: Instance Type to be queried
    :param region: Region where query will be performed
    :return: <int> Number of GPUs on instance with matching instance ID
    """
    assert instance_id or instance_type, "Input must be either instance_id or instance_type"
    instance_info = (
        get_instance_type_details(instance_type, region=region)
        if instance_type
        else get_instance_details(instance_id, region=region)
    )
    return sum(gpu_type["Count"] for gpu_type in instance_info["GpuInfo"]["Gpus"])


def get_ec2_fabric_connection(instance_id, instance_pem_file, region):
    """
    establish connection with EC2 instance if necessary
    :param instance_id: ec2_instance id
    :param instance_pem_file: instance key name
    :param region: Region where ec2 instance is launched
    :return: Fabric connection object
    """
    user = get_instance_user(instance_id, region=region)
    conn = Connection(
        user=user, host=get_public_ip(instance_id, region), connect_kwargs={"key_filename": [instance_pem_file]}, connect_timeout=18000, 
    )
    return conn


def get_ec2_instance_tags(instance_id, region=DEFAULT_REGION, ec2_client=None):
    ec2_client = ec2_client or get_ec2_client(region)
    response = ec2_client.describe_tags(Filters=[{"Name": "resource-id", "Values": [instance_id]}])
    return {tag["Key"]: tag["Value"] for tag in response.get("Tags")}


def fetch_s3_file_and_get_last_line(s3_location, local_filename="temp.txt"):
    """
    Fetches the s3 file locally and extracts its last line.
    
    :param s3_location: str, s3 uri
    :param local_filename: str, location where s3 file is to be downloaded locally.
    :return: str, The last line of the file
    """
    run(f"rm -rf {local_filename}", hide=True)
    run(f"aws s3 cp {s3_location} {local_filename}", hide=True)
    last_line_of_file = run(f"tail -n1 {local_filename}", hide=True).stdout.strip()
    return last_line_of_file


def execute_asynchronus_testing_using_s3_bucket(
    connection,
    execution_command,
    connection_timeout,
    required_log_ending,
    loop_time=2.5 * 3600,
    log_location_within_ec2="~/container_tests/logs.txt",
    s3_uri_for_saving_permanent_logs=None,
):
    """
    This method uses fabric to run the provided execution_command in asynchronus mode. While the execution command
    is being executed in the image, it keeps on uploading the logs to the s3 bucket at fixed intervals. After a
    loop_time is over, it checks the last line of the uploaded logs to see if it is same as required_log_ending.
    This is mainly used in cases where Fabric behaves in an undesired way due to long living connections.

    :param connection: Fabric connection object
    :param execution_command: str, command that connection.run() will execute
    :param connection_timeout: timeout for fabric connection
    :param required_log_ending: str, The string that is desired to be present at the end of the logs
    :param loop_time: int, seconds for which we would wait for the tests to execute on ec2 instance
    :param log_location_within_ec2: Location within ec2 instance where the logs are being witten.
    :param s3_uri_for_saving_permanent_logs: Location where permanent s3 logs could be saved.
    """
    account_id = os.getenv("ACCOUNT_ID", boto3.client("sts").get_caller_identity()["Account"])
    s3_bucket_name = f"dlc-async-test-{account_id}"
    if not s3_uri_for_saving_permanent_logs:
        unique_id = str(uuid.uuid4())
        unique_id_with_timestamp = f"{unique_id}-{int(time.time())}"
        s3_location = f"s3://{s3_bucket_name}/{unique_id_with_timestamp}.txt"
    else:
        s3_location = s3_uri_for_saving_permanent_logs
    connection.run(execution_command, hide=True, timeout=connection_timeout, asynchronous=True)
    start_time = int(time.time())
    loop_count = 0
    local_filename = s3_location.replace(':','-').replace('/','-')
    last_line_of_log = ""
    line_count_list = []
    # time.sleep(5 * 60)
    # s3_upload_cmd = f"aws s3 cp {log_location_within_ec2} {s3_location}"
    # LOGGER.info(f"Will start uploading the logs at {s3_location}")
    # connection.run(f"while true; do {s3_upload_cmd}; sleep 300; done &", timeout=connection_timeout, asynchronous=True)
    # time.sleep(1 * 60)
    while (int(time.time()) - start_time <= loop_time) and (not last_line_of_log.endswith(required_log_ending)):
        time.sleep(5 * 60)
        loop_count += 1
        connection.run(f"aws s3 cp {log_location_within_ec2} {s3_location}", timeout=connection_timeout)
        last_line_of_log = fetch_s3_file_and_get_last_line(s3_location, local_filename)
        number_of_lines_in_log_file = int(run(f"wc -l {local_filename}", hide=True).stdout.strip().split()[0])
        line_count_list.append(number_of_lines_in_log_file)
        number_of_previous_line_counts_to_check = 3
        if len(line_count_list) >= number_of_previous_line_counts_to_check:
            if all(
                line_count == line_count_list[-1]
                for line_count in line_count_list[-number_of_previous_line_counts_to_check:]
            ):
                # If last 3 runs lead to same line number then it demonstrates no progress and hence we stop.
                LOGGER.info(
                    "No progress reported during last 15 minutes. Job most likely hanged so stopping the execution!!"
                )
                break
        LOGGER.info(f"Fetched file from {s3_location} for {loop_count} number of times")
    
    if not last_line_of_log.endswith(required_log_ending):
        raise ValueError(
            f""" Test failed because the last row is not as expected. \n"""
            f""" Last row in the log file ===> {last_line_of_log} \n"""
            f""" expected ===> {required_log_ending}. \n"""
            f""" Full log ===> {s3_location} \n"""
        )


def get_s3_uri_for_saving_permanent_logs(framework, s3_bucket, test_type="ec2"):
    """
    Helper function to get s3 uri where log files generated within test ec2 instances will be uploaded to.

    :param framework: str, tensorflow, pytorch etc.
    :param s3_bucket: str, name of the bucket where we want to upload the logs.
    :param test_type: str, type of the test
    """
    commit_id = run("""git log --format="%H" -n 1""", hide=True).stdout.strip()
    unique_id = str(uuid.uuid4())
    unique_id_with_timestamp = f"{unique_id}-{int(time.time())}"
    s3_filepath = os.path.join(s3_bucket, test_type, framework, commit_id, f"logs-{unique_id_with_timestamp}.txt")
    s3_permanent_log_upload_uri = f"s3://{s3_filepath}"
    return s3_permanent_log_upload_uri


def execute_ec2_training_test(
    connection,
    ecr_uri,
    test_cmd,
    region=DEFAULT_REGION,
    executable="bash",
    large_shm=False,
    host_network=False,
    container_name="ec2_training_container",
    timeout=18000,
    bin_bash_entrypoint=False,
):
    if executable not in ("bash", "python"):
        raise RuntimeError(f"This function only supports executing bash or python commands on containers")
    if executable == "bash":
        executable = os.path.join(os.sep, "bin", "bash")
    docker_cmd = "nvidia-docker" if "gpu" in ecr_uri else "docker"
    container_test_local_dir = os.path.join("$HOME", "container_tests")
    synapseai_version = get_synapseai_version_from_tag(ecr_uri)
    # Make sure we are logged into ECR so we can pull the image
    connection.run(f"$(aws ecr get-login --no-include-email --region {region})", hide=True)

    # Run training command
    shm_setting = '--shm-size="1g"' if large_shm else ""
    network = '--network="host" ' if host_network else ""
    container_runtime = '--runtime=habana -e HABANA_VISIBLE_DEVICES=all' if "hpu" in ecr_uri else ""
    ompi_mca_btl = '-e OMPI_MCA_btl_vader_single_copy_mechanism=none' if "hpu" in ecr_uri else ""
    cap_add = '--cap-add=sys_nice' if "hpu" in ecr_uri else ""
    ipc = '--ipc=host' if "hpu" in ecr_uri and "pytorch" in ecr_uri else ""
    hpu_env_vars = f'-e GIT_BRANCH={synapseai_version}' if "hpu" in ecr_uri else ""
    habana_container_test_repo = '-v ${HOME}/gaudi-test-suite:/gaudi-test-suite' if "hpu" in ecr_uri else ""
    bin_bash_cmd = "--entrypoint /bin/bash " if bin_bash_entrypoint else ""
    connection.run(
        f"{docker_cmd} run --name {container_name} "
        f"{container_runtime} {ompi_mca_btl} {cap_add} {hpu_env_vars} "
        f"{ipc} {network}-v {container_test_local_dir}:{os.path.join(os.sep, 'test')} "
        f"{habana_container_test_repo} {shm_setting} -itd {bin_bash_cmd}{ecr_uri}",
        hide=True,
    )

    if "habana" in ecr_uri:
        execution_command = f"{docker_cmd} exec --user root {container_name} {executable} -c '{test_cmd}'"
        required_log_ending = "INFO: Exiting the script with code 0 PASS"
        framework = "tensorflow" if "tensorflow" in ecr_uri else "pytorch" if "pytorch" in ecr_uri else None
        test_type = "ec2"
        account_id_prefix = os.getenv("ACCOUNT_ID", boto3.client("sts").get_caller_identity()["Account"])[:3]
        s3_bucket_for_permanent_logs = f"dlinfra-habana-tests-{account_id_prefix}"
        s3_uri_permanent_logs = get_s3_uri_for_saving_permanent_logs(
            framework, s3_bucket=s3_bucket_for_permanent_logs, test_type=test_type
        )
        if framework == "tensorflow":
            execute_asynchronus_testing_using_s3_bucket(
                connection,
                execution_command,
                timeout,
                required_log_ending,
                s3_uri_for_saving_permanent_logs=s3_uri_permanent_logs,
            )
            return
        else:
            run_output = connection.run(execution_command, hide=True, timeout=timeout)
            connection.run(f"aws s3 cp ~/container_tests/logs.txt {s3_uri_permanent_logs}")
            LOGGER.info(f"Uploaded logs at: {s3_uri_permanent_logs}")
            return run_output

    return connection.run(
        f"{docker_cmd} exec --user root {container_name} {executable} -c '{test_cmd}'",
        hide=True,
        timeout=timeout,
    )


def execute_ec2_inference_test(connection, ecr_uri, test_cmd, region=DEFAULT_REGION):
    docker_cmd = "nvidia-docker" if "gpu" in ecr_uri else "docker"
    container_test_local_dir = os.path.join("$HOME", "container_tests")

    # Make sure we are logged into ECR so we can pull the image
    connection.run(f"$(aws ecr get-login --no-include-email --region {region})", hide=True)

    # Run training command
    connection.run(
        f"{docker_cmd} run --name ec2_inference_container -v {container_test_local_dir}:{os.path.join(os.sep, 'test')}"
        f" -itd {ecr_uri} bash",
        hide=True,
    )
    connection.run(
        f"{docker_cmd} exec --user root ec2_inference_container {os.path.join(os.sep, 'bin', 'bash')} -c '{test_cmd}'",
        hide=True,
        timeout=3000,
    )


def execute_ec2_training_performance_test(
    connection, ecr_uri, test_cmd, region=DEFAULT_REGION, post_process=None, data_source="", threshold=None,
):
    docker_cmd = "nvidia-docker" if "gpu" in ecr_uri else "docker"
    container_test_local_dir = os.path.join("$HOME", "container_tests")

    timestamp = time.strftime("%Y-%m-%d-%H-%M-%S")
    log_name = f"{data_source}_results_{os.getenv('CODEBUILD_RESOLVED_SOURCE_VERSION')}_{timestamp}.txt"
    log_location = os.path.join(container_test_local_dir, "benchmark", "logs", log_name)

    # Make sure we are logged into ECR so we can pull the image
    connection.run(f"$(aws ecr get-login --no-include-email --region {region})", hide=True)

    connection.run(f"{docker_cmd} pull -q {ecr_uri}")

    # Run training command, display benchmark results to console
    connection.run(
        f"{docker_cmd} run --user root "
        f"-e LOG_FILE={os.path.join(os.sep, 'test', 'benchmark', 'logs', log_name)} "
        f"-e PR_CONTEXT={1 if is_pr_context() else 0} "
        f"-v {container_test_local_dir}:{os.path.join(os.sep, 'test')} {ecr_uri} "
        f"{os.path.join(os.sep, 'bin', 'bash')} -c {test_cmd}"
    )
    ec2_performance_upload_result_to_s3_and_validate(
        connection, ecr_uri, log_location, data_source, threshold, post_process, log_name,
    )


def execute_ec2_habana_training_performance_test(
    connection, ecr_uri, test_cmd, region=DEFAULT_REGION, data_source="", cards_num=None, timeout=18000):
    docker_cmd = "docker"
    container_test_local_dir = os.path.join("$HOME", "container_tests")

    timestamp = time.strftime("%Y-%m-%d-%H-%M-%S")
    log_name = f"{data_source}_results_{os.getenv('CODEBUILD_RESOLVED_SOURCE_VERSION')}_{timestamp}.txt"
    synapseai_version = get_synapseai_version_from_tag(ecr_uri)
    # Make sure we are logged into ECR so we can pull the image
    connection.run(f"$(aws ecr get-login --no-include-email --region {region})", hide=True)

    connection.run(f"{docker_cmd} pull -q {ecr_uri}")

    container_runtime = '--runtime=habana -e HABANA_VISIBLE_DEVICES=all'
    hpu_env_vars = f'-e CARDS_NUM={cards_num} -e GIT_BRANCH={synapseai_version}'
    ompi_mca_btl = '-e OMPI_MCA_btl_vader_single_copy_mechanism=none'
    cap_add = '--cap-add=sys_nice'
    ipc = '--ipc=host' if "pytorch" in ecr_uri else ""
    habana_container_test_repo = '${HOME}/gaudi-test-suite:/gaudi-test-suite'
    execution_command = f"{docker_cmd} run --user root " \
        f"-e LOG_FILE={os.path.join(os.sep, 'test', 'benchmark', 'logs', log_name)} " \
        f"-e PR_CONTEXT={1 if is_pr_context() else 0} " \
        f"{container_runtime} {ompi_mca_btl} {hpu_env_vars} {cap_add} {ipc} " \
        f"-v {container_test_local_dir}:{os.path.join(os.sep, 'test')} -v {habana_container_test_repo} " \
        f"{ecr_uri} {os.path.join(os.sep, 'bin', 'bash')} -c '{test_cmd}'"
    
    framework = "tensorflow" if "tensorflow" in ecr_uri else "pytorch" if "pytorch" in ecr_uri else None
    account_id_prefix = os.getenv("ACCOUNT_ID", boto3.client("sts").get_caller_identity()["Account"])[:3]
    s3_bucket_for_permanent_logs = f"dlinfra-habana-tests-{account_id_prefix}"
    test_type = "benchmark"
    s3_uri_permanent_logs = get_s3_uri_for_saving_permanent_logs(
        framework, s3_bucket=s3_bucket_for_permanent_logs, test_type=test_type
    )

    if cards_num == 1 and framework == "tensorflow" and "bert" in test_cmd and data_source == "squad":
        LOGGER.info("******** Going for Async Execution ********")
        required_log_ending = "Kudos!! Tensorflow BERT tests executed successfully"
        execute_asynchronus_testing_using_s3_bucket(
            connection,
            execution_command,
            timeout,
            required_log_ending,
            loop_time= 4 * 3600,
            s3_uri_for_saving_permanent_logs=s3_uri_permanent_logs,
        )
        return
    run_output = connection.run(execution_command, timeout=timeout)
    connection.run(f"aws s3 cp ~/container_tests/logs.txt {s3_uri_permanent_logs}")
    LOGGER.info(f"Uploaded logs at: {s3_uri_permanent_logs}")
    return run_output


def execute_ec2_inference_performance_test(
    connection, ecr_uri, test_cmd, region=DEFAULT_REGION, post_process=None, data_source="", threshold=None,
):
    docker_cmd = "nvidia-docker" if "gpu" in ecr_uri else "docker"
    container_test_local_dir = os.path.join("$HOME", "container_tests")
    timestamp = time.strftime("%Y-%m-%d-%H-%M-%S")
    log_name = f"{data_source}_results_{os.getenv('CODEBUILD_RESOLVED_SOURCE_VERSION')}_{timestamp}.txt"
    # Make sure we are logged into ECR so we can pull the image
    connection.run(f"$(aws ecr get-login --no-include-email --region {region})", hide=True)
    connection.run(f"{docker_cmd} pull -q {ecr_uri}")

    # Run training command, display benchmark results to console
    repo_name, image_tag = ecr_uri.split("/")[-1].split(":")
    container_name = f"{repo_name}-performance-{image_tag}-ec2"
    connection.run(
        f"{docker_cmd} run -d --name {container_name} "
        f"-e LOG_FILE={os.path.join(os.sep, 'test', 'benchmark', 'logs', log_name)} "
        f"-v {container_test_local_dir}:{os.path.join(os.sep, 'test')} {ecr_uri}"
    )
    try:
        connection.run(
            f"{docker_cmd} exec --user root {container_name} " f"{os.path.join(os.sep, 'bin', 'bash')} -c {test_cmd}"
        )
    except Exception as e:
        raise Exception("Failed to exec benchmark command.\n", e)
    finally:
        connection.run(f"docker rm -f {container_name}")
    log_location = os.path.join(container_test_local_dir, "benchmark", "logs", log_name)
    ec2_performance_upload_result_to_s3_and_validate(
        connection, ecr_uri, log_location, data_source, threshold, post_process, log_name,
    )


def ec2_performance_upload_result_to_s3_and_validate(
    connection, ecr_uri, log_location, data_source, threshold, post_process, log_name
):
    framework = "tensorflow" if "tensorflow" in ecr_uri else "mxnet" if "mxnet" in ecr_uri else "pytorch"
    framework_version = re.search(r"\d+(\.\d+){2}", ecr_uri).group()
    py_version = "py2" if "py2" in ecr_uri else "py37" if "py37" in ecr_uri else "py3"
    processor = "gpu" if "gpu" in ecr_uri else "cpu"
    work_type = "training" if "training" in ecr_uri else "inference"
    s3_location = os.path.join(
        BENCHMARK_RESULTS_S3_BUCKET, framework, framework_version, "ec2", work_type, processor, py_version, log_name,
    )
    params = {"connection": connection, "log_location": log_location}
    if "threshold" in signature(post_process).parameters:
        params["threshold"] = threshold
    performance_number = post_process(**params)
    unit = (
        "s"
        if work_type == "inference" and framework == "tensorflow"
        else "ms"
        if work_type == "inference" and framework == "pytorch"
        else "s/epoch"
        if work_type == "training" and framework == "pytorch" and data_source == "imagenet"
        else "images/sec"
    )
    description = "p99 latency " if unit == "s" or unit == "ms" else ""
    for k, v in performance_number.items():
        performance_statement = (
            f"{framework} {framework_version} ec2 {work_type} {processor} {py_version} "
            f"{data_source} {k} {description}: {v} {unit}, threshold: {threshold[k]} {unit}"
        )
        connection.run(f"echo {performance_statement} | sudo tee -a {log_location}")
        LOGGER.info(f"{performance_statement}")
    connection.run(f"aws s3 cp {log_location} {s3_location}")
    LOGGER.info(f"To retrieve complete benchmark log, check {s3_location}")

    def _assertion_results():
        if "Cost" in performance_number:
            return performance_number["Cost"] < threshold["Cost"]
        if "Throughput" in performance_number:
            return performance_number["Throughput"] > threshold["Throughput"]
        if len(performance_number) == 0:
            return False
        failure_count = 0
        for k, v in performance_number.items():
            if v > threshold[k]:
                failure_count += 1
        return failure_count <= 2

    for _ in performance_number:
        assert _assertion_results(), (
            f"{framework} {framework_version} ec2 {work_type} {processor} {py_version} {data_source} "
            f"Benchmark Result {performance_number} does not reach the threshold {threshold}"
        )


def post_process_inference(connection, log_location, threshold):
    log_content = connection.run(f"cat {log_location}").stdout.split("\n")
    performance_number = {}
    for line in log_content:
        if "p99" in line:
            for key in threshold.keys():
                if key in line:
                    performance_number[key] = float(
                        re.search(r"(p99[ ]*(Latency)?[ ]*:[ ]*)(?P<result>[0-9]+\.?[0-9]+)", line,).group("result")
                    )
                    break
    return performance_number


def post_process_mxnet_ec2_performance(connection, log_location):
    log_content = connection.run(f"cat {log_location}").stdout.split("\n")
    total = 0.0
    n = 0
    for line in log_content:
        if "samples/sec" in line and "warmup" not in line:
            throughput = re.search(r"((?P<throughput>[0-9]+\.?[0-9]+)[ ]+samples/sec)", line).group("throughput")
            total += float(throughput)
            n += 1
    if total and n:
        return {"Throughput": total / n}
    else:
        raise ValueError("total: {}; n: {} -- something went wrong".format(total, n))
