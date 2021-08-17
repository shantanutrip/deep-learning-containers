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

from image import DockerImage
from context import Context
from utils import generate_safety_report_for_image

import os

class ConclusionStageImage(DockerImage):
    """
    Class designed to handle the ConclusionStageImages
    """

    def pre_build_configuration(self):
        """
        Conducts all the pre-build configurations from the parent class and then conducts
        Safety Scan on the images generated in previous stage builds. The safety scan generates
        the safety_report which is then baked into the image. 
        """
        ## Call the pre_build_configuration steps from the parent class
        super(ConclusionStageImage, self).pre_build_configuration()
        ## Generate safety scan report for the first stage image and add the file to artifacts
        first_stage_image_uri = self.build_args['FIRST_STAGE_IMAGE']
        processed_image_uri = first_stage_image_uri.replace('.','-').replace('/','-').replace(':','-')
        storage_file_path = f"{os.getenv('PYTHONPATH')}/src/{processed_image_uri}_safety_report.json"
        generate_safety_report_for_image(first_stage_image_uri, storage_file_path=storage_file_path)
        self.context = self.generate_conclude_stage_context(storage_file_path, tarfile_name=processed_image_uri)

    def generate_conclude_stage_context(self, safety_report_path, tarfile_name='conclusion-stage-file'):
        """
        For ConclusionStageImage, build context is built once the safety report is generated. This is because
        the Dockerfile.multipart uses this safety report to COPY the report into the image.
        """
        ARTIFACTS = {}
        ARTIFACTS.update(
                    {
                        "safety_report": {
                            "source": safety_report_path,
                            "target": "safety_report.json"
                        }
                    })
        ARTIFACTS.update(
                    {
                        "dockerfile": {
                            "source": f"Dockerfile.multipart",
                            "target": "Dockerfile",
                        }
                    }
                )
        
        artifact_root = os.path.join(os.sep, os.getenv("PYTHONPATH"), "src") + "/"
        return Context(ARTIFACTS, context_path=f'build/{tarfile_name}.tar.gz',artifact_root=artifact_root)

