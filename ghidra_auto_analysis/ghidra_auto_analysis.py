"""Analyse binary with Ghidra and output an analysis database"""

import os
from pathlib import Path
from typing import Dict

from assemblyline.common import forge
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import KVSectionBody, Result, ResultSection, SectionBody

from assemblyline_v4_service.common.task import PARENT_RELATION
import pyghidra

class GhidraAutoAnalysis(ServiceBase):
    """Analyse binary with Ghidra and output an analysis database"""

    def start(self):
        if not os.getenv("GHIDRA_INSTALL_DIR"):
            self.log.error("GHIDRA_INSTALL_DIR environment variable not set")
            raise Exception("GHIDRA_INSTALL_DIR environment variable not set")

        if not pyghidra.started():
            self.log.info("Starting Ghidra")
            pyghidra.start()

    def execute(self, request: ServiceRequest):
        """Run the service."""
        result = Result()

        with pyghidra.open_program(
            binary_path=request.file_path,
            project_name=request.file_name,
            project_location=self.working_directory
        ) as program:
            self.log.info(f"Analyzing {request.file_name} with Ghidra")
            metadata = dict(program.getMetadata())
            metadata_section_body = KVSectionBody()
            for key, value in metadata.items():
                metadata_section_body.set_item(key, value)
            metadata_section = ResultSection(title_text="Ghidra Metadata", body=metadata_section_body)

            # Extract libraries
            for key, value in metadata.items():
                if key.startswith("Required Library"):
                    metadata_section.add_tag("file.library", value)

            # Add tags:
            meta_to_tag: Dict[str, str] = {
                "Compiler ID": "file.compiler",
                "Compiler": "file.compiler",
            }

            for meta_key, tag_key in meta_to_tag.items():
                if meta_key in metadata:
                    metadata_section.add_tag(tag_key, metadata[meta_key])

            result.add_section(metadata_section)

            output_path = Path(self.working_directory) / f"{request.file_name}.gzf"
            with open(output_path, "wb") as output_file:
                program.getDomainFile().packfile(output_file)

            request.add_supplementary(
                path=str(output_path),
                name=f"{request.file_name}.gzf",
                description="Ghidra analysis database",
                parent_relation=PARENT_RELATION.INFORMATION,
            )
        request.result = result
