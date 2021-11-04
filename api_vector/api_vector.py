import json
import os
import re

import lief
import ordlookup
from apiscout import ApiVector
from apiscout.ApiQR import ApiQR
from assemblyline.common import forge
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    Result,
    ResultImageSection,
    ResultSection,
)

classification = forge.get_classification()


class API_VECTOR(ServiceBase):
    def __init__(self, config=None):
        super(API_VECTOR, self).__init__(config)
        self.collection_filepaths = {}

    def _load_rules(self) -> None:
        temp_list = {}
        for source_obj in self.service_attributes.update_config.sources:
            source = source_obj.as_primitives()
            for signature_path in self.rules_list:
                signature_file = os.path.basename(signature_path)
                if signature_file == source["name"]:
                    temp_list[signature_file] = {
                        "path": signature_path,
                        "classification": source.get("default_classification", classification.UNRESTRICTED),
                    }
        self.log.info(f"Will load the following files: {temp_list}")
        self.collection_filepaths = temp_list

    def start(self):
        self.log.info("Starting API_VECTOR")
        winapi_file = os.path.join(os.path.dirname(__file__), "winapi1024v1.txt")
        self.apivector = ApiVector.ApiVector(winapi_file)
        self.apiQR = ApiQR(winapi_file)

        self.min_confidence = self.config.get("min_confidence", 50)
        self.min_jaccard_info = self.config.get("min_jaccard_info", 40) / 100
        self.min_jaccard_tag = self.config.get("min_jaccard_tag", 80) / 100

    def execute(self, request: ServiceRequest):
        request.result = Result()
        self.file_res = request.result
        self.path = request.file_path
        self.request = request

        self.pe = lief.parse(self.path)

        import_list = set()
        for library in self.pe.imports:
            library_name = library.name[:-4].lower() if library.name.endswith(".dll") else library.name.lower()
            for entry in library.entries:
                if entry.is_ordinal:
                    import_name = ordlookup.ordLookup(str.encode(library.name), entry.ordinal, make_name=False)
                    entry_name = str(entry.ordinal) if import_name is None else import_name.decode()
                    import_list.add(f"{library_name}!{entry_name.rstrip('AW').lower()}")
                else:
                    import_list.add(f"{library_name}!{entry.name.rstrip('AW').lower()}")
        import_list = [re.sub("msvcrt[0-9]+!", "msvcrt!", x) for x in import_list]
        res = self.apivector.getApiVectorFromApiList(import_list)
        res["vector_confidence"] = self.apivector.getVectorConfidence(res["user_list"]["vector"])

        temp_path = os.path.join(self.working_directory, "apivector.json")
        with open(temp_path, "w") as f:
            f.write(json.dumps(res))
        request.add_supplementary(temp_path, "apivector.json", "ApiScout result as a JSON file")

        vector = res["user_list"]["vector"]
        self.apiQR.setVector(vector)
        temp_path = os.path.join(self.working_directory, "apivector_qr.png")
        self.apiQR.exportPng(temp_path)
        image_section = ResultImageSection(self.request, "APIVector QR-like")
        image_section.add_image(temp_path, "apivector_qr.png", "QR-like representation of the APIVector")
        self.file_res.add_section(image_section)

        r_section = ResultSection(title_text="ApiVector Information")
        r_section.add_line(f"Vector: {vector}")
        r_section.add_tag("vector", f"apivector_{vector}")

        for collection_name, collection_metadata in self.collection_filepaths.items():
            matches = self.apivector.matchVectorCollection(vector, collection_metadata["path"])
            if matches["confidence"] > self.min_confidence:
                c_section = ResultSection(
                    title_text=f"ApiVector Collection Information - {collection_name}",
                    classification=collection_metadata["classification"],
                )
                c_section.add_line(f"Confidence: {matches['confidence']}")
                for result in matches["match_results"]:
                    if result[2] > self.min_jaccard_info:
                        c_section.add_line(f"{result[0]} ({result[2]})")
                    if result[2] > self.min_jaccard_tag:
                        c_section.add_tag("attribution.family", f"apivector_{result[0]}")

                r_section.add_subsection(c_section)

        self.file_res.add_section(r_section)
