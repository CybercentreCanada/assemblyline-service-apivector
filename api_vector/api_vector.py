import json
import os
import re
import shutil
import tarfile
import tempfile
import time
from pathlib import Path

import lief
import requests
from apiscout import ApiVector
from apiscout.ApiQR import ApiQR
from assemblyline.common import forge
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection

UPDATES_HOST = os.environ.get("updates_host")
UPDATES_PORT = os.environ.get("updates_port")
UPDATES_KEY = os.environ.get("updates_key")

classification = forge.get_classification()


class API_VECTOR(ServiceBase):
    def __init__(self, config=None):
        super(API_VECTOR, self).__init__(config)
        self.collection_filepaths = {}

        # Updater-related
        self.rules_directory = None
        self.update_time = None

    def _update_datasources(self):
        url_base = f"http://{UPDATES_HOST}:{UPDATES_PORT}"
        headers = {"X_APIKEY": UPDATES_KEY}

        # Check if there are new
        while True:
            resp = requests.get(f"{url_base}/status")
            resp.raise_for_status()
            status = resp.json()
            if self.update_time is not None and self.update_time >= status["local_update_time"]:
                return False
            if status["download_available"]:
                break
            self.log.warning("Waiting on update server availability...")
            time.sleep(10)

        # Download the current update
        temp_directory = tempfile.mkdtemp()
        buffer_handle, buffer_name = tempfile.mkstemp()
        try:
            with os.fdopen(buffer_handle, "wb") as buffer:
                resp = requests.get(f"{url_base}/tar", headers=headers)
                resp.raise_for_status()
                for chunk in resp.iter_content(chunk_size=1024):
                    buffer.write(chunk)

            tar_handle = tarfile.open(buffer_name)
            tar_handle.extractall(temp_directory)
            self.update_time = status["local_update_time"]
            self.rules_directory, temp_directory = temp_directory, self.rules_directory
        finally:
            os.unlink(buffer_name)
            if temp_directory is not None:
                shutil.rmtree(temp_directory, ignore_errors=True)

        temp_collection_filepaths = [
            (os.basename(f), str(f)) for f in Path(self.rules_directory).rglob("*") if os.path.isfile(str(f))
        ]

        temp_list = {}
        for source_obj in self.service_attributes.update_config.sources:
            source = source_obj.as_primitives()
            for signature_file, signature_path in temp_collection_filepaths:
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
        self.min_jaccard = self.config.get("min_jaccard", 0.40)

        self._update_datasources()

    def execute(self, request: ServiceRequest):
        request.result = Result()
        self.file_res = request.result
        self.path = request.file_path
        self.request = request

        self.pe = lief.parse(self.path)

        import_list = set()
        for library in self.pe.imports:
            library_name = library.name[:-4].lower() if library.name.endswith(".dll") else library.name.lower()
            for function in library.entries:
                import_list.add(f"{library_name}!{function.name.rstrip('AW').lower()}")
        import_list = [re.sub("msvcrt[0-9]+!", "msvcrt!", x) for x in import_list]
        res = self.apivector.getApiVectorFromApiList(import_list)
        res["vector_confidence"] = self.apivector.getVectorConfidence(res["user_list"]["vector"])

        temp_path = os.path.join(self.working_directory, "api_vector.json")
        with open(temp_path, "w") as f:
            f.write(json.dumps(res))
        request.add_supplementary(temp_path, "api_vector.json", "ApiScout result as a JSON file")

        vector = res["user_list"]["vector"]
        self.apiQR.setVector(vector)
        temp_path = os.path.join(self.working_directory, "api_vector_qr.png")
        self.apiQR.exportPng(temp_path)
        request.add_supplementary(temp_path, "api_vector_qr.png", "QR-like representation of the APIVector, as a PNG")

        r_section = ResultSection(title_text="ApiVector Collection Information")
        r_section.add_line(f"Vector: {vector}")

        for collection_name, collection_metadata in self.collection_filepaths.items():
            matches = self.apivector.matchVectorCollection(vector, collection_metadata["path"])
            if matches["confidence"] > self.min_confidence:
                c_section = ResultSection(
                    title_text=f"ApiVector Collection Information - {collection_name}",
                    classification=collection_metadata["classification"],
                )
                c_section.add_line(f"Confidence: {matches['confidence']}")
                # Get the top-10 matches over the minimum threshold
                matches_str_list = [
                    f"{result[0]} ({result[2]})" for result in matches["match_results"] if result[2] > self.min_jaccard
                ][:10]
                c_section.add_lines(matches_str_list)
                r_section.add_subsection(c_section)

        self.file_res.add_section(r_section)

    def _cleanup(self) -> None:
        super()._cleanup()
        self._update_datasources()
