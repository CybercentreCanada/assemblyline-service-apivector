import logging
import os
import tempfile
import time

from assemblyline.common import forge
from assemblyline.common import log as al_log
from assemblyline.odm.models.service import Service, UpdateSource
from assemblyline.odm.models.signature import Signature
from assemblyline_client import get_client
from assemblyline_client.v4_client.client import Client as Client4
from assemblyline_v4_service.updater.helper import (
    SkipSource,
    git_clone_repo,
    url_download,
)
from assemblyline_v4_service.updater.updater import ServiceUpdater, temporary_api_key

al_log.init_logging("updater.apivector")
LOGGER = logging.getLogger("assemblyline.updater.apivector")

classification = forge.get_classification()

UPDATE_DIR = os.path.join(tempfile.gettempdir(), "apivector_updates")
UI_SERVER = os.getenv("UI_SERVER", "https://nginx")


class APIVectorUpdateServer(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.updater_type = "apivector"

    def import_file(self, file_path: str, source: str, al_client: Client4, default_classification: str = None):
        # File is in the following format : malware_family, sample_metadata, _, _, compressed_apivector
        with open(file_path) as fh:
            file_content = fh.read()

        sig = Signature(
            dict(
                classification=default_classification or classification.UNRESTRICTED,
                data=file_content,
                name=source,
                order=1,
                signature_id=source,
                source=source,
                status="DEPLOYED",
                type="apivector",
            )
        )

        r = al_client.signature.add_update(sig.as_primitives(), dedup_name=False)
        return r["success"]

    def do_source_update(self, service: Service) -> None:
        LOGGER.info(f"Connecting to Assemblyline API: {UI_SERVER}...")
        run_time = time.time()
        username = self.ensure_service_account()
        with temporary_api_key(self.datastore, username) as api_key:
            al_client = get_client(UI_SERVER, apikey=(username, api_key), verify=False)
            old_update_time = self.get_source_update_time()

            LOGGER.info("Connected!")

            previous_hashes: dict[str, str] = self.get_source_extra()
            sources: dict[str, UpdateSource] = {_s["name"]: _s for _s in service.update_config.sources}
            files_sha256: dict[str, str] = {}
            old_files_sha256: dict[str, str] = {}
            source_default_classification = {}

            for source_name, source_obj in sources.items():
                source = source_obj.as_primitives()
                uri: str = source["uri"]
                source_default_classification[source_name] = source.get(
                    "default_classification", classification.UNRESTRICTED
                )

                # Replace source headers' environment variables
                if "headers" in source:
                    new_headers = {}
                    for header in source["headers"]:
                        new_headers[header["name"]] = os.path.expandvars(header["value"])
                    source["headers"] = new_headers

                try:
                    if uri.endswith(".git"):
                        files = git_clone_repo(source, old_update_time, "*.csv", LOGGER, UPDATE_DIR)
                        for file, sha256 in files:
                            files_sha256.setdefault(source_name, {})
                            if previous_hashes.get(source_name, {}).get(file, None) != sha256:
                                files_sha256[source_name][file] = sha256
                    else:
                        files = url_download(source, old_update_time, LOGGER, UPDATE_DIR)
                        for file, sha256 in files:
                            files_sha256.setdefault(source_name, {})
                            if previous_hashes.get(source_name, {}).get(file, None) != sha256:
                                files_sha256[source_name][file] = sha256
                except SkipSource:
                    if source_name in previous_hashes:
                        old_files_sha256[source_name] = previous_hashes[source_name]
                    continue

            if files_sha256:
                LOGGER.info("Found new files to process!")
                for source_name, source_file_dict in files_sha256.items():
                    total_imported = 0
                    default_classification = source_default_classification[source_name]
                    for source_file in source_file_dict.keys():
                        total_imported += self.import_file(
                            source_file, source_name, al_client, default_classification=default_classification
                        )
                    LOGGER.info(f"{total_imported} signatures were imported for source {source_name}")
            else:
                LOGGER.info("No new file to process")

            files_sha256.update(old_files_sha256)

        self.set_source_update_time(run_time)
        self.set_source_extra(files_sha256)
        self.set_active_config_hash(self.config_hash(service))
        self.local_update_flag.set()


if __name__ == "__main__":
    with APIVectorUpdateServer() as server:
        server.serve_forever()
