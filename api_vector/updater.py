import os
import shutil

from assemblyline.common import forge
from assemblyline.common.path import strip_path_inclusion
from assemblyline_client.v4_client.client import Client as Client4
from assemblyline_v4_service.updater.updater import ServiceUpdater, UpdateSource

classification = forge.get_classification()


class APIVectorUpdateServer(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def import_update(self, files_sha256: str, al_client: Client4, source: str, default_classification: str = None):
        if len(files_sha256) != 1:
            # No file were found in the latest source update
            source_config: UpdateSource = [x for x in self._service.update_config.sources if x["name"] == source][0]
            for header in source_config.headers:
                if "<REPLACE_ME>" in header.value:
                    raise Exception("<REPLACE_ME> token found in headers. Make sure to replace it.")
            raise Exception("No file found. Source fetch probably failed.")

        shutil.move(
            files_sha256[0][0],
            os.path.join(self.latest_updates_dir, strip_path_inclusion(source, self.latest_updates_dir)),
        )


if __name__ == "__main__":
    with APIVectorUpdateServer(default_pattern=".*\\.csv") as server:
        server.serve_forever()
