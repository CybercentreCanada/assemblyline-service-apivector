from assemblyline.common import forge
from assemblyline.odm.models.signature import Signature
from assemblyline_client.v4_client.client import Client as Client4
from assemblyline_v4_service.updater.updater import ServiceUpdater

classification = forge.get_classification()


class APIVectorUpdateServer(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def import_update(self, files_sha256: str, al_client: Client4, source: str, default_classification: str = None):
        total_imported = 0
        for file_path, _ in files_sha256:
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
                    type=self.updater_type,
                )
            )

            r = al_client.signature.add_update(sig.as_primitives(), dedup_name=False)
            total_imported += r["success"]
        self.log.info(f"{total_imported} signature(s) were imported for source {source}")


if __name__ == "__main__":
    with APIVectorUpdateServer(default_pattern="*.csv") as server:
        server.serve_forever()
