#!/usr/bin/env python

import os, glob
from assemblyline.al.common.result import Result, ResultSection, SCORE, Classification, Tag, TAG_TYPE, TAG_WEIGHT
from assemblyline.common.context import Context
from assemblyline.al.service.base import ServiceBase, Category, UpdaterFrequency, UpdaterType
from assemblyline.common.exceptions import RecoverableError
import traceback
from assemblyline.al.common import forge


class ApiVector(ServiceBase):
    SERVICE_CATEGORY = Category.STATIC_ANALYSIS
    SERVICE_ACCEPTS = '.*'
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_VERSION = '1'
    SERVICE_ENABLED = True
    SERVICE_DESCRIPTION = "Gets an ApiVector out of a mem dump and then compares it to the Malpedia ApiVector dataset in order to attribute it to a malware family."
    SERVICE_CPU_CORES = 1
    SERVICE_CPU_RAM = 256

    SERVICE_DEFAULT_CONFIG = {

        # Can be configured to use malpedia directly, or pull down multiple databases from the support server
        "malpedia_apikey": "",

        # remote path on support server holding apiscout DBs from VMs used to generate
        # memory dumps
        "apiscout_dbs_remote_path": "apiscout",

        # The apiscout DBs to download and use. There should be one for each VM you have generating process memory dumps
        "apiscout_dbs": [],

        # path to apivector DBs to compare against on the support server
        "apivector_lists_remote_path": "apivector_lists",

        # The apivector DBs to retrieve from the support server
        "apivector_lists": []
    }

    def __init__(self, cfg=None):
        config = forge.get_config()
        self.local_db_path = os.path.join(config.system.root, "apivector", "db")
        self.local_list_path = os.path.join(config.system.root, "apivector", "lists")
        super(ApiVector, self).__init__(cfg)

    # noinspection PyUnresolvedReferences
    def import_service_deps(self):
        global ApiScout, ApiVector, apiscout
        from apiscout.ApiScout import ApiScout
        from apiscout.ApiVector import ApiVector
        import apiscout

        global requests
        import requests

    def sysprep(self):
        for d in [self.local_db_path, self.local_list_path]:
            if not os.path.exists(d):
                os.makedirs(d)
        global requests
        import requests
        # Make sure the updater gets called at svc init so we have the latest data
        # TODO - uncomment for prod
        #self._svc_updater()

    def start(self):
        self.log.debug("apivector service started")

        self._register_update_callback(self._svc_updater, execute_now=False,
                                       blocking=False,
                                       utype=UpdaterType.BOX,
                                       freq=UpdaterFrequency.DAY)

        module_path = os.path.dirname(os.path.realpath(apiscout.__file__))
        self.winapi1024_path = os.sep.join([module_path, "data", "winapi1024v1.txt"])

    def update_malpedia_apivector_list(self):
        log = self.log.getChild("malpedia_update")
        if len(self.cfg.get("malpedia_apikey")) > 0:
            update_url = "https://malpedia.caad.fkie.fraunhofer.de/api/list/apiscout/csv"
            log.info("Making requeest to get latest apiscout csv from malpedia %s..." % update_url)
            try:
                malpedia_req = requests.get(update_url,
                                            headers={"Authorization": "apitoken %s" % self.cfg.get("malpedia_apikey")})
            except:
                self.log.error("Error getting malpedia data. Traceback: %s" % traceback.format_exc())
                return

            # Make sure we actaully have content
            if len(malpedia_req.content) < 20:
                self.log.error("Return from malpedia was very small, there was probably an error")
                return

            malpedia_path = os.path.join(self.local_list_path, "malpedia.csv")
            log.info("Writing output to %s" % malpedia_path)
            with open(malpedia_path, "w") as fh:
                fh.write(malpedia_req.content)

    def _svc_updater(self):

        log = self.log.getChild("svc_updater")

        sp_filestore = forge.get_support_filestore()
        import pprint
        self.log.info("Running with config: %s" % pprint.pformat(self.cfg))

        for remote_dir, remote_files, local_dir in [(
            self.cfg.get("apiscout_dbs_remote_path"), self.cfg.get("apiscout_dbs"), self.local_db_path),
             (self.cfg.get("apivector_lists_remote_path"), self.cfg.get("apivector_lists"), self.local_list_path)]:

            log.info("Working on %s" % remote_dir)
            for f in remote_files:
                log.info("Downloading %s/%s" % (remote_dir, f))
                sp_filestore.download(os.path.join(remote_dir, f), os.path.join(local_dir, f + ".tmp"))
                os.rename(os.path.join(local_dir, f + ".tmp"), os.path.join(local_dir, f))

            # Make sure these are the only files held locally
            local_files = os.listdir(local_dir)
            valid_files = remote_files + ["malpedia.csv"]
            for local_file in local_files:
                if local_file not in valid_files:
                    os.unlink(os.path.join(local_dir, local_file))

        self.update_malpedia_apivector_list()

    def extract_vector(self, memory_dump, apiscout_profile_path):

        scout = ApiScout()
        scout.loadDbFile(apiscout_profile_path)
        # TODO depends on setup that produces memory dumps
        scout.ignoreAslrOffsets(True)
        # TODO potentially change this path
        scout.loadWinApi1024(self.winapi1024_path)
        self.log.debug("crawling memdump...")
        results = scout.crawl(memory_dump)
        self.log.debug("... done crawling memdump")
        # experience tells that neighborhood filter of 32 produces good results
        filtered_results = scout.filter(results, 0, 0, 32)
        all_vectors = scout.getWinApi1024Vectors(filtered_results)
        primary_vector = scout.getPrimaryVector(all_vectors)
        return primary_vector

    def match_vector(self, vector, collection):
        apivector = ApiVector(self.winapi1024_path)
        results = apivector.matchVectorCollection(vector, collection)
        return results

    def execute(self, request):

        # Check to see what VM generated this
        # also, this is a kind of file type checker - we don't have a good way to ID
        # memory dumps
        vm_name = self.submission_tags.get("vm_name",
                                           request.task.submission["metadata"].get("vm_name"))
        if not vm_name:
            request.drop()
            return

        # Make sure we have a profile to work with
        apiscout_profile = os.path.join(self.local_db_path, vm_name + ".json")
        if not os.path.exists(apiscout_profile):
            self.log.warning("No apiscout profile found for %s. Can't proceed with analysis" % vm_name)
            request.drop()
            return

        memory_dump = request.get()

        request.result = Result()

        self.log.debug("Extracting vector..")
        vector_info = self.extract_vector(memory_dump, apiscout_profile)
        self.log.debug("Done extracting vector from memdump")
        vector = vector_info[1]["vector"]
        apivector_str = "%d:%d:%s" % (
            vector_info[1].get("in_api_vector", 0),
            vector_info[1].get("num_unique_apis", 0),
            vector_info[1].get("vector", "")
        )
        # self.log.info("got apivector str: %s" % apivector_str)
        request.result.add_tag(TAG_TYPE.PE_APIVECTOR, apivector_str, context=Context.DYNAMIC)


        csv_list = os.listdir(self.local_list_path)
        for apiscout_csv in [x for x in csv_list if x.endswith(".csv")]:
            self.log.debug("Checking for matches...")
            # see https://github.com/danielplohmann/apiscout/blob/master/apiscout/ApiVector.py#L205
            # for details on what match_vector returns
            # the "match_results" key  returns a list of tuples in format:
            #   (family, sample, jaccard_index_percentage_match)
            matches = self.match_vector(vector, os.path.join(self.local_list_path, apiscout_csv))
            self.log.debug("done checking for matches")

            r_section = ResultSection(title_text='ApiVector Information')
            r_section.score = SCORE.NULL
            r_section.add_line('Vector: {}'.format(matches['vector']))
            # confidence is calculated based on APIs less common than top75 and total number of APIs in the vector
            r_section.add_line('Confidence: {}'.format(matches['confidence']))
            r_section.add_line('Collection Filepath: {}'.format(matches['collection_filepath']))
            r_section.add_line('Families in Collection: {}'.format(matches['families_in_collection']))
            r_section.add_line('Vectors in Collection: {}'.format(matches['vectors_in_collection']))


            # get a list of all the specific matches
            # We only care about providing these matches if the confidence is above some
            # threshold
            if matches['confidence'] > 50:
                m_section = ResultSection(title_text='Matches')
                # only provide the top ten matches
                matches_str_list = ["('{}')".format("', '".join(map(str, stuff))) for stuff in matches['match_results']][:10]

                for family, sample, jaccard_score in matches["match_results"]:
                    if jaccard_score > 0.75:
                        # report the family as implant family
                        request.result.add_tag(TAG_TYPE.IMPLANT_FAMILY, family)

                m_section.add_lines(matches_str_list)
                r_section.add_section(m_section)

            request.result.add_section(r_section)
