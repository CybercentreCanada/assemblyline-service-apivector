#!/usr/bin/env python

import os, glob
from assemblyline.al.common.result import Result, ResultSection, SCORE, Classification, Tag, TAG_TYPE, TAG_WEIGHT
from assemblyline.al.service.base import ServiceBase, Category
from assemblyline.common.exceptions import RecoverableError


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
        # "malpedia_user": "",
        # "malpedia_pass": "",
        # remote path on support server holding apiscout DBs from VMs used to generate
        # memory dumps
        "apiscout_remote_path": "apiscout",

        # path to apivector DBs to compare against on the support server
        "apivector_remote_path": "apivector"
    }

    def __init__(self, cfg=None):
        super(ApiVector, self).__init__(cfg)

    # noinspection PyUnresolvedReferences
    def import_service_deps(self):
        global ApiScout
        from apiscout.ApiScout import ApiScout
        
        global ApiVector
        from apiscout.ApiVector import ApiVector

        global MalpediaClient
        from malpediaclient.client import Client as MalpediaClient

        # You must create a config.py file based on the config.template.py file and put your api credentials in it.
        global MALPEDIA_USER, MALPEDIA_APIKEY
        from malpediaclient.config import MALPEDIA_USER, MALPEDIA_APIKEY
        
    def start(self):
        self.log.debug("apivector service started")

    def update_paths(self):
        self.basepath = os.path.dirname(os.path.realpath(__file__))
        self.datapath = os.path.join(self.basepath, "apiscout", "data")

        self.apiscout_profile_path = os.path.join(self.basepath, "apiscout", "dbs", "win7_sp1_x64_vector.json")
        self.log.info("Using apiscout profile file: {}".format(self.apiscout_profile_path))
        if not os.path.exists(self.apiscout_profile_path) or not os.path.isfile(self.apiscout_profile_path):
            self.log.error("There appears to be something wrong with the apiscout profile file: {}".format(self.apiscout_profile_path))

        self.update_malpedia_apivector_list()
        self.log.info("Using apivector list file: {}".format(self.apivector_list_path))
        if not os.path.exists(self.apivector_list_path) or not os.path.isfile(self.apivector_list_path):
            self.log.error("There appears to be something wrong with the apivector list file: {}".format(self.apivector_list_path))

        self.winapi1024_path = os.path.join(self.datapath, "winapi1024v1.txt")
        self.log.info("Using apivector file: {}".format(self.winapi1024_path))
        if not os.path.exists(self.winapi1024_path) or not os.path.isfile(self.winapi1024_path):
            self.log.error("There appears to be something wrong with the apivector file definition: {}".format(self.winapi1024_path))


    def update_malpedia_apivector_list(self):
        malpedia_client = MalpediaClient(MALPEDIA_USER, MALPEDIA_APIKEY)

        newest_malpedia_version = str(malpedia_client.get_version()['version'])
        # remove all other malpedia versions
        for old_apivector_list in glob.glob(os.path.join(self.datapath, "*.malpedia_apivector_list.csv")):
            if not os.path.basename(old_apivector_list).startswith(newest_malpedia_version):
                os.remove(old_apivector_list)

        self.apivector_list_path = os.path.join(self.datapath, "{}.malpedia_apivector_list.csv".format(newest_malpedia_version))

        if not os.path.exists(self.apivector_list_path) and not os.path.isfile(self.apivector_list_path):
            newest_malpedia_info = malpedia_client.list_apiscout_csv()
            new_malpedia_file = open(self.apivector_list_path, 'w')
            new_malpedia_file.write(newest_malpedia_info)
            new_malpedia_file.close()

    def extract_vector(self, memory_dump, apiscout_profile_path, winapi1024_path):
        scout = ApiScout()
        scout.loadDbFile(apiscout_profile_path)
        # TODO depends on setup that produces memory dumps
        scout.ignoreAslrOffsets(True)
        # TODO potentially change this path
        scout.loadWinApi1024(winapi1024_path)
        results = scout.crawl(memory_dump)
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
        if "cuckoo_vm" not in self.submission_tags:
            request.drop()
            return

        self.update_paths()

        path = request.download()
        with open(path, 'r') as f:
            memory_dump = f.read()

        request.result = Result()
        
        vector_info = self.extract_vector(memory_dump, self.apiscout_profile_path, self.winapi1024_path)
        vector = vector_info[1]["vector"]
        matches = self.match_vector(vector, self.apivector_list_path)
    
        r_section = ResultSection(title_text='ApiVector matches')
        r_section.score = SCORE.NULL
        r_section.add_line('Vector: {}'.format(matches['vector']))
        r_section.add_line('Confidence: {}'.format(matches['confidence']))
        r_section.add_line('Collection Filepath: {}'.format(matches['collection_filepath']))
        r_section.add_line('Families in Collection: {}'.format(matches['families_in_collection']))
        r_section.add_line('Vectors in Collection: {}'.format(matches['vectors_in_collection']))
        m_section = ResultSection(title_text='Matches')
        # ouch oof owie my bones
        matches_str_list = ["('{}')".format("', '".join(map(str, stuff))) for stuff in matches['match_results']]

        m_section.add_lines(matches_str_list)
        r_section.add_section(m_section)
   
        request.result.add_section(r_section)
