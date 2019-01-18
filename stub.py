import json, sys, os, glob

from apiscout.ApiScout import ApiScout
from apiscout.ApiVector import ApiVector
from malpediaclient.client import Client as MalpediaClient
from malpediaclient.config import MALPEDIA_USER, MALPEDIA_APIKEY

class OhNo():
    def update_paths(self):
        self.basepath = os.path.dirname(os.path.realpath(__file__))
        self.datapath = os.path.join(self.basepath, "apiscout", "data")

        self.apiscout_profile_path = os.path.join(self.basepath, "apiscout", "dbs", "win7_sp1_x64_vector.json")

        self.update_malpedia_apivector_list()

        self.winapi1024_path = os.path.join(self.datapath, "winapi1024v1.txt")

    def main(self, memory_dump):
        """ poc routine to be adapted in AL """
        self.update_paths()

        vector_info = self.extract_vector(memory_dump, self.apiscout_profile_path, self.winapi1024_path)
        vector = vector_info[1]["vector"]
        matches = self.match_vector(vector, self.apivector_list_path)

        return matches

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
            new_malpedia_file = open(self.apivector_list_path, 'wb')
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

if __name__ == "__main__":
    """ replace inputs with data received from AL """
    # this "dump" contains kernel32!Sleep and kernel32!CreateProcess for Win7 profile
    #memory_dump = bytearray.fromhex("00000000ff10d77d000000007210d77d000000000000000000000000000000000000000000000000")
    memory_dump = open('/home/bobby/repos/al/al_services/alsvc_apivector/PID_150.executable.ex_.dmp1', 'rb').read()
    oh_no = OhNo()
    matches = oh_no.main(memory_dump)
    print(matches)