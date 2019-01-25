#!/usr/bin/env python

"""
This is a hacky way to easily generate the database per VM required for ApiScout / ApiVector (https://github.com/danielplohmann/apiscout)
analysis of memory dumps from Cuckoo.

"""

import base64
import zipfile
import StringIO
import sys
import os
import logging

logging.basicConfig(format='%(asctime)s %(message)s', filename='db_create.log', level=logging.DEBUG)


# This should be replaced by the actual contents for the apiscout repo (zipped and base64 encoded) by the generate_apivector_script.py
APISCOUT_DATA = __APISCOUT_B64__

zip_data = StringIO.StringIO(base64.b64decode(APISCOUT_DATA))
zip_data.seek(0)

logging.info("Extracting data...")
z = zipfile.ZipFile(zip_data)
z.extractall(".")

sys.path.append(os.path.join("apiscout-master","apiscout","db_builder"))

import DatabaseBuilder

# It can be useful to monkeypatch this value for the sake of testing (to reduce the run time)
#DatabaseBuilder.config.DLL_FILTER = ["acgeneral.dll", "ieframe.dll"]

# Just copying the same configuration from https://github.com/danielplohmann/apiscout/blob/master/apiscout/db_builder/DatabaseBuilder.py#L240
builder = DatabaseBuilder.DatabaseBuilder()
logging.info("Running builder.extractRecursively...")
api_db = builder.extractRecursively(None, True)
logging.info("Running extractAslyOffsets..")
api_db = builder.extractAslrOffsets(api_db)
logging.info("persisting...")
builder.persistApiDb(api_db, "C:\\apiscout_db.json")

logging.info("Done!")
