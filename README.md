# ApiVector Service

Initial work for this done during GeekWeek 5 (https://gitlab.com/GeekWeekV/4.2_malfinder/alsvc_apivector)

See https://github.com/danielplohmann/apiscout and http://byte-atlas.blogspot.com/2017/04/apiscout.html
for technical details.

## Service Configuration



### ApiScout Database Generation

One of the pre-requisites for ApiScout to work is a database of the available APIs. 
This database needs to be built for **each** VM.

There are two ways you can generate this database:

1. Copy the [apiscout repo](https://github.com/danielplohmann/apiscout/archive/master.zip) into  your analysis VM(s)
and run the apiscout\db_build\DatabaseBuilder.py script, then extract the generated .json file.

2. OR - use the scripts provided in this repo to (hopefully) simplify this:

    * Run `generate_apivector_script.py`. This will download the apiscout repo and base64 encode the zip file inside of 
    a python script: `create_apivector_db.py`
    * Submit this script for 'analysis' to each VM used by Cuckoo. Make sure to set the following submission parameters for Cuckoo:
        * Increase the analysis timeout - the script seems to take about 8 minutes or so
        * Run with 'free=yes' - the monitor seems to slow down the script 
        * pass 'filepickup=c:\\apiscout_db.json' - filepickup is an auxiliary module included in the [al_cuckoo_community](https://bitbucket.org/cse-assemblyline/al_cuckoo_community/src) repo.
        since we're running without the monitor, we need some way to pick up the apiscout DB

Using the AssemblyLine client, you can do something like this:

```
al-submit -u AL_USER -p AL_PASSWORD -s https://AL_SERVER -j '{"selected":["Cuckoo"]}' --srv-spec '{"Cuckoo": {"analysis_timeout": 550, "custom_options": "free=yes,filepickup=c:\\apiscout_db.json"}}' -i create_apivector_db.py >/dev/null
```

Once you've generated the json database files (`apiscout_db.json`), copy them to your support server. For example: on a default appliance 
assuming your VM is named `inetsim_win7`, copy the generated database file to `/opt/al/var/support/apiscout/inetsim_win7.json`.

You'll also have to let the ApiVector service know by adding the filename to `apiscout_dbs` service configuration parameter 
(avatar -> Services -> ApiVector)

