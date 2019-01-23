#!/usr/bin/env python

import requests
import base64

def main():
    print "Downloading apiscout..."
    r = requests.get("https://github.com/danielplohmann/apiscout/archive/master.zip")
    apiscout_data = base64.b64encode(r.content)

    with open("create_apivector_db.template.py", "r") as template_fh:
        template_data = template_fh.read()

        # replace the placeholder with the data
        out_data = template_data.replace("__APISCOUT_B64__", "\"%s\"" % apiscout_data)

        print "Writing output file.."
        with open("create_apivector_db.py", "w") as output_fh:
            output_fh.write(out_data)

    print "Done!"

if __name__ == "__main__":
    main()