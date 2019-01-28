#!/usr/bin/env python

import os

def install(alsi):
    # Get our copy of apiscout as well - use the same one as from pefile
    apiscout_pkg = "apiscout-master.zip"
    remote_path_apiscout = os.path.join('pefile/' + apiscout_pkg)
    local_path_apiscout = os.path.join('/tmp/', apiscout_pkg)
    alsi.fetch_package(remote_path_apiscout, local_path_apiscout)

    alsi.pip_install_all(["requests>=2.13", local_path_apiscout])

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    alsi = SiteInstaller()
    install(alsi)


