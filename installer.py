#!/usr/bin/env python

import os

def install(alsi):
    alsi.pip_install('requests>=2.13', 'git+https://github.com/danielplohmann/apiscout')

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    alsi = SiteInstaller()
    install(alsi)


