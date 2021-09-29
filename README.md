# ApiVector Service

[ApiScout](https://github.com/danielplohmann/apiscout) uses common Windows API calls to build a representation of them called an ApiVector.

It is installed by default but requires some additional configuration before enabling within AssemblyLine.

Initial work for this was done during GeekWeek 5 (https://gitlab.com/GeekWeekV/4.2_malfinder/alsvc_apivector)

See the following links for technical details:

* Academic paper describing ApiScout/ApiVectors and results when applied to the malpedia dataset - https://journal.cecyf.fr/ojs/index.php/cybin/article/view/20
* Code on GitHub - https://github.com/danielplohmann/apiscout
* Blog post - http://byte-atlas.blogspot.com/2017/04/apiscout.html

**NB** : In order for the ApiVector AL service to work you need to

1. Set the MALPEDIA_APIKEY as an environment variable

To get the most out of the service, you should have a collection of apivectors you want to compare incoming data to.
You can request access to [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/) and request an apikey from them, which this service can use
to regularly pull updates from.

Alternatively, you can generate your own, as long as you follow the format [here](https://github.com/danielplohmann/apiscout/blob/master/dbs/collection_example.csv):
It's a CSV file, using semi-colons as separators:

    malware_family;sample_metadata;0;0;compressed_apivector


## Service Configuration

The following service configuration options are available:
    # Parameters for matching apivector
    # minimum confidence in the apivector match to do anything with it
    "min_confidence": 50,
    # min jaccard score to report as implant family
    # from https://journal.cecyf.fr/ojs/index.php/cybin/article/view/2 , you can set this depending on your
    # tolerance for false positives.
    # Even if set very high, FPs are still possible for samples that share a lot of statically linked code
    # * 0.18 leads to a TPR/FPR of 90.18% and 9.45%
    # * 0.22 leads to a TPR/FPR of 89.10% and 4.74% (closest distance to the (0,1) point)
    # * 0.32 leads to a TPR/FPR of 86.55% and 0.99%
    # * 0.55 leads to a TPR/FPR of 80.72% and 0.09%
    "min_jaccard": 0.40
