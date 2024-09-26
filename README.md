[![Discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg?sanitize=true)](https://discord.gg/GUAy9wErNu)
[![](https://img.shields.io/discord/908084610158714900)](https://discord.gg/GUAy9wErNu)
[![Static Badge](https://img.shields.io/badge/github-assemblyline-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline)
[![Static Badge](https://img.shields.io/badge/github-assemblyline\_service\_apivector-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline-service-apivector)
[![GitHub Issues or Pull Requests by label](https://img.shields.io/github/issues/CybercentreCanada/assemblyline/service-apivector)](https://github.com/CybercentreCanada/assemblyline/issues?q=is:issue+is:open+label:service-apivector)
[![License](https://img.shields.io/github/license/CybercentreCanada/assemblyline-service-apivector)](./LICENSE)
# APIVector Service

This service extracts library imports from windows PE files or memory dump to generate api vector classification.

## Service Details

[ApiScout](https://github.com/danielplohmann/apiscout) uses common Windows API calls to build a representation of them called an ApiVector.

It is installed by default but requires some additional configuration before enabling within AssemblyLine.

Initial work for this was done during GeekWeek 5 (https://gitlab.com/GeekWeekV/4.2_malfinder/alsvc_apivector)

See the following links for technical details:

* Academic paper describing ApiScout/ApiVectors and results when applied to the malpedia dataset - https://journal.cecyf.fr/ojs/index.php/cybin/article/view/20
* Code on GitHub - https://github.com/danielplohmann/apiscout
* Blog post - http://byte-atlas.blogspot.com/2017/04/apiscout.html

**NB** : In order for the APIVector AL service to work you need to

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

## Image variants and tags

Assemblyline services are built from the [Assemblyline service base image](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
which is based on Debian 11 with Python 3.11.

Assemblyline services use the following tag definitions:

| **Tag Type** | **Description**                                                                                  |      **Example Tag**       |
| :----------: | :----------------------------------------------------------------------------------------------- | :------------------------: |
|    latest    | The most recent build (can be unstable).                                                         |          `latest`          |
|  build_type  | The type of build used. `dev` is the latest unstable build. `stable` is the latest stable build. |     `stable` or `dev`      |
|    series    | Complete build details, including version and build type: `version.buildType`.                   | `4.5.stable`, `4.5.1.dev3` |

## Running this service

This is an Assemblyline service. It is designed to run as part of the Assemblyline framework.

If you would like to test this service locally, you can run the Docker image directly from the a shell:

    docker run \
        --name Apivector \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-apivector

To add this service to your Assemblyline deployment, follow this
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

General Assemblyline documentation can be found at: https://cybercentrecanada.github.io/assemblyline4_docs/

# Service APIVector

Ce service extrait les importations de libraries des executables Windows ou des fichiers mémoire pour générer une classification vectorielle des api.

## Variantes et étiquettes d'image

Les services d'Assemblyline sont construits à partir de l'image de base [Assemblyline service](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
qui est basée sur Debian 11 avec Python 3.11.

Les services d'Assemblyline utilisent les définitions d'étiquettes suivantes:

| **Type d'étiquette** | **Description**                                                                                                |  **Exemple d'étiquette**   |
| :------------------: | :------------------------------------------------------------------------------------------------------------- | :------------------------: |
|   dernière version   | La version la plus récente (peut être instable).                                                               |          `latest`          |
|      build_type      | Type de construction utilisé. `dev` est la dernière version instable. `stable` est la dernière version stable. |     `stable` ou `dev`      |
|        série         | Détails de construction complets, comprenant la version et le type de build: `version.buildType`.              | `4.5.stable`, `4.5.1.dev3` |

## Exécution de ce service

Il s'agit d'un service d'Assemblyline. Il est optimisé pour fonctionner dans le cadre d'un déploiement d'Assemblyline.

Si vous souhaitez tester ce service localement, vous pouvez exécuter l'image Docker directement à partir d'un terminal:

    docker run \
        --name Apivector \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-apivector

Pour ajouter ce service à votre déploiement d'Assemblyline, suivez ceci
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/fr/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

La documentation générale sur Assemblyline peut être consultée à l'adresse suivante: https://cybercentrecanada.github.io/assemblyline4_docs/
