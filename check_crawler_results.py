#!/usr/bin/python

#***************************************************************************
# Copyright 2015 IBM
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#***************************************************************************

import json
import logging
import logging.handlers
import os
import os.path
import requests
import sys
import time
import timeit
from datetime import datetime
from subprocess import Popen, PIPE

# ascii color codes for output
LABEL_GREEN='\033[0;32m'
LABEL_RED='\033[0;31m'
LABEL_COLOR='\033[0;33m'
LABEL_NO_COLOR='\033[0m'
STARS="**********************************************************************"

# base locations to get the info
CALL_VIA_API=True
API_VULN_BASE_TEMPLATE="%s/v3/containers/images/validate"
API_COMP_BASE_TEMPLATE="%s/v3/containers/images/validate?compliance=t"
VULN_BASE_TEMPLATE="http://%s/vulnerabilityscan-*/vulnerabilityscan/_search?pretty"
COMP_BASE_TEMPLATE="http://%s/compliance-*/_search?pretty"
VULN_BASE_URL=""
COMP_BASE_URL=""
BODY_TEMPLATE="{ \"query\": { \"bool\":{ \"must\": [ { \"match_phrase_prefix\": { \"namespace.raw\" : \"%s\" } } ] } }, \"size\":\"100\" }"
API_BODY_TEMPLATE="{ \"name\": \"%s\" }"
API_SERVER=""
CRAWLER_SERVER=""

# compliance IDs to skip (don't need to report the "summary" id as a separate result)
COMP_IDS_TO_IGNORE=["Linux.0-0-a"]
VULN_IDS_TO_IGNORE=[]

# call information for authentication
BEARER_TOKEN=""
SPACE_GUID=""

# last image checked
last_image_id=None

DEBUG=os.environ.get('DEBUG')
# time to sleep between checks when waiting on pending jobs, in seconds
SLEEP_TIME=30

SCRIPT_START_TIME = timeit.default_timer()
LOGGER = None
WAIT_TIME = 0

# load bearer token and space guid from ~/.cf/config.json
def load_cf_auth_info ():
    global BEARER_TOKEN, SPACE_GUID

    cf_filename = "%s/.cf/config.json" % os.path.expanduser("~")

    with open( cf_filename ) as cf_config_file:
        config_info = json.load(cf_config_file)
        BEARER_TOKEN = config_info["AccessToken"]
        if BEARER_TOKEN.lower().startswith("bearer "):
            BEARER_TOKEN=BEARER_TOKEN[7:]
        SPACE_GUID = config_info["SpaceFields"]["Guid"]

# check with cf to find the api server, adjust to find the
# ICE api server
def find_ice_api_server ():
    global API_SERVER

    command = "cf api"
    proc = Popen([command], shell=True, stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate();

    if proc.returncode != 0:
        msg = "Error: Unable to find api server, rc was " + str(proc.returncode)
        LOGGER.error(msg)
        raise Exception(msg)

    # cf api output comes back in the form:
    # API endpoint: https://api.ng.bluemix.net (API version: 2.23.0)
    # so take out just the part we need
    words = out.split()
    for word in words:
        if word.startswith("https://"):
            API_SERVER=word
    # point to ice server, not cf server
    API_SERVER = API_SERVER.replace ( 'api.', 'containers-api.')
    if DEBUG=="1":
        LOGGER.debug("API SERVER set to " + str(API_SERVER))

# check cli args, set globals appropriately
def parse_args ():
    global LOGGER, WAIT_TIME, VULN_BASE_URL, COMP_BASE_URL, API_SERVER, CRAWLER_SERVER, DEBUG, CALL_VIA_API
    parsed_args = {}
    parsed_args['nocompcheck'] = False
    parsed_args['novulncheck'] = False
    parsed_args['calldirect'] = False
    parsed_args['hidepass'] = False
    parsed_args['images'] = []
    parsed_args['debug'] = False
    parsed_args['help'] = False
    # check command line args
    for idx, arg in enumerate(sys.argv):
        if idx == 0:
            # don't worry about the calling parm at this time
            continue
        if arg == "--nocompcheck":
            # only check vulnerabilities
            parsed_args['nocompcheck'] = True
        if arg == "--novulncheck":
            # only check compliance
            parsed_args['novulncheck'] = True
        if arg == "--calldirect":
            # call direct mode - bypass the api server and go straight to the crawler server
            parsed_args['calldirect'] = True
            CALL_VIA_API = False
        if arg == "--hidepass":
            # don't print checks that passed
            parsed_args['hidepass'] = True
        if arg == "--debug":
            # enable debug mode, can also be done with DEBUG env var
            parsed_args['debug'] = True
            DEBUG = "1"
        if arg == "--help":
            # just print help and return
            parsed_args['help'] = True
        if not arg.startswith("--"):
            # add this as an image to be checked
            parsed_args['images'].append(arg)

    # check for env var args that we may need as well
    image_name = os.environ.get('IMAGE_NAME')
    if image_name:
        parsed_args['images'].append(image_name)
    call_direct_env = os.environ.get('CC_CALLDIRECT')
    if call_direct_env:
        # call direct mode - bypass the api server and go straight to the crawler server
        parsed_args['calldirect'] = True
        CALL_VIA_API = False

    LOGGER = setup_logging()

    # set up the server urls
    if CALL_VIA_API:
        find_ice_api_server()
        if not API_SERVER:
            msg = "Cannot determine correct api server, unable to place queries"
            LOGGER.error( msg )
            raise Exception( msg )
    else:
        CRAWLER_SERVER = os.environ.get('CRAWLER_SERVER')
        if not CRAWLER_SERVER:
            msg = "CRAWLER_SERVER is not set, unable to place queries"
            LOGGER.error( msg )
            raise Exception( msg )
        VULN_BASE_URL=VULN_BASE_TEMPLATE % CRAWLER_SERVER
        COMP_BASE_URL=COMP_BASE_TEMPLATE % CRAWLER_SERVER

    # load creds
    load_cf_auth_info()

    # see how much time we have left after completing init
    WAIT_TIME = get_remaining_wait_time(first = True)

    return parsed_args

# print a quick usage/help statement
def print_help ():
    print "usage: check_crawler_results.py [options] imagename1 [ imagename2 [...] ] ]"
    print
    print "\toptions:"
    print "\t   --nocompcheck  : don't check compliance"
    print "\t   --novulncheck  : don't check security vulnerabilities"
    print "\t   --calldirect   : call the crawler server directly, instead of going through the API server"
    print "\t                    This requires direct VPN connection"
    print "\t   --hidepass     : hide full description information for checks that pass"
    print "\t   --debug        : get additional debug output"
    print "\t   --help         : print this help message and exit"
    print
    print "\tExpected env vars:"
    print "\t   WAIT_TIME      : time (in minutes) to wait for results before giving up.  Default 5"
    print "\t   DEBUG          : if is 1, then include debug messages"
    print "\t   IMAGE_NAME     : image name to scan.  can also be passed on the command line"
    if not CALL_VIA_API:
        print "\t   CRAWLER_SERVER : the hostname of the server to query.  no default, will fail if not set"
    print


# setup logmet logging connection if it's available
def setup_logging ():
    logger = logging.getLogger('pipeline')
    if DEBUG:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    # if logmet is enabled, send the log through syslog as well
    if os.environ.get('LOGMET_LOGGING_ENABLED'):
        handler = logging.handlers.SysLogHandler(address='/dev/log')
        logger.addHandler(handler)
        # don't send debug info through syslog
        handler.setLevel(logging.INFO)

    # in any case, dump logging to the screen
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    if DEBUG:
        handler.setLevel(logging.DEBUG)
    else:
        handler.setLevel(logging.INFO)
    logger.addHandler(handler)
    
    return logger

# return the remaining time to wait
# first time, will prime from env var and subtract init script time 
#
# return is the expected max time left in seconds we're allowed to wait
# for pending jobs to complete
def get_remaining_wait_time (first = False):
    if first:
        # first time through, set up the var from env
        try:
            time_to_wait = int(os.getenv('WAIT_TIME', "5")) * 60
        except ValueError:
            time_to_wait = 300

        # and (if not 0) subtract out init time
        if time_to_wait != 0:
            try:
                initTime = int(os.getenv("INT_EST_TIME", "0"))
            except ValueError:
                initTime = 0

            time_to_wait -= initTime
    else:
        # just get the initial start time
        time_to_wait = WAIT_TIME

    # if no time to wait, no point subtracting anything
    if time_to_wait != 0:
        time_so_far = int(timeit.default_timer() - SCRIPT_START_TIME)
        time_to_wait -= time_so_far

    # can't wait negative time, fix it
    if time_to_wait < 0:
        time_to_wait = 0

    return time_to_wait

# given an image name, get the id for it
def get_image_id_for_name( imagename ):
    if not imagename:
        return None

    xheaders = {
        'content-type': 'application/json',
        'X-Auth-Token': BEARER_TOKEN,
        'X-Auth-Project-Id': SPACE_GUID
    }

    url = "%s/v3/containers/images/json" % API_SERVER
    if DEBUG=="1":
        LOGGER.debug("Sending request \"" + str(url) + "\" with headers \"" + str(xheaders) + "\"")
    res = requests.get(url, headers=xheaders)

    if DEBUG=="1":
        LOGGER.debug("received status " + str(res.status_code) + " and data " + str(res.text))

    if res.status_code != 200:
        return None

    image_list = res.json()
    for image in image_list:
        if image["Image"] == imagename:
            if "Id" in image:
                return image["Id"]

    return None

# get the vulnerability info for a given image name, if any
def get_vuln_info ( imagename ):
    if not imagename:
        return None

    xheaders = {
        'content-type': 'application/json',
        'X-Auth-Token': BEARER_TOKEN,
        'X-Auth-Project-Id': SPACE_GUID
    }

    if CALL_VIA_API:
        url = API_VULN_BASE_TEMPLATE % API_SERVER
        body = API_BODY_TEMPLATE % imagename

    else:
        url = VULN_BASE_URL
        body = BODY_TEMPLATE % imagename

    if DEBUG=="1":
        LOGGER.debug("Sending request \"" + str(url) + "\" with body \"" + str(body) + "\" and headers \"" + str(xheaders) + "\"")
    res = requests.post(url, data=body, headers=xheaders)

    if DEBUG=="1":
        LOGGER.debug("received status " + str(res.status_code) + " and data " + str(res.text))

    if res.status_code != 200:
        if res.status_code == 401:
            raise Exception("Failed to find image: message was: " + str(res.text))
        else:
            raise Exception("Unable to contact server, request got return code " + str(res.status_code))

    return res.json()

# get the compliance info for a given image name, if any
def get_comp_info ( imagename ):
    if not imagename:
        return None

    xheaders = {
        'content-type': 'application/json',
        'X-Auth-Token': BEARER_TOKEN,
        'X-Auth-Project-Id': SPACE_GUID
    }

    if CALL_VIA_API:
        url = API_COMP_BASE_TEMPLATE % API_SERVER
        body = API_BODY_TEMPLATE % imagename

    else:
        url = COMP_BASE_URL
        body = BODY_TEMPLATE % imagename

    if DEBUG=="1":
        LOGGER.debug("Sending request \"" + str(url) + "\" with body \"" + str(body) + "\" and headers \"" + str(xheaders) + "\"")
    res = requests.post(url, data=body, headers=xheaders)

    if DEBUG=="1":
        LOGGER.debug("received status " + str(res.status_code) + " and data " + str(res.text))

    if res.status_code != 200:
        if res.status_code == 401:
            raise Exception("Failed to find image: message was: " + str(res.text))
        else:
            raise Exception("Unable to contact server, request got return code " + str(res.status_code))

    return res.json()

# check for completed compliance results on an image
# returns Boolean(complete), Boolean(all passed)
def check_compliance (image):
    global last_image_id

    comp_complete = False
    passed_check = True
    if not parsed_args['nocompcheck']:
        comp_res = get_comp_info(image)
        if comp_res:
            if comp_res["hits"]["total"] > 0:
                # got results, mark compliance check complete
                comp_complete = True
                # clear result counts
                passed = 0
                failed = 0
                total = 0
                failedlist = []
                goodlist = []
                for hit in comp_res["hits"]["hits"]:
                    if hit["_source"]["compliance_id"] in COMP_IDS_TO_IGNORE:
                        # skip this one
                        continue
                    total += 1
                    if hit["_source"]["compliant"] == "false":
                        passed_check = False
                        failed += 1
                        failedlist.append(hit)
                    else:
                        passed += 1
                        goodlist.append(hit)

                print STARS
                print "image %s compliance results found, %d hits" % ( str(image),total )
                print LABEL_GREEN + "\t%d checks passed" % passed
                if not parsed_args['hidepass']:
                    for hit in goodlist:
                        print "\t\t%s : %s" % ( hit["_source"]["description"], hit["_source"]["reason"] )
                print LABEL_RED + "\t%d checks failed" % failed
                for hit in failedlist:
                    print "\t\t%s : %s" % ( hit["_source"]["description"], hit["_source"]["reason"] )
                print LABEL_NO_COLOR + STARS
                # check if we got back an image id
                if "nova" in comp_res and "Id" in comp_res["nova"]:
                    last_image_id = comp_res["nova"]["Id"]
    else:
        # don't check compliance == compliance check complete
        comp_complete = True

    return comp_complete, passed_check


# check for completed vulnerability results on an image
# returns Boolean(complete), Boolean(all passed)
def check_vulnerabilities (image):
    global last_image_id

    vuln_complete = False
    passed_check = True
    if not parsed_args['novulncheck']:
        vuln_res = get_vuln_info(image)
        if vuln_res:
            if vuln_res["hits"]["total"] > 0:
                # got results, mark vulnerability check complete
                vuln_complete = True
                # clear results totals
                passed = 0
                failed = 0
                total = 0
                summary_total = 0
                summary_failed = 0
                failedlist = []
                goodlist = []
                for hit in vuln_res["hits"]["hits"]:
                    # if this is the summary, may not contain a usnid
                    if "usnid" in hit["_source"]:
                        if hit["_source"]["usnid"] in VULN_IDS_TO_IGNORE:
                            # skip this one
                            continue
                        if hit["_source"]["vulnerable"]:
                            passed_check = False
                            failed += 1
                            failedlist.append(hit)
                        else:
                            passed += 1
                            goodlist.append(hit)
                    else:
                        # no usnid, check for summary
                        if "total_usns_for_distro" in hit["_source"]:
                            summary_total = hit["_source"]["total_usns_for_distro"]
                        if "vulnerable_usns" in hit["_source"]:
                            summary_failed = hit["_source"]["vulnerable_usns"]
                            if summary_total >= summary_failed:
                                summary_passed = summary_total - summary_failed

                print STARS
                # if we have individual results, report those
                if total > 0:
                    print "image %s vulnerability results found, %d hits" % ( str(image),total )
                    print LABEL_GREEN + "\t%d checks passed" % passed
                    if not parsed_args['hidepass']:
                        for hit in goodlist:
                            print "\t\t%s : %s" % ( hit["_source"]["usnid"], hit["_source"]["summary"] )
                    print LABEL_RED + "\t%d checks failed" % failed
                    for hit in failedlist:
                        print "\t\t%s : %s" % ( hit["_source"]["usnid"], hit["_source"]["summary"] )
                elif summary_total > 0:
                    # if we only have summary results, report those
                    print "image %s vulnerability results found, %d hits" % ( str(image),summary_total )
                    print LABEL_GREEN + "\t%d checks passed" % summary_passed
                    print LABEL_RED + "\t%d checks failed" % summary_failed
                print LABEL_NO_COLOR + STARS
                # check if we got back an image id
                if "nova" in vuln_res and "Id" in vuln_res["nova"]:
                    last_image_id = vuln_res["nova"]["Id"]

    else:
        # don't check vulnerabilities == vuln check complete
        vuln_complete = True

    return vuln_complete, passed_check


# get and report results from the listed images, waiting as needed
def wait_for_image_results (images):
    global last_image_id

    all_passed = True
    any_passed = False
    time_left = WAIT_TIME
    # check all images
    for image in images:
        LOGGER.info("Running checks on image %s" % str(image))
        comp_complete = False
        vuln_complete = False
        last_image_id = None
        while (not comp_complete) and (not vuln_complete) and (time_left >= SLEEP_TIME):
            # only check comp if not already complete
            if not comp_complete:
                comp_complete, passed_check = check_compliance(image)
                # if this check completed, and it didn't pass, mark that not all passed
                if comp_complete and (not passed_check):
                    all_passed = False
            # only check vulnerabilities if not already complete
            if not vuln_complete:
                vuln_complete, passed_check = check_vulnerabilities(image)
                # if this check completed, and it didn't pass, mark that not all passed
                if vuln_complete and (not passed_check):
                    all_passed = False
            time_left = get_remaining_wait_time()
            if ((not comp_complete) or (not vuln_complete)) and (time_left >= SLEEP_TIME):
                LOGGER.info( "waiting for results for image %s" % str(image) )
                time.sleep(SLEEP_TIME)

        # if no results found for a given image, display that
        if (not parsed_args['nocompcheck']) and (not comp_complete):
            all_passed = False
            LOGGER.warning( LABEL_COLOR + "no compliance results found for image %s" % str(image) + LABEL_NO_COLOR )
        else:
            any_passed = True
        if (not parsed_args['novulncheck']) and (not vuln_complete):
            all_passed = False
            LOGGER.warning( LABEL_COLOR + "no vulnerability results found for image %s" % str(image) + LABEL_NO_COLOR )
        else:
            any_passed = True

        # if any of the scans passed, link to the results page
        if API_SERVER and any_passed:
            results_url = API_SERVER
            results_url = results_url.replace ( 'containers-api.', 'vulnerability-advisor.')
            if not last_image_id:
                # get the image id
                last_image_id = get_image_id_for_name( image )
            if last_image_id:
                results_url = "%s/vulnerability-advisor/ui/image?id=%s&spaceGuid=%s" % (results_url, last_image_id, SPACE_GUID)
                LOGGER.info("For a more in-depth review of these results, go to this URL: %s" % results_url)
            else:
                LOGGER.debug("Unable to get image id, no URL presented")

    return all_passed


# begin main execution sequence

try:
    # set us up per args and env vars
    parsed_args = parse_args()
    if parsed_args['help']:
        print_help()
        sys.exit(0)

    if not parsed_args['images']:
        LOGGER.error( "Error: No image names passed for validation." )
        print
        print_help()
        sys.exit(1)

    # check the images, wait until done (or timeout)
    all_passed = wait_for_image_results( parsed_args['images'] )

    endtime = timeit.default_timer()
    print "Script completed in " + str(endtime - SCRIPT_START_TIME) + " seconds"
    if not all_passed:
        sys.exit(1)
    sys.exit(0)

except Exception, e:
    LOGGER.warning("Execution failed - error was: " +  str(e))
    LOGGER.debug("Exception received", exc_info=e)
    endtime = timeit.default_timer()
    print "Script completed in " + str(endtime - SCRIPT_START_TIME) + " seconds"
    sys.exit(1)

