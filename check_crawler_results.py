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
import python_utils

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
CF_API_SERVER=""
API_SERVER=""
CRAWLER_SERVER=""

# compliance IDs to skip (don't need to report the "summary" id as a separate result)
COMP_IDS_TO_IGNORE=["Linux.0-0-a"]

# call information for authentication
BEARER_TOKEN=""
SPACE_GUID=""

# last image checked
last_image_id=None

# time to sleep between checks when waiting on pending jobs, in seconds
SLEEP_TIME=30

# compliance and vulnerability results
compliance_result = {}

# check cli args, set globals appropriately
def parse_args ():
    global VULN_BASE_URL, COMP_BASE_URL, API_SERVER, CRAWLER_SERVER, CALL_VIA_API
    global BEARER_TOKEN, SPACE_GUID
    global CF_API_SERVER, API_SERVER
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
            # enable debug mode, can also be done with python_utils.DEBUG env var
            parsed_args['debug'] = True
            python_utils.DEBUG = "1"
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

    python_utils.LOGGER = python_utils.setup_logging()

    # set up the server urls
    if CALL_VIA_API:
        CF_API_SERVER, API_SERVER = python_utils.find_api_servers()
        if not API_SERVER:
            msg = "Cannot determine correct api server, unable to place queries"
            python_utils.LOGGER.error( msg )
            raise Exception( msg )
    else:
        CRAWLER_SERVER = os.environ.get('CRAWLER_SERVER')
        if not CRAWLER_SERVER:
            msg = "CRAWLER_SERVER is not set, unable to place queries"
            python_utils.LOGGER.error( msg )
            raise Exception( msg )
        VULN_BASE_URL=VULN_BASE_TEMPLATE % CRAWLER_SERVER
        COMP_BASE_URL=COMP_BASE_TEMPLATE % CRAWLER_SERVER

    # load creds
    BEARER_TOKEN, SPACE_GUID = python_utils.load_cf_auth_info()

    # see how much time we have left after completing init
    python_utils.WAIT_TIME = python_utils.get_remaining_wait_time(first = True)

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
    if python_utils.DEBUG=="1":
        python_utils.LOGGER.debug("Sending request \"" + str(url) + "\" with headers \"" + str(xheaders) + "\"")
    res = requests.get(url, headers=xheaders)

    if python_utils.DEBUG=="1":
        python_utils.LOGGER.debug("received status " + str(res.status_code) + " and data " + str(res.text))

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

    if python_utils.DEBUG=="1":
        python_utils.LOGGER.debug("Sending request \"" + str(url) + "\" with body \"" + str(body) + "\" and headers \"" + str(xheaders) + "\"")
    res = requests.post(url, data=body, headers=xheaders)

    if python_utils.DEBUG=="1":
        python_utils.LOGGER.debug("received status " + str(res.status_code) + " and data " + str(res.text))

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

    if python_utils.DEBUG=="1":
        python_utils.LOGGER.debug("Sending request \"" + str(url) + "\" with body \"" + str(body) + "\" and headers \"" + str(xheaders) + "\"")
    res = requests.post(url, data=body, headers=xheaders)

    if python_utils.DEBUG=="1":
        python_utils.LOGGER.debug("received status " + str(res.status_code) + " and data " + str(res.text))

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
    global compliance_result

    comp_complete = False
    passed_check = True
    if not parsed_args['nocompcheck']:
        comp_res = get_comp_info(image)
        if comp_res:
            if comp_res["hits"]["total"] > 0:
                # got results, mark compliance check complete
                comp_complete = True
                # first filter to keep only latest test result for each test
                checkedlist = {}
                compresults = []
                for hit in comp_res["hits"]["hits"]:
                    hit_id = hit["_source"]["compliance_id"]
                    if hit_id in COMP_IDS_TO_IGNORE:
                        # skip this one
                        continue
                    # only want to show the latest result for a given test for
                    # each image
                    if hit_id in checkedlist:
                        oldhit = checkedlist[hit_id]
                        # keep only the latest result
                        try:
                            newtime = datetime.strptime(hit["_source"]["@timestamp"], "%Y-%m-%dT%H:%M:%S.%fZ")
                        except Exception:
                            newtime = None
                        try:
                            oldtime = datetime.strptime(oldhit["_source"]["@timestamp"], "%Y-%m-%dT%H:%M:%S.%fZ")
                        except Exception:
                            oldtime = None
                        if newtime:
                            if (not oldtime) or oldtime<newtime:
                                # if the new one is newer, or old one has no timestamp,
                                # save the new one (replace previous)
                                checkedlist[hit_id] = hit
                    else:
                        checkedlist[hit_id] = hit

                # now run a count to get passed/failed/etc
                # clear result counts
                passed = 0
                failed = 0
                total = 0
                failedlist = []
                goodlist = []
                for key, hit in checkedlist.iteritems():
                    compresults.append(hit)
                    total += 1
                    if hit["_source"]["compliant"] == "false":
                        passed_check = False
                        failed += 1
                        failedlist.append(hit)
                    else:
                        passed += 1
                        goodlist.append(hit)

                print python_utils.STARS
                print "image %s compliance results found, %d hits" % ( str(image),total )
                print python_utils.LABEL_GREEN + "\t%d checks passed" % passed
                if not parsed_args['hidepass']:
                    for hit in goodlist:
                        print "\t\t%s : %s" % ( hit["_source"]["description"], hit["_source"]["reason"] )
                if failed == 0:
                    failed_label = python_utils.LABEL_GREEN
                else:
                    failed_label = python_utils.LABEL_RED
                print "%s\t%d checks failed" % (failed_label, failed)
                for hit in failedlist:
                    print "\t\t%s : %s" % ( hit["_source"]["description"], hit["_source"]["reason"] )
                print python_utils.LABEL_NO_COLOR + python_utils.STARS
                # check if we got back an image id
                if "nova" in comp_res and "Id" in comp_res["nova"]:
                    last_image_id = comp_res["nova"]["Id"]
                compliance_result.update({'compliance': compresults})

    else:
        # don't check compliance == compliance check complete
        comp_complete = True

    return comp_complete, passed_check


# check for completed vulnerability results on an image
# returns Boolean(complete), Boolean(all passed)
def check_vulnerabilities (image):
    global last_image_id
    global compliance_result

    vuln_complete = False
    passed_check = True
    if not parsed_args['novulncheck']:
        vuln_res = get_vuln_info(image)
        if vuln_res:
            if vuln_res["hits"]["total"] > 0:
                # got results, mark vulnerability check complete
                vuln_complete = True
                # sort into groups by _index and keep track of which _index is the newest
                newestTime = None
                newestIndex = None
                #scans will be in the format of _index:{time:<datetime>, hits:[hit1, hit2, hit3...]}
                scans = {}
                for hit in vuln_res["hits"]["hits"]:
                    if not hit["_index"] in scans:
                        scans[hit["_index"]] = {}
                        scans[hit["_index"]]["hits"] = []
                        try:
                            scans[hit["_index"]]["time"] = datetime.strptime(hit["_source"]["@timestamp"], "%Y-%m-%dT%H:%M:%S.%fZ")
                        except Exception:
                            scans[hit["_index"]]["time"] = None
                    elif not scans[hit["_index"]]["time"]:
                        try:
                            scans[hit["_index"]]["time"] = datetime.strptime(hit["_source"]["@timestamp"], "%Y-%m-%dT%H:%M:%S.%fZ")
                        except Exception:
                            scans[hit["_index"]]["time"] = None
                    scans[hit["_index"]]["hits"].append(hit)
                    if (not newestIndex) or (not newestTime) or newestTime < scans[hit["_index"]]["time"]:
                        newestTime = scans[hit["_index"]]["time"]
                        newestIndex = hit["_index"]
                vulnsults = scans[newestIndex]["hits"]
                # clear results totals
                passed = 0
                failed = 0
                total = 0
                total_packages = -1
                vulnerable_packages = -1
                summary_total = 0
                summary_failed = 0
                failedlist = []
                goodlist = []
                for hit in vulnsults:
                    # if this is the summary, may not contain a usnid
                    if "total_usns_for_distro" in hit["_source"]:
                        summary_total = hit["_source"]["total_usns_for_distro"]
                        if "vulnerable_usns" in hit["_source"]:
                            summary_failed = hit["_source"]["vulnerable_usns"]
                            if summary_total >= summary_failed:
                                summary_passed = summary_total - summary_failed
                        if "total_packages" in hit["_source"]:
                            total_packages = hit["_source"]["total_packages"]
                        if "vulnerable_packages" in hit["_source"]:
                            vulnerable_packages = hit["_source"]["vulnerable_packages"]
                        if "vulnerable" in hit["_source"]:
                            # if vulnerable is set and set to "true", flag
                            # that the image is vulnerable/failed
                            if hit["_source"]["vulnerable"]:
                                passed_check = False
                    else:
                        if hit["_source"]["vulnerable"]:
                            passed_check = False
                            failed += 1
                            failedlist.append(hit)
                        else:
                            passed += 1
                            goodlist.append(hit)
                print python_utils.STARS
                # if we have individual results, report those
                if (total_packages != -1) and (vulnerable_packages != -1):
                    print "image %s vulnerability results found" % str(image)
                    print python_utils.LABEL_GREEN + "\t%d packages scanned" % total_packages
                    if vulnerable_packages == 0:
                        failed_label = python_utils.LABEL_GREEN
                    else:
                        failed_label = python_utils.LABEL_RED
                    print "%s\t%d vulnerable packages" % (failed_label, vulnerable_packages)
                    for hit in failedlist:
                        if "package_name" in hit["_source"]:
                            print "\t\t%s : current: %s  fixed: %s" % ( hit["_source"]["package_name"], hit["_source"]["current_version"], hit["_source"]["fix_version"] )
                elif total > 0:
                    print "image %s vulnerability results found, %d hits" % ( str(image),total )
                    print python_utils.LABEL_GREEN + "\t%d checks passed" % passed
                    if not parsed_args['hidepass']:
                        for hit in goodlist:
                            print "\t\t%s" % ( hit["_source"]["package_name"] )
                    if failed == 0:
                        failed_label = python_utils.LABEL_GREEN
                    else:
                        failed_label = python_utils.LABEL_RED
                    print "%s\t%d checks failed" % (failed_label, failed)
                    for hit in failedlist:
                        if "package_name" in hit["_source"]:
                            print "\t\t%s : current: %s  fixed: %s" % ( hit["_source"]["package_name"], hit["_source"]["current_version"], hit["_source"]["fix_version"] )
                elif summary_total > 0:
                    # if we only have summary results, report those
                    print "image %s vulnerability results found, %d hits" % ( str(image),summary_total )
                    print python_utils.LABEL_GREEN + "\t%d checks passed" % summary_passed
                    if summary_failed == 0:
                        failed_label = python_utils.LABEL_GREEN
                    else:
                        failed_label = python_utils.LABEL_RED
                    print "%s\t%d checks failed" % (failed_label, summary_failed)
                print python_utils.LABEL_NO_COLOR + python_utils.STARS
                # check if we got back an image id
                if "nova" in vuln_res and "Id" in vuln_res["nova"]:
                    last_image_id = vuln_res["nova"]["Id"]
                compliance_result.update({'vulnerability': vulnsults})

    else:
        # don't check vulnerabilities == vuln check complete
        vuln_complete = True

    return vuln_complete, passed_check


# get and report results from the listed images, waiting as needed
def wait_for_image_results (images):
    global last_image_id

    all_passed = True
    any_passed = False
    failed_exception = None
    time_left = python_utils.WAIT_TIME
    # check all images
    for image in images:
        python_utils.LOGGER.info("Running checks on image %s" % str(image))
        comp_complete = False
        vuln_complete = False
        last_image_id = None
        while ((not comp_complete) or (not vuln_complete)) and (time_left >= SLEEP_TIME):
            try:
                # only check comp if not already complete
                if not comp_complete:
                    comp_complete, passed_check = check_compliance(image)
                    # if no exception, make sure it's clear
                    failed_exception = None
                    # if this check completed, and it didn't pass, mark that not all passed
                    if comp_complete and (not passed_check):
                        all_passed = False
                # only check vulnerabilities if not already complete
                if not vuln_complete:
                    vuln_complete, passed_check = check_vulnerabilities(image)
                    # if no exception, make sure it's clear
                    failed_exception = None
                    # if this check completed, and it didn't pass, mark that not all passed
                    if vuln_complete and (not passed_check):
                        all_passed = False
            except Exception, e:
                python_utils.LOGGER.debug( "non-fatal failure during check for image %s" % str(image), exc_info=e )
                # we'll retry, but save the exception for if this was the last try
                failed_exception = e
            time_left = python_utils.get_remaining_wait_time()
            if ((not comp_complete) or (not vuln_complete)) and (time_left >= SLEEP_TIME):
                python_utils.LOGGER.info( "waiting for results for image %s" % str(image) )
                time.sleep(SLEEP_TIME)

        # if we failed because of an exception, even after retries, reraise it now
        if (failed_exception != None):
            raise failed_exception

        # if no results found for a given image, display that
        if (not parsed_args['nocompcheck']) and (not comp_complete):
            all_passed = False
            python_utils.LOGGER.warning( python_utils.LABEL_COLOR + "no compliance results found for image %s" % str(image) + python_utils.LABEL_NO_COLOR       )
        else:
            any_passed = True
        if (not parsed_args['novulncheck']) and (not vuln_complete):
            all_passed = False
            python_utils.LOGGER.warning( python_utils.LABEL_COLOR + "no vulnerability results found for image %s" % str(image) + python_utils.LABEL_NO_COLOR       )
        else:
            any_passed = True

        # if any of the scans passed, link to the results page
        if API_SERVER and any_passed:
            results_url = API_SERVER
            results_url = results_url.replace ( 'containers-api.', 'console.')
            if not last_image_id:
                # get the image id
                last_image_id = get_image_id_for_name( image )
            if last_image_id:
                results_url = "%s/vulnerability-advisor/ui/image?id=%s&spaceGuid=%s" % (results_url, last_image_id, SPACE_GUID)
                python_utils.LOGGER.info("For a more in-depth review of these results, go to this URL: %s" % results_url)
                f = open("result_url","w")
                f.write(results_url)
                f.close()
            else:
                python_utils.LOGGER.debug("Unable to get image id, no URL presented")

    return all_passed


# begin main execution sequence

try:
    # set us up per args and env vars
    parsed_args = parse_args()
    if parsed_args['help']:
        print_help()
        sys.exit(0)

    if not parsed_args['images']:
        python_utils.LOGGER.error( "Error: No image names passed for validation." )
        print
        print_help()
        sys.exit(1)

    # check the images, wait until done (or timeout)
    all_passed = wait_for_image_results( parsed_args['images'] )

    # generate compliance-result.json file
    if compliance_result:
        compliance_result_file = './compliance-result.json'
        with open(compliance_result_file, 'w') as outfile:
            json.dump(compliance_result, outfile, sort_keys = True)

    endtime = timeit.default_timer()
    print "Script completed in " + str(endtime - python_utils.SCRIPT_START_TIME) + " seconds"
    if not all_passed:
        sys.exit(1)
    sys.exit(0)

except Exception, e:
    python_utils.LOGGER.warning("Execution failed - error was: " +  str(e))
    python_utils.LOGGER.debug("Exception received", exc_info=e)
    endtime = timeit.default_timer()
    print "Script completed in " + str(endtime - python_utils.SCRIPT_START_TIME) + " seconds"
    sys.exit(1)

