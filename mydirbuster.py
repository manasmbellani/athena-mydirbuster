#!/usr/bin/env python3
import argparse
import logging
import os
import sys

# Used to make requests calls for URL paths
import requests

# Get rid of unverified HTTPS requests warning
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def main():
    parser = argparse.ArgumentParser(description="Custom Directory brute-forcing script - looks for folder paths recursively",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-t", "--target", dest="target", required=True,
                        help="URL to target")
    parser.add_argument("-w", "--wordlist", required=True, help="Wordlist")
    parser.add_argument("-pr", "--protocol", dest="protocol", default="https",
                        help="Protocol to use (HTTP/HTTPS)")
    parser.add_argument("-p", "--port", dest="port", default="443",
                        help="Port")
    parser.add_argument("-pa", "--path", dest="path", default="",
                        help="Path to use")
    parser.add_argument("-ua", "--user-agent", action="store", 
                        default="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.116 Safari/537.36",
                        help="User Agent string ")
    parser.add_argument("-ll", "--log-level", action="store", default=logging.DEBUG,
                        help="Logging level")
    parser.add_argument("-f", "--outfile", action="store", default="out-http-paths.txt",
                        help="Output file to write the file paths to")
    parser.add_argument("-r", "--recursive", action="store_true", help="Recursively target indefinitely")

    args = parser.parse_args()


    # list of URLs to check
    url_queue = []

    # setup the logger
    logging.basicConfig(level=int(args.log_level))
    logger = logging.getLogger()

    logger.debug("Building target URL...")
    url = args.protocol + "://" + args.target + ":" + args.port + args.path

    logger.debug("Adding initial URL to target to list...")
    url_queue.append(url)

    logger.debug("Checking if wordlist path exists...")
    wordlist = []
    if not os.path.isfile(args.wordlist):
        logger.error("Wordlist file: {} not found".format(args.wordlist))
        return 1

    logger.debug("Reading Wordlist file...")
    with open(args.wordlist, "r+") as f:
        for line in f.readlines():
            wordlist.append(line.strip())

    logger.debug("Starting checks on URL: {}".format(url))
    with open(args.outfile, 'w+') as of:
        url_queue = run_checks_from_queue(logger, url_queue, wordlist, args.user_agent, args.recursive,
                                          of)

def run_checks_from_queue(logger, url_queue, wordlist, user_agent, recursive=False, outfile_obj=None):
    continue_checks = True
    while len(url_queue) > 0 and continue_checks:
        url_to_check = url_queue[0]
        url_queue = url_queue[1:]
        logger.debug("Checking URL: {} for sub-directories".format(url_to_check))
        for word in wordlist:
            full_url_to_check = url_to_check + "/" + word
            url_queue = check_path(logger, url_queue, full_url_to_check, user_agent, outfile_obj)
        if not recursive:
            continue_checks = False

    return url_queue

def check_path(logger, url_queue, url, user_agent, outfile_obj):
    headers = {'User-Agent': user_agent}
    try:
        resp = requests.get(url, headers=headers, verify=False, 
                            allow_redirects=True, timeout=2)
        if 200 <= resp.status_code < 400:
            resp_len = len(resp.text)
            logger.info("Found path: {}, {}: {}".format(resp.status_code, resp_len, url))

            logger.debug("Add url: {} as discovered and for further recursive checks".format(url))
            if url not in url_queue:
                url_queue.append(url)
            
            if outfile_obj:
                logger.debug("Writing URL to output file")
                outfile_obj.write(url + '\n')
                outfile_obj.flush()

    except Exception as e:
        logger.debug("Error when requesting url: {}".format(url))
        logger.debug(e, e.__class__)
        pass

    return url_queue

if __name__ == "__main__":
    sys.exit(main())

