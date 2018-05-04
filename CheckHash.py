#-------------------------------------------------------------------------------
# Name:        CheckHash.py
# Purpose:     Check the md5 hash of the files in a folder tree
#
# Author:      Charles Lomboni
#
# Created:     04/05/2018
# Copyright:   (c) Charles Lomboni 2018
# Licence:     <MIT License>
#-------------------------------------------------------------------------------

import hashlib
import argparse
import requests
import json
import os
import time

def getArgs():
    parser = argparse.ArgumentParser("CheckHash")
    parser.add_argument("-p", "--rootPath",
                        help="Path from the root folder")
    parser.add_argument("-av","--filterAv",
                        help="Verify if specific AV cath this malware")
    return parser.parse_args()

def getMD5Hash(filePath):

     if os.path.isfile(filePath):
        extensionFile = os.path.splitext(filePath)[1]

        if extensionFile.lower() != ".url":
            hasher = hashlib.md5()
            with open(filePath, 'rb') as afile:
                buf = afile.read()
                hasher.update(buf)
            return hasher.hexdigest()

def sendToVirusTotal(md5Hash, fileName):
    statusCode = ""

    try:
        urlVirusTotal = "https://www.virustotal.com/vtapi/v2/file/report"
        params = {'apikey':
            'YOUR_APIKEY_HERE',
            'resource': md5Hash}

        response = requests.post(urlVirusTotal, params=params)
        statusCode = response.status_code

        return response.json()
    except:
        print "FileName => " + fileName + " :: Hash => " + md5Hash + " :: StatusCode => " + str(statusCode)


def getItemsDirBy(rootDirPath):

    foldersName = ""

    if os.path.isdir(rootDirPath):
        foldersName = os.listdir(rootDirPath)

    return foldersName


def isAv(av, response):
    scans = response.get("scans")
    symantecAv = scans.get(av)
    return symantecAv

def main():

    args = getArgs()

    # return all folders in passed folder
    foldersName = getItemsDirBy(args.rootPath)

    print "Analysis was started.."

    for folder in foldersName:
        # get all files inseide folder
        allFilesInFolder = getItemsDirBy(args.rootPath + "\\" + folder)
        for singleFile in allFilesInFolder:

            fullPath = ""
            md5Hash = ""
            response = ""

            try:
                fullPath = args.rootPath + "\\" + folder + "\\" + singleFile
                md5Hash = getMD5Hash(fullPath)

                if md5Hash:
                    response = sendToVirusTotal(md5Hash, singleFile)

                    # sleep time to bypass limit for virustotal
                    time.sleep(5)

                    if response is None:
                        break

                    if response.get("positives", "none") <= 0:
                        print "** NEW ** [ " + fullPath + " ] :: Hash => " + md5Hash
                        responseAv = isAv(args.filterAv, response)
                        print args.filterAv + " detected => " + str(responseAv.get("detected"))

            except Exception as ex:
               print ex
    pass

if __name__ == '__main__':
    main()





