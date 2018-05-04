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

def getArgs():
    parser = argparse.ArgumentParser("verifyHash")
    parser.add_argument("-p", "--rootPath",
                        help="Path from the root folder")
    return parser.parse_args()

def getMD5Hash(filePath):
     if os.path.isfile(filePath):
        hasher = hashlib.md5()
        with open(filePath, 'rb') as afile:
            buf = afile.read()
            hasher.update(buf)
        return hasher.hexdigest()

def sendToVirusTotal(md5Hash):
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
        print "Hash: " + md5Hash + " -- StatusCode: " + str(statusCode)


def getItemsDirBy(rootDirPath):

    foldersName = ""

    if os.path.isdir(rootDirPath):
        foldersName = os.listdir(rootDirPath)

    return foldersName

def main():

    args = getArgs()

    # return all folders in passed folder
    foldersName = getItemsDirBy(args.rootPath)

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
                    response = sendToVirusTotal(md5Hash)

                    if response is None:
                        break

                    if response.get("positives", "none") != "none"  and response.get("positives", "none") > 0:
                        print "Artifact has been identified :("
                    else:
                        print "New artifact! Start the analysis NOW! \o/ \n" + fullPath
            except Exception as ex:
               print ex
    pass

if __name__ == '__main__':
    main()





