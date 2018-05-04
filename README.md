# CheckHash

## Goals
Check the md5 hash of the files in a folder tree

## Dependencies
```
sudo pip install requests
```

## How to use this script?
```
λ python CheckHash.py -h
usage: verifyHash [-h] [-p ROOTPATH]

optional arguments:
  -h, --help            show this help message and exit
  -p ROOTPATH, --rootPath ROOTPATH
                        Path from the root folder

```

**Example**
```
λ python CheckHash.py -p "tests"
New artifact! Start the analysis NOW! \o/ [ tests\malwareFolder\1.URL ]
Artifact has been identified :(

```


