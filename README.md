# athena-mydirbuster

## Introduction
A custom Directory buster used to find folder paths within the specified web application

## Installation
This script has been tested to work with python3 only.

Install the requirements within the requirements.txt file: 
```
pip install -r requirements.txt
```

## Examples
Following script is used to make custom calls to domain: `www.hotmail.com` using the specific wordlist in a recursive fashion:
```
python3 ./mydirbuster.py -t "www.hotmail.com" -w /tmp/wordlist.txt -ll 20 -r
```

