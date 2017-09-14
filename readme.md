Obfuscate CactusTorch
============
Author: Arno0x0x - [@Arno0x0x](https://twitter.com/Arno0x0x)

The [CactusTorch](https://github.com/mdsecactivebreach/CACTUSTORCH) project from Vincent Yiu (@vysecurity) is a fantastic toolkit making use of the [DotNetToJScript](https://github.com/tyranid/DotNetToJScript) project.

This little tool tries to achieve two goals:
  1. Make a more obfuscated versions of the Office macro (VBA) and JScript stagers,
  2. Make use my [WebDavDelivery](https://github.com/Arno0x/WebDavDelivery) project to deliver the shellcode and CactusTorch serialized assembly.

Here is born ObfuscateCactusTorch, when CactusTorch meets WebDavDelivery :-).

How to use it
------------

Installation is pretty straight forward:
* Git clone this repository: `git clone https://github.com/Arno0x/ObfuscateCactusTorch ObfuscateCactusTorch`
* cd into the WebDAVDelivery folder: `cd ObfuscateCactusTorch`
* Give the execution rights to the main script: `chmod +x obfuscateCactusTorch.py`


1. Get a working copy of [WebDavDelivery](https://github.com/Arno0x/WebDavDelivery) tool

2. Lunch `obfuscateCactusTorch.py` with the following arguments:
   - type of stager to generate: can be either `js` or `vba`
   - IP address or FQDN of the WebDavDelivery server
   - binary name in which CactusTorch should inject the shellcode (*must be a 32 bits binary check CactusTorch project for details*)
   - output file name for the generated stager (*either VBA or JS*)

<img src="https://dl.dropboxusercontent.com/s/ewl76gennz59ifx/obfuscateCactusTorch_01.jpg?dl=0" width="600">

3. Generate an x86 shellcode **with no encoding**, you can use metasploit for instance.
4. Copy the shellcode file as well as the provided `cactusTorch/cactusTorch_serialized.bin` in the `servedFiles` folder of your WebDav Delivery folder.
5. Start WebDavDelivery.
6. On the target system, launch the stager generated in step 2.
7. You can see on the WebDavDelivery side that the stager is downloading the shellcode and the serialized object.

<img src="https://dl.dropboxusercontent.com/s/nhkovmmiadfqyam/obfuscateCactusTorch_02.jpg?dl=0" width="600">

8. Let the magic happen :-)


<img src="https://dl.dropboxusercontent.com/s/qki8yq0sjcs6sh1/obfuscateCactusTorch_03.jpg?dl=0" width="600">

DISCLAIMER
----------------
This tool is intended to be used in a legal and legitimate way only:
  - either on your own systems as a means of learning, of demonstrating what can be done and how, or testing your defense and detection mechanisms
  - on systems you've been officially and legitimately entitled to perform some security assessments (pentest, security audits)

Quoting Empire's authors:
*There is no way to build offensive tools useful to the legitimate infosec industry while simultaneously preventing malicious actors from abusing them.*