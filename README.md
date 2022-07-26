# a-ray-grass
`a-ray-grass` is a yara module that provides support for DCSO format bloom filters in yara. In the context of [hashlookup](https://hashlookup.io), it allows quickly discard known files "pour séparer le grain de l\'ivraie".

# Installation
## Copy
- Copy the folder `libyara/fleur` in `libyara`
- Copy the folder `libyara/modules/araygrass` in `libyara/modules`

## Modify `libyara/Makefile.am`
- Add `modules/araygrass/araygrass.c` to the `MODULES` variable:
```
MODULES += modules/araygrass/araygrass.c
```
- Add `fleur/fnv.c` and `fleur/fleur.c` to the `libyara_la_SOURCES` variable:
```
libyara_la_SOURCES = \
	$(MODULES) \
	grammar.y \
...
	fleur/fnv.c \
	fleur/fleur.c \
	threading.c
```

## Modify `/libyara/modules/module_list`
- Append `MODULE(araygrass)` at the end of the file

## Finally modify `libyara/modules/araygrass/araygrass.c`
There you will find two paths defined:

- `BF_PATH_IN`: specify here the path to your input bloom filter, the filter against wich variables will be checked.
- `BF_PATH_OUT`: specify here the path where you wish to save the modified
  bloom filter after yara finished its execution. It can be left empty if no
  modification are made to the filter.

It's totally ok to set the same path for both variables.

# Compilation

Go back the yara's root folder and `make` (followed by `sudo make install` if you wish this version of yara to replace your current version).

# Functions
a-ray-grass provides two functions, `check_string` and `add_string`. Both functions take two arguments:
- a string to match against the bloom filter,
- a flag to specify whether the string should bit translated to uppercase before checking/adding.

## `check_string`
`check_string` takes a string, the uppercase int flag, and returns an integer:
- 1 if the string may be in the bloom filter (given your bloom filter' parameter),
- 0 if the string is definitely on in the filter.

## `add_string`
`add_string` takes a string, the uppercase int flag, and returns an integer:
- 0 if the string likely already present in the filter, therefore not added,
- 1 if the string was definitely not present, but now it is.

# Usage and use-cases
Wait would you use this modules? I am glad you asked !

## Bloom filters
This modules is compatible with bloom filters generated by DCSO's tools:
- [bloom](https://github.com/DCSO/bloom) (golang)
- [flor](https://github.com/DCSO/flor) (python)
As well as [fleur](https://github.com/hashlookup/fleur) (C)

As a bloom filter is necessary, an empty one is provided in `examples/empty.bloom`. But you can create one with
`bloom create test.bloom` for instance.

The most useful public filter one can use is [hashlookup's](https://cra.circl.lu/hashlookup/hashlookup-full.bloom), that contains a lot of sha1 (in uppercase) of known files.

## Filtering known files
Let's consider the following yara rule for instance:
```
import "araygrass"
import "hash"

rule HashlookupMatching
{
    condition:
        araygrass.check_string(hash.sha1(0, filesize), 1) == 1
}

```
In this instance, each file is fully hashed with SHA1, then checked against hashlookup's filter:
```shell
$./yara hashlookup-sha1.yar -r /usr/bin
Hashlookup /usr/bin/ctanify
Hashlookup /usr/bin/qdoc
Hashlookup /usr/bin/ps2pdfwr
Hashlookup /usr/bin/ubuntu-security-status
...
```
One can recompile the module to point to the right filter but consider copying/linking to get more flexibilty.

## Storing already processed files
In the following examples, we actually match against hashlookup, and add to the filter if we don't know the file.
```
import "araygrass"
import "hash"

rule Hashlookup
{
    condition:
        araygrass.check_string(hash.sha1(0, filesize), 1) == 1
}
```
It's especially usefull to avoid bumping into the same file again, and can come handy when combined with other conditions ;)

## Partial hashing
Remember that `yara`'s `hash` modules support hashing parts of file, therefore it is totatally doable to only store the hash of say the first 2K of each files.
Hashlookup team is working on such dataset but it is not public ATM.

# Acknowledgment

![](./img/cef.png)

The project has been co-funded by CEF-TC-2020-2 - 2020-EU-IA-0260 - JTAN - Joint Threat Analysis Network.
