import "araygrass"
import "hash"

rule Hashlookup
{
    condition:
        araygrass.check_string(hash.sha1(0, filesize), 1) == 1
}
