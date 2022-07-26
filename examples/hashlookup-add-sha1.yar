import "araygrass"
import "hash"

rule Hashlookup
{
    condition:
        araygrass.add_string(hash.sha1(0, filesize)) == 0
}
