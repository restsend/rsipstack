"""Independent MD5 qop=auth oracle for SIPp's Proxy-Authorization blind spot."""
import hashlib
import re
import sys

def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify():
    message = sys.stdin.read()
    method, target, _ = message.splitlines()[0].split()
    header = re.search(r"^Proxy-Authorization: Digest (.*)$", message, re.M | re.I)
    require(header is not None, "Missing Proxy-Authorization")
    fields = {
        key.lower(): quoted or bare
        for key, quoted, bare in re.findall(r'(\w+)=(?:"([^"]*)"|([^,\s]+))', header[1])
    }
    require(fields["username"] == "alice", "Unexpected digest field: " + str(fields["username"]))
    require(fields["realm"] == "interop.test", "Unexpected digest field: " + str(fields["realm"]))
    require(fields["nonce"] == "interop-1", "Unexpected digest field: " + str(fields["nonce"]))
    require(fields["uri"] == target, "Unexpected digest field: " + str(fields["uri"]))
    require(fields["algorithm"].upper() == "MD5", "Unexpected digest algorithm")
    require(fields["qop"] == "auth", "Unexpected digest field: " + str(fields["qop"]))
    require(fields["nc"] == "00000001", "Unexpected digest field: " + str(fields["nc"]))
    require(bool(fields["cnonce"]), "Missing cnonce")

    def md5(value):
        return hashlib.md5(value.encode()).hexdigest()

    ha1 = md5("alice:interop.test:secret")
    ha2 = md5(f"{method}:{target}")
    expected = md5(f'{ha1}:{fields["nonce"]}:{fields["nc"]}:{fields["cnonce"]}:auth:{ha2}')
    require(fields["response"] == expected, "Invalid proxy digest response")


if __name__ == "__main__":
    try:
        verify()
    except (ValueError, KeyError, IndexError) as error:
        sys.exit(f"Proxy-Authorization verification failed: {error}")
