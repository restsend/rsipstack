"""Independent MD5 qop=auth oracle for SIPp's Proxy-Authorization blind spot."""
import hashlib
import re
import sys

message = sys.stdin.read()
method, target, _ = message.splitlines()[0].split()
header = re.search(r"^Proxy-Authorization: Digest (.*)$", message, re.M | re.I)
assert header, "Missing Proxy-Authorization"
fields = {
    key.lower(): quoted or bare
    for key, quoted, bare in re.findall(r'(\w+)=(?:"([^"]*)"|([^,\s]+))', header[1])
}
assert fields["username"] == "alice"
assert fields["realm"] == "interop.test"
assert fields["nonce"] == "interop-1"
assert fields["uri"] == target
assert fields["algorithm"].upper() == "MD5"
assert fields["qop"] == "auth"
assert fields["nc"] == "00000001"
assert fields["cnonce"]

def md5(value):
    return hashlib.md5(value.encode()).hexdigest()

ha1 = md5("alice:interop.test:secret")
ha2 = md5(f"{method}:{target}")
expected = md5(f'{ha1}:{fields["nonce"]}:{fields["nc"]}:{fields["cnonce"]}:auth:{ha2}')
assert fields["response"] == expected, "Invalid proxy digest response"
