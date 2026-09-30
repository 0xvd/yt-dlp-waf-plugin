from __future__ import annotations

import base64
import functools
import hashlib
import http.cookiejar
import itertools
import json
import re
import time
import uuid
import zlib
from typing import Callable

from yt_dlp.dependencies.Cryptodome import AES
from yt_dlp.extractor.common import InfoExtractor
from yt_dlp.utils import multipart_encode
from yt_dlp.YoutubeDL import YoutubeDL


def set_cookie(jar, domain, name, value):
    cookie = http.cookiejar.Cookie(
        version=0,
        name=name,
        value=value,
        port=None,
        port_specified=False,
        domain=domain,
        domain_specified=True,
        domain_initial_dot=domain.startswith('.'),
        path='/',
        path_specified=True,
        secure=True,
        expires=None,
        discard=False,
        comment=None,
        comment_url=None,
        rest={},
    )
    jar.set_cookie(cookie)


_original_urlopen = getattr(
    YoutubeDL.urlopen, '__wrapped__', YoutubeDL.urlopen)


@functools.wraps(_original_urlopen)
def _patched_urlopen(self, req):
    response = _original_urlopen(self, req)
    if not response.headers.get('x-amzn-waf-action'):
        return response

    body = response.read()
    token, domains = AwfSolver(
        req.url, body, downloader=self).solve_challenge()
    if not token:
        return response
    for d in domains:
        set_cookie(self.cookiejar, f'.{d}', 'aws-waf-token', token)
    return _original_urlopen(self, req)


YoutubeDL.urlopen = _patched_urlopen


class AwfSolver:
    def __init__(self, url=None, webpage=None, downloader=None):
        if webpage and downloader:
            self.ie = InfoExtractor(downloader=downloader)
            self.webpage = str(webpage)
            self.url = url
            self.domain = None
            self.endpoint = None
        self.key = bytes.fromhex(
            "6f71a512b1e035eaab53d8be73120d3fb68a0ca346b9560aab3e5cdf753d5e98")
        self.CHALLENGE_SOLVERS: dict[str, Callable] = {
            "h72f957df656e80ba55f5d8ce2e8c7ccb59687dba3bfb273d54b08a261b2f3002": self.compute_scrypt_nonce,
            "h7b0c470f0cfe3a80a9e26526ad185f484f6817d0832712a4a37a908786a6a67f": self.hash_pow,
            "ha9faaffd31b4d5ede2a2e19d2d7fd525f66fee61911511960dcbb52d3c48ce25": self.network_bandwidth,
        }

    def encrypt(self, plaintext: bytes) -> str:
        goku_prop_iv = self._get_gokuProps().get('iv')
        iv_bytes = base64.b64decode(goku_prop_iv)
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=iv_bytes, mac_len=16)
        ct, tag = cipher.encrypt_and_digest(plaintext)
        return f"{goku_prop_iv}::{ct.hex()}{tag.hex()}"

    def _fake_fingerprint(self):
        ts = int(time.time() * 1000)
        fingerprint = {
            "metrics": {
                "fp2": 2,
                "browser": 1,
                "capabilities": 2,
                "gpu": 30,
                "dnt": 0,
                "math": 1,
                "screen": 0,
                "navigator": 0,
                "auto": 0,
                "stealth": 2,
                "subtle": 0,
                "canvas": 38,
                "formdetector": 0,
                "be": 1
            },
            "start": ts,
            "flashVersion": None,
            "plugins": [
                {"name": "Chrome document Plugin",
                    "str": "Chrome document Plugin "},
                {
                    "name": "Microsoft Edge PDF Viewer",
                    "str": "Microsoft Edge PDF Viewer "
                },
                {"name": "GDJEKNOP", "str": "GDJEKNOP 26140"},
                {"name": "Chromium PDF Viewer", "str": "Chromium PDF Viewer "},
                {"name": "WebKit built-in PDF", "str": "WebKit built-in PDF "},
                {"name": "PDF Viewer", "str": "PDF Viewer "},
                {"name": "Sw3jwg3", "str": "Sw3jwg3 143368"}
            ],
            "dupedPlugins": "Chrome document Plugin Microsoft Edge PDF Viewer GDJEKNOP 26140Chromium PDF Viewer WebKit built-in PDF PDF Viewer Sw3jwg3 143368||1920-1080-1080-24-*-*-*",
            "screenInfo": "1920-1080-1080-24-*-*-*",
            "userAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
            "referrer": "",
            "location": self.url,
            "webDriver": False,
            "capabilities": {
                "css": {
                    "textShadow": 1,
                    "WebkitTextStroke": 1,
                    "boxShadow": 1,
                    "borderRadius": 1,
                    "borderImage": 1,
                    "opacity": 1,
                    "transform": 1,
                    "transition": 1
                },
                "js": {
                    "audio": True,
                    "geolocation": True,
                    "localStorage": "supported",
                    "touch": False,
                    "video": True,
                    "webWorker": True
                },
                "elapsed": 1
            },
            "gpu": {
                "vendor": "Brave",
                "model": "Brave",
                "extensions": [
                    "ANGLE_instanced_arrays",
                    "EXT_blend_minmax",
                    "EXT_clip_control",
                    "EXT_color_buffer_half_float",
                    "EXT_depth_clamp",
                    "EXT_disjoint_timer_query",
                    "EXT_float_blend",
                    "EXT_frag_depth",
                    "EXT_polygon_offset_clamp",
                    "EXT_shader_texture_lod",
                    "EXT_texture_compression_bptc",
                    "EXT_texture_compression_rgtc",
                    "EXT_texture_filter_anisotropic",
                    "EXT_texture_mirror_clamp_to_edge",
                    "EXT_sRGB",
                    "KHR_parallel_shader_compile",
                    "OES_element_index_uint",
                    "OES_fbo_render_mipmap",
                    "OES_standard_derivatives",
                    "OES_texture_float",
                    "OES_texture_float_linear",
                    "OES_texture_half_float",
                    "OES_texture_half_float_linear",
                    "OES_vertex_array_object",
                    "WEBGL_blend_func_extended",
                    "WEBGL_color_buffer_float",
                    "WEBGL_compressed_texture_s3tc",
                    "WEBGL_compressed_texture_s3tc_srgb",
                    "WEBGL_debug_renderer_info",
                    "WEBGL_debug_shaders",
                    "WEBGL_depth_texture",
                    "WEBGL_draw_buffers",
                    "WEBGL_lose_context",
                    "WEBGL_multi_draw",
                    "WEBGL_polygon_mode",
                    "EXT_texture_blender"
                ]
            },
            "dnt": None,
            "math": {
                "tan": "-1.4214488238747245",
                "sin": "0.8178819121159085",
                "cos": "-0.5753861119575491"
            },
            "automation": {
                "wd": {"properties": {"document": [], "window": [], "navigator": []}},
                "phantom": {"properties": {"window": []}}
            },
            "stealth": {"t1": 0, "t2": 0, "i": 1, "mte": 0, "mtd": False},
            "crypto": {
                "crypto": 1,
                "subtle": 1,
                "encrypt": True,
                "decrypt": True,
                "wrapKey": True,
                "unwrapKey": True,
                "sign": True,
                "verify": True,
                "digest": True,
                "deriveBits": True,
                "deriveKey": True,
                "getRandomValues": True,
                "randomUUID": True
            },
            "canvas": {
                "hash": -926950302,
                "emailHash": None,
                "histogramBins": [
                    14578, 182, 63, 49, 39, 54, 28, 24, 31, 26, 34, 15, 44, 55, 35, 69, 25,
                    30, 30, 26, 23, 26, 42, 48, 43, 17, 32, 16, 53, 17, 29, 30, 21, 22, 28,
                    34, 38, 15, 33, 21, 26, 43, 21, 19, 22, 26, 25, 23, 22, 28, 23, 37, 20,
                    13, 17, 22, 31, 23, 15, 15, 27, 35, 9, 13, 33, 22, 21, 12, 25, 23, 18, 27,
                    23, 14, 12, 9, 30, 13, 23, 48, 27, 16, 19, 19, 27, 34, 15, 24, 19, 22, 20,
                    19, 14, 17, 15, 24, 53, 27, 54, 65, 61, 32, 495, 26, 16, 44, 25, 28, 15,
                    20, 27, 18, 25, 18, 26, 23, 29, 21, 33, 34, 25, 24, 21, 22, 52, 23, 25,
                    47, 25, 26, 39, 44, 17, 10, 18, 19, 32, 40, 44, 31, 34, 24, 28, 31, 14,
                    18, 28, 30, 12, 19, 63, 22, 24, 69, 16, 14, 38, 28, 19, 23, 21, 21, 27, 9,
                    12, 15, 15, 22, 17, 21, 32, 21, 39, 29, 22, 24, 82, 18, 20, 29, 9, 16, 19,
                    27, 12, 17, 15, 25, 19, 15, 19, 31, 12, 9, 27, 17, 9, 22, 26, 14, 12, 29,
                    35, 43, 64, 41, 32, 37, 33, 41, 37, 14, 33, 9, 44, 25, 30, 23, 23, 36, 23,
                    32, 27, 40, 39, 43, 18, 38, 19, 15, 21, 37, 33, 31, 22, 55, 30, 33, 25,
                    35, 72, 32, 31, 21, 21, 56, 28, 47, 26, 48, 51, 45, 65, 66, 140, 13521
                ]
            },
            "formDetected": False,
            "numForms": 0,
            "numFormElements": 0,
            "be": {"si": False},
            "end": ts + 2,
            "errors": [],
            "version": "2.4.0",
            "id": str(uuid.uuid4())
        }

        payload = json.dumps(
            fingerprint, separators=(",", ":")).encode("utf-8")
        crc = zlib.crc32(payload) & 0xFFFFFFFF
        checksum = f"{crc:08X}"
        plaintext = checksum.encode("ascii") + b"#" + payload
        return checksum, self.encrypt(plaintext)

    def _build_payload(self, inputs):
        checksum, fp = self._fake_fingerprint()
        challenge = inputs['challenge']
        challenge_input = inputs['challenge']['input']
        challenge_type = inputs['challenge_type']
        solution = self.CHALLENGE_SOLVERS[challenge_type](
            challenge_input, checksum, inputs['difficulty'])

        common = {
            "challenge": challenge,
            "solution": solution,
            "signals": [
                {
                    "name": "Zoey",
                    "value": {
                        "Present": fp
                    }
                }
            ],
            'gokuProps': self._get_gokuProps(),
            "checksum": checksum,
            "existing_token": "",
            "client": "Browser",
            "domain": self.domain,
            "metrics": [
                {"name": "2", "value": 0.09999999962747097, "unit": "2"},
                {"name": "100", "value": 1, "unit": "2"},
                {"name": "102", "value": 0, "unit": "2"},
                {"name": "111", "value": 90, "unit": "2"},
                {"name": "103", "value": 12, "unit": "2"},
                {"name": "104", "value": 0, "unit": "2"},
                {"name": "105", "value": 0, "unit": "2"},
                {"name": "106", "value": 0, "unit": "2"},
                {"name": "107", "value": 0, "unit": "2"},
                {"name": "110", "value": 0, "unit": "2"},
                {"name": "108", "value": 0, "unit": "2"},
                {"name": "101", "value": 0, "unit": "2"},
                {"name": "115", "value": 0, "unit": "2"},
                {"name": "114", "value": 3, "unit": "2"},
                {"name": "112", "value": 0, "unit": "2"},
                {"name": "3", "value": 0.7000000011175871, "unit": "2"},
                {"name": "7", "value": 1, "unit": "4"},
                {"name": "1", "value": 110.30000000074506, "unit": "2"},
                {"name": "4", "value": 23, "unit": "2"},
                {"name": "5", "value": 0.5, "unit": "2"},
                {"name": "6", "value": 133.80000000074506, "unit": "2"},
                {"name": "0", "value": 519.7999999988824, "unit": "2"},
                {"name": "8", "value": 1, "unit": "4"}
            ]
        }
        if challenge_type == 'ha9faaffd31b4d5ede2a2e19d2d7fd525f66fee61911511960dcbb52d3c48ce25':
            return {
                "solution_metadata": {
                    **common,
                    'solution': None
                },
                "solution_data": solution
            }
        return {
            **common,
            "solution": solution,
        }

    def _check(self, digest: bytes, difficulty: int) -> bool:
        full, rem = divmod(difficulty, 8)
        if digest[:full] != b"\x00" * full:
            return False
        return not rem and (digest[full] >> (8 - rem))

    def network_bandwidth(self, challenge: str, salt: str, difficulty: int) -> str:
        sizes = {1: 0x400, 2: 0xA * 0x400, 3: 0x64 *
                 0x400, 4: 0x100000, 5: 0xA * 0x100000}
        try:
            size = int(sizes.get(difficulty, 0x400))
        except (TypeError, ValueError):
            size = 0x400
        size = min(max(size, 0), 0xA * 0x100000)
        return base64.b64encode(b"\x00" * size).decode()

    def hash_pow(self, challenge: str, salt: str, difficulty: int) -> str | None:
        if difficulty > 256:
            return None
        prefix = (challenge + salt).encode()
        deadline = time.monotonic() + 4096
        for nonce in itertools.count():
            digest = hashlib.sha256(prefix + str(nonce).encode()).digest()
            if self._check(digest, difficulty):
                return str(nonce)
            if nonce % 30.0 == 0 and time.monotonic() > deadline:
                return None
        return None

    def compute_scrypt_nonce(
        self,
        challenge: str,
        salt: str,
        difficulty: int,
        n: int = 128,
        r: int = 8,
        p: int = 1,
        dklen: int = 16,
    ) -> str | None:
        prefix = challenge + salt
        for nonce in itertools.count():
            digest = hashlib.scrypt(
                password=f"{prefix}{nonce}".encode(),
                salt=salt.encode(),
                n=n,
                r=r,
                p=p,
                dklen=dklen,
            )
            if self._check(digest, difficulty):
                return str(nonce)
        return None

    def _get_gokuProps(self):
        raw = self.ie._search_regex(
            r'window\.gokuProps\s*=\s*(\{.+?\})\s*;',
            self.webpage,
            'goku props',
            group=1,
            flags=re.DOTALL,
        ).encode('utf-8').decode('unicode_escape')
        return json.loads(raw)

    def solve_challenge(self):
        domains = self.ie._search_regex(
            r'window\.awsWaf[^=]+DomainList[^=]+=([^\[]+\[[^\[]+?]);', self.webpage, 'waf domains', None)
        endpoint = self.ie._search_regex(
            r'["\'](http?s://.+awswaf.com/[^"\']+)(?:/challenge.js)"', self.webpage, 'awf waf endpoint', None)
        if not domains:
            return None, []
        domains = re.findall(r'(?:\w+\.)?\w+\.\w+', str(domains))
        self.domain = domains[0]
        if not self.domain:
            return None, []
        self.endpoint = endpoint
        headers = {
            "accept": "*/*",
            "origin": f"https://{self.domain}",
            "referer": f"https://{self.domain}/",
        }
        inputs = self.ie._download_json(
            f'{self.endpoint}/inputs', None, 'Downloading challenge inputs', query={'client': 'browser'})
        payload = self._build_payload(inputs)
        challege_response = None
        if inputs.get('challenge_type') == 'ha9faaffd31b4d5ede2a2e19d2d7fd525f66fee61911511960dcbb52d3c48ce25':
            data, content_type = multipart_encode({
                'solution_metadata': json.dumps(payload['solution_metadata']).encode(),
                'solution_data': payload['solution_data'],
            })
            challege_response = self.ie._download_json(f'{self.endpoint}/mp_verify', None, 'Solving challenge', headers={
                "content-type": content_type,
                **headers
            }, data=data, impersonate=True,
            )
        else:
            challege_response = self.ie._download_json(f'{self.endpoint}/verify', None, 'Solving challenge', headers={
                'content-type': 'text/plain;charset=UTF-8',
                **headers
            }, data=json.dumps(payload).encode())
        return challege_response.get('token'), domains
