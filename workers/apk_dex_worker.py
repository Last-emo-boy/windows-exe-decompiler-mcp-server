"""
APK/DEX analysis worker.
Handles APK structure parsing, manifest extraction, DEX class listing,
and DEX decompilation via jadx CLI.
"""

import json
import sys
import os
import struct
import zipfile
import subprocess
import tempfile
import shutil
from pathlib import Path


# ---------------------------------------------------------------------------
# Android Manifest binary XML minimal parser
# ---------------------------------------------------------------------------

CHUNK_AXML_FILE = 0x00080003
CHUNK_STRING_POOL = 0x001C0001
CHUNK_XML_START_ELEMENT = 0x00100102
CHUNK_XML_END_ELEMENT = 0x00100103
CHUNK_XML_START_NAMESPACE = 0x00100100


def _read_u16(buf, off):
    return struct.unpack_from('<H', buf, off)[0]


def _read_u32(buf, off):
    return struct.unpack_from('<I', buf, off)[0]


def _decode_string_pool(buf, offset):
    """Minimal string pool decoder for binary XML."""
    strings = []
    string_count = _read_u32(buf, offset + 8)
    _flags = _read_u32(buf, offset + 16)
    strings_start = _read_u32(buf, offset + 20)
    is_utf8 = (_flags & (1 << 8)) != 0

    offsets = []
    for i in range(string_count):
        offsets.append(_read_u32(buf, offset + 28 + i * 4))

    pool_start = offset + strings_start
    for off in offsets:
        pos = pool_start + off
        try:
            if is_utf8:
                # skip char-count & byte-count encoded lengths
                n = buf[pos]
                if n & 0x80:
                    pos += 2
                else:
                    pos += 1
                n = buf[pos]
                if n & 0x80:
                    byte_len = ((n & 0x7F) << 8) | buf[pos + 1]
                    pos += 2
                else:
                    byte_len = n
                    pos += 1
                strings.append(buf[pos:pos + byte_len].decode('utf-8', errors='replace'))
            else:
                char_len = _read_u16(buf, pos)
                pos += 2
                raw = buf[pos:pos + char_len * 2]
                strings.append(raw.decode('utf-16-le', errors='replace'))
        except Exception:
            strings.append('')
    return strings


def parse_binary_manifest(data: bytes) -> dict:
    """Extract basic info from AndroidManifest.xml binary format."""
    result = {
        'package': None,
        'version_code': None,
        'version_name': None,
        'min_sdk': None,
        'target_sdk': None,
        'permissions': [],
        'activities': [],
        'services': [],
        'receivers': [],
        'providers': [],
        'main_activity': None,
    }

    if len(data) < 8:
        return result

    magic = _read_u32(data, 0)
    if magic != CHUNK_AXML_FILE:
        return result

    strings = []
    pos = 8
    while pos < len(data) - 8:
        chunk_type = _read_u32(data, pos)
        chunk_size = _read_u32(data, pos + 4)
        if chunk_size < 8:
            break
        if chunk_type == CHUNK_STRING_POOL:
            strings = _decode_string_pool(data, pos)
        pos += chunk_size

    # Collect permissions and components from string pool heuristic
    for s in strings:
        if s.startswith('android.permission.'):
            result['permissions'].append(s)

    return result


# ---------------------------------------------------------------------------
# DEX header parsing
# ---------------------------------------------------------------------------

DEX_MAGIC = b'dex\n'
DEX_HEADER_SIZE = 112


def parse_dex_header(data: bytes) -> dict:
    """Parse DEX file header for basic metadata."""
    if len(data) < DEX_HEADER_SIZE or data[:4] != DEX_MAGIC:
        return {'error': 'Not a valid DEX file'}

    version = data[4:7].decode('ascii', errors='replace')
    checksum = _read_u32(data, 8)
    file_size = _read_u32(data, 32)
    string_ids_size = _read_u32(data, 56)
    type_ids_size = _read_u32(data, 64)
    proto_ids_size = _read_u32(data, 68)
    method_ids_size = _read_u32(data, 80)
    class_defs_size = _read_u32(data, 96)

    return {
        'version': version,
        'checksum': hex(checksum),
        'file_size': file_size,
        'string_ids_count': string_ids_size,
        'type_ids_count': type_ids_size,
        'proto_ids_count': proto_ids_size,
        'method_ids_count': method_ids_size,
        'class_defs_count': class_defs_size,
    }


def list_dex_classes(data: bytes) -> list:
    """List class names from DEX string table (heuristic)."""
    classes = []
    if len(data) < DEX_HEADER_SIZE or data[:4] != DEX_MAGIC:
        return classes

    string_ids_size = _read_u32(data, 56)
    string_ids_off = _read_u32(data, 60)

    for i in range(min(string_ids_size, 50000)):
        off_pos = string_ids_off + i * 4
        if off_pos + 4 > len(data):
            break
        string_data_off = _read_u32(data, off_pos)
        if string_data_off >= len(data):
            continue
        # Skip ULEB128 length
        pos = string_data_off
        while pos < len(data) and data[pos] & 0x80:
            pos += 1
        pos += 1
        end = data.find(0, pos)
        if end < 0:
            end = min(pos + 256, len(data))
        s = data[pos:end].decode('utf-8', errors='replace')
        if s.startswith('L') and ';' in s and '/' in s:
            cls = s[1:s.index(';')].replace('/', '.')
            classes.append(cls)

    return sorted(set(classes))


# ---------------------------------------------------------------------------
# APK structure parsing
# ---------------------------------------------------------------------------

KNOWN_ANDROID_PACKERS = {
    'libjiagu.so': {'name': '360加固', 'confidence': 0.95},
    'libDexHelper.so': {'name': '梆梆加固', 'confidence': 0.95},
    'libBugly.so': {'name': '腾讯Bugly', 'confidence': 0.6},
    'libexec.so': {'name': '爱加密', 'confidence': 0.85},
    'libmobisec.so': {'name': '阿里聚安全', 'confidence': 0.9},
    'libsecexe.so': {'name': '梆梆企业版', 'confidence': 0.9},
    'libprotectClass.so': {'name': '360加固Pro', 'confidence': 0.9},
    'libtup.so': {'name': '腾讯乐固', 'confidence': 0.9},
    'libshell.so': {'name': '通用壳', 'confidence': 0.5},
    'libDexCryptor.so': {'name': 'DexCryptor', 'confidence': 0.85},
    'libdexjni.so': {'name': 'DexProtector', 'confidence': 0.85},
}


def parse_apk_structure(file_path: str) -> dict:
    """Full APK structure analysis."""
    result = {
        'ok': True,
        'format': 'APK',
        'entries': [],
        'dex_files': [],
        'native_libs': {},
        'manifest': None,
        'signing': None,
        'packer_indicators': [],
        'total_size': os.path.getsize(file_path),
    }

    try:
        with zipfile.ZipFile(file_path, 'r') as zf:
            for info in zf.infolist():
                entry = {
                    'name': info.filename,
                    'size': info.file_size,
                    'compressed_size': info.compress_size,
                    'compress_type': 'deflate' if info.compress_type == zipfile.ZIP_DEFLATED else 'stored',
                }
                result['entries'].append(entry)

                # DEX files
                if info.filename.endswith('.dex'):
                    dex_data = zf.read(info.filename)
                    dex_info = parse_dex_header(dex_data)
                    dex_info['filename'] = info.filename
                    dex_info['classes'] = list_dex_classes(dex_data)[:200]
                    result['dex_files'].append(dex_info)

                # Native libraries
                if info.filename.startswith('lib/') and info.filename.endswith('.so'):
                    parts = info.filename.split('/')
                    if len(parts) >= 3:
                        arch = parts[1]
                        lib_name = parts[-1]
                        if arch not in result['native_libs']:
                            result['native_libs'][arch] = []
                        result['native_libs'][arch].append({
                            'name': lib_name,
                            'size': info.file_size,
                        })
                        # Check packer indicators
                        if lib_name in KNOWN_ANDROID_PACKERS:
                            indicator = KNOWN_ANDROID_PACKERS[lib_name].copy()
                            indicator['found_in'] = info.filename
                            result['packer_indicators'].append(indicator)

                # Signing info
                if info.filename.startswith('META-INF/') and info.filename.endswith(('.RSA', '.DSA', '.EC')):
                    result['signing'] = {
                        'cert_file': info.filename,
                        'cert_size': info.file_size,
                    }

            # Parse manifest
            if 'AndroidManifest.xml' in zf.namelist():
                try:
                    manifest_data = zf.read('AndroidManifest.xml')
                    result['manifest'] = parse_binary_manifest(manifest_data)
                except Exception as e:
                    result['manifest'] = {'parse_error': str(e)}

    except zipfile.BadZipFile:
        result['ok'] = False
        result['error'] = 'Not a valid ZIP/APK file'
    except Exception as e:
        result['ok'] = False
        result['error'] = str(e)

    return result


# ---------------------------------------------------------------------------
# JADX integration for full DEX decompilation
# ---------------------------------------------------------------------------

def decompile_with_jadx(file_path: str, class_filter: str = None) -> dict:
    """Decompile APK/DEX using jadx CLI."""
    jadx_bin = shutil.which('jadx')
    if not jadx_bin:
        jadx_home = os.environ.get('JADX_HOME', '')
        if jadx_home:
            candidate = os.path.join(jadx_home, 'bin', 'jadx')
            if os.path.isfile(candidate):
                jadx_bin = candidate
    if not jadx_bin:
        return {'ok': False, 'error': 'jadx not found. Install via: apt install jadx or set JADX_HOME'}

    output_dir = tempfile.mkdtemp(prefix='jadx_out_')
    try:
        cmd = [jadx_bin, '-d', output_dir, '--no-res', '--no-imports', file_path]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        sources = {}
        source_root = os.path.join(output_dir, 'sources')
        if os.path.isdir(source_root):
            for root, _dirs, files in os.walk(source_root):
                for fname in files:
                    if fname.endswith('.java'):
                        full = os.path.join(root, fname)
                        rel = os.path.relpath(full, source_root)
                        class_name = rel.replace(os.sep, '.').removesuffix('.java')
                        if class_filter and class_filter not in class_name:
                            continue
                        try:
                            with open(full, 'r', encoding='utf-8', errors='replace') as f:
                                sources[class_name] = f.read()
                        except Exception:
                            sources[class_name] = '<read error>'

        return {
            'ok': True,
            'class_count': len(sources),
            'sources': sources,
            'jadx_stderr': proc.stderr[:2000] if proc.stderr else None,
        }
    except subprocess.TimeoutExpired:
        return {'ok': False, 'error': 'jadx timed out (120s)'}
    except Exception as e:
        return {'ok': False, 'error': str(e)}
    finally:
        shutil.rmtree(output_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# JNI export detection in native SO libraries
# ---------------------------------------------------------------------------

def detect_jni_exports(file_path: str) -> list:
    """Detect JNI-style exports from an ELF .so extracted from APK."""
    exports = []
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        # Simple string scan for Java_ prefixed symbols
        pos = 0
        while True:
            idx = data.find(b'Java_', pos)
            if idx < 0:
                break
            end = idx
            while end < len(data) and data[end] != 0 and end - idx < 512:
                end += 1
            sym = data[idx:end].decode('ascii', errors='replace')
            if len(sym) > 6 and '/' not in sym:
                parts = sym.split('_')
                if len(parts) >= 3:
                    exports.append({
                        'symbol': sym,
                        'class_hint': '.'.join(parts[1:-1]),
                        'method_hint': parts[-1],
                    })
            pos = end + 1

    except Exception:
        pass
    return exports


# ---------------------------------------------------------------------------
# Worker entry point
# ---------------------------------------------------------------------------

def main():
    raw = sys.stdin.read().strip()
    if not raw:
        json.dump({'ok': False, 'error': 'No input'}, sys.stdout)
        return

    request = json.loads(raw)
    action = request.get('action', '')
    file_path = request.get('file_path', '')

    if file_path and not os.path.isfile(file_path):
        json.dump({'ok': False, 'error': f'File not found: {file_path}'}, sys.stdout)
        return

    if action == 'parse_apk':
        result = parse_apk_structure(request['file_path'])
    elif action == 'decompile_dex':
        result = decompile_with_jadx(
            request['file_path'],
            class_filter=request.get('class_filter'),
        )
    elif action == 'list_dex_classes':
        with open(request['file_path'], 'rb') as f:
            data = f.read()
        classes = list_dex_classes(data)
        result = {'ok': True, 'classes': classes, 'class_count': len(classes)}
    elif action == 'detect_jni':
        jni = detect_jni_exports(request['file_path'])
        result = {'ok': True, 'jni_exports': jni, 'count': len(jni)}
    elif action == 'detect_packer':
        result = parse_apk_structure(request['file_path'])
        result = {
            'ok': True,
            'packer_indicators': result.get('packer_indicators', []),
            'native_libs': result.get('native_libs', {}),
        }
    else:
        result = {'ok': False, 'error': f'Unknown action: {action}'}

    json.dump(result, sys.stdout)


if __name__ == '__main__':
    main()
