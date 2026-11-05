#!/usr/bin/env python3
"""Prepare an unsigned publication copy; never modify the verified input bundle.

Requires macOS and Xcode command-line tools. Only debug symbols and local provenance
paths are removed. Runtime Mach-O sections, dyld blobs and exported symbols must match.
"""
# SPDX-License-Identifier: MIT
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import struct
import subprocess
import zipfile


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def inventory(app):
    result = {}
    for path in sorted(app.rglob('*')):
        require(not path.is_symlink(), 'Symlink in bundle: ' + path.name)
        if path.is_file():
            result[path.relative_to(app).as_posix()] = sha(path)
    return result


def macho_runtime(path):
    """Fingerprint allocated sections and loader data, excluding the debug symbol table."""
    b = path.read_bytes()
    require(len(b) >= 32, 'Truncated Mach-O')
    magic, cpu, subtype, kind, ncmds, commands_size, flags, reserved = struct.unpack_from('<IiiIIIII', b)
    require(magic == 0xfeedfacf, 'Expected a little-endian 64-bit Mach-O')
    require(32 + commands_size <= len(b), 'Truncated load commands')
    at, sections, blobs, identity_commands = 32, {}, {}, []
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', b, at)
        require(size >= 8 and at + size <= 32 + commands_size, 'Invalid load command')
        if cmd == 0x19:  # LC_SEGMENT_64
            require(size >= 72, 'Truncated segment')
            segment = struct.unpack_from('<II16sQQQQiiII', b, at)
            count = segment[-2]
            require(72 + count * 80 <= size, 'Truncated section list')
            for j in range(count):
                s = struct.unpack_from('<16s16sQQIIIIIIII', b, at + 72 + j * 80)
                name = s[1].rstrip(b'\0').decode() + ',' + s[0].rstrip(b'\0').decode()
                length, offset, section_type = s[3], s[4], s[8] & 0xff
                zero_fill = section_type in (1, 12, 18)
                require(zero_fill or offset + length <= len(b), 'Section outside file')
                require(name not in sections, 'Duplicate section')
                sections[name] = {'address': s[2], 'bytes': length, 'offset': offset,
                                  'flags': s[8], 'alignment': s[5],
                                  'sha256': None if zero_fill else hashlib.sha256(b[offset:offset + length]).hexdigest()}
        elif cmd in (0x26, 0x29, 0x80000033, 0x80000034):
            require(size == 16, 'Unexpected linkedit command size')
            offset, length = struct.unpack_from('<II', b, at + 8)
            require(offset + length <= len(b), 'Loader data outside file')
            blobs[str(cmd)] = {'bytes': length, 'sha256': hashlib.sha256(b[offset:offset + length]).hexdigest()}
        elif cmd in (0x1b, 0xc, 0x80000018, 0x8000001c, 0x32):
            identity_commands.append(b[at:at + size].hex())
        at += size
    require(at == 32 + commands_size and sections, 'Invalid command layout')
    symbols = subprocess.check_output(['xcrun', 'nm', '-g', '-j', str(path)])
    return {'cpu': cpu, 'subtype': subtype, 'kind': kind, 'sections': sections,
            'loaderData': blobs, 'identityCommands': identity_commands,
            'exportedSymbolNamesSHA256': hashlib.sha256(symbols).hexdigest()}


def sanitise_routing_manifest(value, project_root):
    """Keep hashes and relative provenance; a local file URL is not a download URL."""
    result = json.loads(json.dumps(value))
    source = result.get('sourceInput', {})
    if 'url' in source:
        require(source['url'].startswith(project_root.as_uri() + '/'), 'Unexpected local source URL')
        require(isinstance(source.get('file'), str) and not Path(source['file']).is_absolute()
                and '..' not in Path(source['file']).parts,
                'A relative input filename must remain available')
        require(source['url'] == (project_root / source['file']).as_uri(), 'Source filename and URL disagree')
        del source['url']
    for key in ('sourceDerivation', 'parentSource'):
        item = result.get(key, {})
        if 'receiptFile' in item:
            path = Path(item['receiptFile'])
            if path.is_absolute():
                relative = path.relative_to(project_root)
                item['receiptFile'] = relative.as_posix()
    text = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
    require('/Users/' not in text and 'file://' not in text, 'Unredacted local manifest path')
    return result


def privacy_scan(app, project_root):
    # These paths originate in the already-public Valhalla binary, not the owner's build.
    vendor_prefixes = (b'/Users/runner/work/valhalla-mobile/', b'/Users/runner/work/llama.cpp/')
    forbidden = [str(project_root).encode(), (str(Path.home()) + '/').encode()]
    prohibited = {'.p12', '.pfx', '.key', '.pem', '.p8', '.cer', '.mobileprovision'}
    patterns = re.compile(rb'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----|\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|sk-proj-[A-Za-z0-9_-]{25,}|AKIA[0-9A-Z]{16})')
    for path in app.rglob('*'):
        if not path.is_file():
            continue
        require(path.suffix.lower() not in prohibited, 'Signing material in publication bundle')
        require('_CodeSignature' not in path.parts, 'Expected an unsigned bundle')
        tail = b''
        with path.open('rb') as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b''):
                data = tail + chunk
                require(not any(prefix in data for prefix in forbidden), 'Owner build path in ' + path.name)
                vendor_redacted = data
                for prefix in vendor_prefixes:
                    vendor_redacted = vendor_redacted.replace(prefix, b'')
                require(b'/Users/' not in vendor_redacted, 'Unreviewed user path in ' + path.name)
                require(patterns.search(data) is None, 'Credential-like data in ' + path.name)
                tail = data[-1024:]


def prepare(app, project_root, stage, output, receipt):
    require(app.is_dir() and not app.is_symlink(), 'Missing or symlinked input bundle')
    require(not stage.exists() and not output.exists() and not receipt.exists(), 'Refusing to overwrite an artifact')
    require(not any(path.is_relative_to(app) for path in (stage, output, receipt)), 'Output overlaps the input bundle')
    require(not any(path.is_relative_to(stage / 'Payload') for path in (output, receipt)), 'Output overlaps the staged payload')
    before = inventory(app)
    info = plistlib.loads((app / 'Info.plist').read_bytes())
    executable = info['CFBundleExecutable']
    require(Path(executable).name == executable, 'Invalid executable name')
    original_runtime = macho_runtime(app / executable)
    stage.mkdir(parents=True)
    payload = stage / 'Payload'
    payload.mkdir()
    public_app = payload / app.name
    subprocess.run(['cp', '-cR', str(app), str(public_app)], check=True)
    subprocess.run(['xcrun', 'strip', '-S', str(public_app / executable)], check=True)
    public_runtime = macho_runtime(public_app / executable)
    require(original_runtime == public_runtime, 'Debug stripping changed runtime contents')
    manifest_name = 'moscow-routing.manifest.json'
    manifest_path = public_app / manifest_name
    original_manifest = json.loads(manifest_path.read_text())
    manifest = sanitise_routing_manifest(original_manifest, project_root)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    cohort_path = public_app / 'moscow-region-cohort.json'
    cohort = json.loads(cohort_path.read_text())
    require(cohort['files'][manifest_name]['sha256'] == before[manifest_name], 'Input cohort mismatch')
    cohort['files'][manifest_name] = {'bytes': manifest_path.stat().st_size, 'sha256': sha(manifest_path)}
    cohort_path.write_text(json.dumps(cohort, ensure_ascii=False, indent=2) + '\n')
    after = inventory(public_app)
    require(before.keys() == after.keys(), 'Publication changed the bundle file set')
    changed = sorted(name for name in before if before[name] != after[name])
    require(changed == sorted([executable, manifest_name, cohort_path.name]), 'Unexpected publication change')
    privacy_scan(public_app, project_root)
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for path in sorted(public_app.rglob('*')):
            if path.is_file():
                z.write(path, path.relative_to(stage).as_posix())
    with zipfile.ZipFile(output) as z:
        require(z.testzip() is None, 'ZIP CRC failure')
        require(len(z.infolist()) == len(after), 'Unexpected ZIP inventory')
        for member in z.infolist():
            name = member.filename.removeprefix('Payload/' + app.name + '/')
            require(name in after and hashlib.sha256(z.read(member)).hexdigest() == after[name], 'ZIP payload mismatch')
        require(z.getinfo('Payload/' + app.name + '/' + executable).external_attr >> 16 & 0o111,
                'Executable permission lost')
    result = {'schemaVersion': 1, 'version': info['CFBundleShortVersionString'], 'build': info['CFBundleVersion'],
              'artifact': output.name, 'bytes': output.stat().st_size, 'sha256': sha(output),
              'signed': False, 'physicalReleaseAccepted': False, 'publicationRevision': 1,
              'changedBundleFiles': changed, 'runtimeEquivalent': True,
              'runtimeSectionCount': len(public_runtime['sections']), 'runtimeIdentity': public_runtime,
              'ownerBuildPathsPresent': False, 'publicVendorBuildPathsRetained': True,
              'rawMapDataChanged': False, 'zipCRCValid': True, 'payloadFileCount': len(after)}
    receipt.parent.mkdir(parents=True, exist_ok=True)
    with receipt.open('x') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
        f.write('\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('app', 'project-root', 'stage', 'output', 'receipt'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    result = prepare(args.app.resolve(), args.project_root.resolve(), args.stage.resolve(),
                     args.output.resolve(), args.receipt.resolve())
    print('Verified publication package:', result['artifact'], result['sha256'])
