# SPDX-License-Identifier: MIT
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('public_ipa', Path(__file__).parents[1] / 'tools/prepare_public_ipa.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


class PublicationTests(unittest.TestCase):
    def test_redaction_preserves_source_identity_and_input(self):
        root = Path('/Users/example/Maps')
        original = {'sourceURL': 'https://example.org/data.osm.pbf', 'sourceSHA256': 'a' * 64,
                    'sourceInput': {'file': 'build/area.osm.pbf', 'url': root.as_uri() + '/build/area.osm.pbf', 'sha256': 'b' * 64},
                    'sourceDerivation': {'receiptFile': str(root / 'build/extract.json')},
                    'parentSource': {'receiptFile': str(root / 'build/source.json'), 'url': 'https://example.org/data.osm.pbf'}}
        snapshot = copy.deepcopy(original)
        result = tool.sanitise_routing_manifest(original, root)
        self.assertEqual(original, snapshot)
        self.assertNotIn('url', result['sourceInput'])
        self.assertEqual(result['sourceInput']['file'], 'build/area.osm.pbf')
        self.assertEqual(result['sourceDerivation']['receiptFile'], 'build/extract.json')
        self.assertEqual(result['parentSource']['receiptFile'], 'build/source.json')
        self.assertEqual(result['sourceSHA256'], 'a' * 64)
        self.assertEqual(result['sourceInput']['sha256'], 'b' * 64)

    def test_foreign_receipt_is_not_silently_rewritten(self):
        with self.assertRaises(ValueError):
            tool.sanitise_routing_manifest({'sourceDerivation': {'receiptFile': '/Users/other/source.json'}}, Path('/Users/example/Maps'))

    def test_missing_relative_provenance_fails(self):
        with self.assertRaises(ValueError):
            tool.sanitise_routing_manifest({'sourceInput': {'url': 'file:///Users/example/Maps/input.pbf'}}, Path('/Users/example/Maps'))

    def test_mismatched_filename_and_url_fails(self):
        with self.assertRaises(ValueError):
            tool.sanitise_routing_manifest({'sourceInput': {'file': 'other.pbf', 'url': 'file:///Users/example/Maps/input.pbf'}}, Path('/Users/example/Maps'))

    def test_unknown_path_field_fails(self):
        with self.assertRaises(ValueError):
            tool.sanitise_routing_manifest({'extra': '/Users/example/private'}, Path('/Users/example/Maps'))

    def test_credential_container_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            app = Path(folder)
            (app / 'key.p12').write_bytes(b'not-a-key')
            with self.assertRaises(ValueError):
                tool.privacy_scan(app, Path('/example/project'))

    def test_path_across_scan_chunk_boundary_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            app = Path(folder)
            (app / 'data').write_bytes(b'x' * (1024 * 1024 - 4) + b'/Users/example/private')
            with self.assertRaises(ValueError):
                tool.privacy_scan(app, Path('/example/project'))

    def test_reviewed_public_vendor_ci_prefixes_are_allowed(self):
        with tempfile.TemporaryDirectory() as folder:
            app = Path(folder)
            (app / 'vendor').write_bytes(b'/Users/runner/work/llama.cpp/source.cpp\0/Users/runner/work/valhalla-mobile/source.cpp')
            tool.privacy_scan(app, Path('/example/project'))

    def test_truncated_macho_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'binary'
            path.write_bytes(b'bad')
            with self.assertRaises(ValueError):
                tool.macho_runtime(path)


if __name__ == '__main__':
    unittest.main()
