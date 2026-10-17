"""Rebuild selected files and provenance offline from the already pinned archive."""
import hashlib
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parent
ARCHIVE = ROOT.parents[1] / 'external-candidates/snapshots/security-defect-corpus-84dd9c822eea735448353a01afe5e7e0df6549c4.tar.gz'
COMMIT = '84dd9c822eea735448353a01afe5e7e0df6549c4'
REPO = 'https://github.com/RusDavies/security-defect-corpus'
CASES = [
    ('TS-SECRET-001', 'reachable', 'positive', 'Synthetic payment API credential is a literal assigned to apiKey and returned by the exported function.'),
    ('TS-SECRET-001', 'unreachable', 'negative', 'Credential comes from env.PAYMENT_API_KEY; the only credential-shaped literal is an explicitly documented test placeholder.'),
    ('NODE-BACKDOOR-OPKEY-001', 'reachable', 'positive', 'operator-maintenance-key is embedded as OPERATOR_KEY and compared with the authentication header.'),
    ('NODE-BACKDOOR-OPKEY-001', 'unreachable', 'positive', 'The same embedded authentication key remains in retired code. Static secret presence is positive despite upstream reachability=false.'),
    ('NODE-BACKDOOR-OPKEY-001', 'fixed', 'negative', 'Authentication-key literal and operator override are removed; only role names and an error string remain.'),
    ('NODE-BACKDOOR-MAGIC-001', 'reachable', 'positive', 'debug-open-sesame is a hardcoded password alternative granting administrator access.'),
    ('NODE-BACKDOOR-MAGIC-001', 'unreachable', 'positive', 'The same password remains in a retired function. Static secret presence is positive despite upstream reachability=false.'),
    ('NODE-BACKDOOR-MAGIC-001', 'fixed', 'negative', 'Hardcoded password alternative is removed; authentication delegates to passwordVerifier.'),
]


def main():
    archive_hash = hashlib.sha256(ARCHIVE.read_bytes()).hexdigest()
    pinned_hash = next(line.split()[0] for line in (ARCHIVE.parent / 'SHA256SUMS').read_text().splitlines() if line.split()[-1] == ARCHIVE.name)
    if archive_hash != pinned_hash:
        raise ValueError('snapshot checksum does not match pinned inventory')
    with tarfile.open(ARCHIVE) as archive:
        members = {member.name.split('/', 1)[1]: member for member in archive.getmembers() if member.isfile() and '/' in member.name}
        def raw(path):
            return archive.extractfile(members[path]).read()
        truth = json.loads(raw('ground_truth/cases.json'))
        by_id = {case['id']: case for case in truth['cases']}
        provenance = ['LICENSE', 'README.md', 'docs/benchmark-validity.md', 'ground_truth/cases.json']
        paths = []
        for path in provenance:
            out = ROOT / 'upstream' / path
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(raw(path))
            paths.append(out.relative_to(ROOT).as_posix())
        records = []
        for family, version, label, rationale in CASES:
            case = by_id[family]
            path = case[version + '_file']
            source = raw(path)
            out = ROOT / 'upstream' / path
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(source)
            paths.append(out.relative_to(ROOT).as_posix())
            records.append(dict(id=family + '-' + version, family=family, detector='secrets', label=label,
                path=out.relative_to(ROOT).as_posix(), bytes=len(source), sha256=hashlib.sha256(source).hexdigest(),
                provenance=f'{REPO}/blob/{COMMIT}/{path}', rationale=rationale,
                upstream_variant=version, label_origin='maintainer source review of upstream ground truth, remapped to static credential presence',
                independent_label_review=False))
        (ROOT / 'cases.jsonl').write_text(''.join(json.dumps(record, ensure_ascii=False) + '\n' for record in records))
        (ROOT / 'provenance.json').write_text(json.dumps(dict(repository=REPO, commit=COMMIT,
            archive=ARCHIVE.name, archive_sha256=archive_hash, license='MIT', families=3, cases=8,
            source_policy='byte-preserving upstream files; no execution and no network',
            selection='all reachable/unreachable/fixed JS/TS hardcoded-authentication-secret families in pinned ground truth; omit duplicate fixed TS variant'), indent=2) + '\n')
        paths += ['cases.jsonl', 'provenance.json']
        (ROOT / 'SHA256SUMS').write_text(''.join(f'{hashlib.sha256((ROOT / path).read_bytes()).hexdigest()}  {path}\n' for path in sorted(paths)))


if __name__ == '__main__':
    main()
