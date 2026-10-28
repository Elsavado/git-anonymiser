"""Self-test (selftest.yml): the parallel blob step must give exactly the history the one-core rewrite gives.

Rewrites one public repo twice with a throw-away key, ANON_PARALLEL=0 and =1, and compares every ref.
Usage: python -I anon/selftest.py owner/name
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mirror as m  # noqa: E402
import extra  # noqa: E402

m.log = lambda msg: print(msg, flush=True)


def main(source):
    owner, name = source.split("/")
    work = tempfile.mkdtemp()
    m.PSEUDO = m.Pseudo(os.path.join(work, "key"))
    anon_cls, _, _ = extra.install(m, owner, name)
    base = os.path.join(work, "source.git")
    subprocess.run(["git", "clone", "-q", "--mirror", f"https://github.com/{source}.git", base], check=True)
    anon = anon_cls(m.collect_identities(base, {}))
    refs = {}
    for mode in ("0", "1"):
        os.environ["ANON_PARALLEL"] = mode
        repo = os.path.join(work, f"run{mode}.git")
        shutil.copytree(base, repo)
        t = time.time()
        cmap, _ = m.rewrite(repo, [], anon, True)
        refs[mode] = subprocess.run(["git", "for-each-ref", "--format=%(objectname) %(refname)"], cwd=repo,
                                    capture_output=True, text=True, check=True).stdout
        print(f"parallel={mode}: {time.time() - t:.0f}s, {len(cmap)} commits, {len(refs[mode].splitlines())} refs",
              flush=True)
    same = refs["0"] == refs["1"]
    print("IDENTICAL" if same else "DIFFERENT")
    return 0 if same else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
