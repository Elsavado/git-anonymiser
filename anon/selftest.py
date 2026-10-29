"""Self-test (selftest.yml) of the rewrite on a real public repo:
- the parallel blob step gives exactly the history the one-core rewrite gives, also when a worker dies;
- the rewritten history has the source's shape (commits, parents, branches, tags) once unpublished refs are gone;
- a file that takes too long is stopped and replaced; email_sub gives what EMAIL_RE.sub gives.

Rewrites one public repo with a throw-away key, ANON_PARALLEL=0 and =1 (and =1 with a dying worker), and compares
every ref. Usage: python -I anon/selftest.py owner/name
"""
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mirror as m  # noqa: E402
import extra  # noqa: E402

m.log = lambda msg: print(msg, flush=True)
_work = extra._pre_work


def dying_work(oids):
    """The first worker to get here exits at once, like a worker killed for memory."""
    try:
        os.close(os.open(os.path.join(os.environ["DIE_DIR"], "died"), os.O_CREAT | os.O_EXCL))
    except FileExistsError:
        return _work(oids)
    os._exit(9)


def check_timeout():
    import signal
    if not hasattr(signal, "SIGALRM"):
        print("timeout: not available here (no SIGALRM)", flush=True)
        return None
    extra.SLOW_BLOB = 2
    t = time.time()
    try:
        extra.timed(re.match, r"(a+)+$", "a" * 40 + "b")  # exponential: never ends on its own
        return "a runaway regex was not stopped"
    except extra.Slow:
        print(f"timeout: a runaway regex was stopped after {time.time() - t:.1f}s", flush=True)
    finally:
        extra.SLOW_BLOB = 300


def check_email():
    rnd = random.Random(7)
    for _ in range(100000):
        s = "".join(rnd.choice("aZ9.-_%+@ /x.cOm@@\n") for _ in range(rnd.randint(0, 40)))
        if extra.EMAIL_RE.sub("E", s) != extra.email_sub("E", s):
            return f"email_sub differs on {s!r}"
    s = "x" * 200000 + " a.b@c.de"
    t = time.time()
    if extra.email_sub("E", s) != "x" * 200000 + " E" or time.time() - t > 1:
        return "email_sub is wrong or slow on a long run"
    print("email: 100000 random strings same as the regex, long run fast", flush=True)


def main(source):
    owner, name = source.split("/")
    problems = [p for p in (check_timeout(), check_email()) if p]
    work = tempfile.mkdtemp()
    m.PSEUDO = m.Pseudo(os.path.join(work, "key"))
    anon_cls, _, _ = extra.install(m, owner, name)
    base = os.path.join(work, "source.git")
    subprocess.run(["git", "clone", "-q", "--mirror", f"https://github.com/{source}.git", base], check=True)
    dropped = extra.keep_published_refs(base)
    src = extra.shape(base)
    print(f"source: {len(src['parents'])} commits, {len(src['heads'])} branches, {len(src['tags'])} tags, "
          f"{dropped} unpublished refs left out", flush=True)
    anon = anon_cls(m.collect_identities(base, {}))
    refs = {}
    for mode in ("0", "1", "1-die"):
        os.environ["ANON_PARALLEL"] = mode[0]
        os.environ["DIE_DIR"] = tempfile.mkdtemp()
        extra._pre_work = dying_work if mode.endswith("die") else _work
        repo = os.path.join(work, f"run{mode}.git")
        shutil.copytree(base, repo)
        t = time.time()
        cmap, _ = m.rewrite(repo, [], anon, True)
        refs[mode] = subprocess.run(["git", "for-each-ref", "--format=%(objectname) %(refname)"], cwd=repo,
                                    capture_output=True, text=True, check=True).stdout
        shape = extra.shape_problems(src, repo, cmap)
        problems += [f"parallel={mode}: {p}" for p in shape]
        print(f"parallel={mode}: {time.time() - t:.0f}s, {len(cmap)} commits, {len(refs[mode].splitlines())} refs, "
              f"shape {'same as the source' if not shape else 'DIFFERENT'}", flush=True)
    if not (refs["0"] == refs["1"] == refs["1-die"]):
        problems.append("the parallel rewrites differ from the one-core rewrite")
    print("IDENTICAL" if not problems else "PROBLEMS: " + "; ".join(problems))
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
