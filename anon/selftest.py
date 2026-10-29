"""Self-test (selftest.yml) of the rewrite on a real public repo:
- the parallel blob step gives exactly the history the one-core rewrite gives, also when a worker dies;
- the rewritten history has the source's shape (commits, parents, branches, tags) once unpublished refs are gone;
- a file that takes too long is stopped and replaced; email_sub gives what EMAIL_RE.sub gives;
- the replacement rules (made-up names only): escaped underscores, ordinary words kept in prose, logins in merge
  lines, ref names, TODO(x) and metadata files, reverse-DNS ids, CamelCase joins, bot accounts.

Rewrites one public repo with a throw-away key, ANON_PARALLEL=0 and =1 (and =1 with a dying worker), and compares
every ref. Usage: python -I anon/selftest.py owner/name   (or --rules: only the replacement rules)
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


def check_twins(work, anon):
    """Two commits on the same parent, 1 s apart from two e-mails, must stay two commits after rounding."""
    repo = os.path.join(work, "twins.git")
    subprocess.run(["git", "init", "-q", "--bare", repo], check=True)
    git = lambda *a, **env: subprocess.run(["git", *a], cwd=repo, check=True, capture_output=True,  # noqa: E731
                                           env={**os.environ, **env}).stdout.decode().strip()
    tree = subprocess.run(["git", "mktree"], cwd=repo, input=b"", capture_output=True, check=True).stdout.decode().strip()
    who = dict(GIT_AUTHOR_NAME="Ann Example", GIT_COMMITTER_NAME="Ann Example")
    base = git("commit-tree", tree, "-m", "base", **who, GIT_AUTHOR_EMAIL="a@x.org", GIT_COMMITTER_EMAIL="a@x.org",
               GIT_AUTHOR_DATE="1700000000 +0000", GIT_COMMITTER_DATE="1700000000 +0000")
    for i, mail in enumerate(("a@x.org", "a@y.org")):
        c = git("commit-tree", tree, "-p", base, "-m", "same change", **who, GIT_AUTHOR_EMAIL=mail,
                GIT_COMMITTER_EMAIL=mail, GIT_AUTHOR_DATE=f"{1700000100 + i} +0200",
                GIT_COMMITTER_DATE=f"{1700000100 + i} +0200")
        git("update-ref", f"refs/heads/b{i}", c)
    git("symbolic-ref", "HEAD", "refs/heads/b0")
    src = extra.shape(repo)
    cmap, _ = m.rewrite(repo, [], anon, True)
    problems = extra.shape_problems(src, repo, cmap)
    print(f"twins: {len(src['parents'])} commits in, {len(extra.shape(repo)['parents'])} out", flush=True)
    return "; ".join(f"twins: {p}" for p in problems) or None


def check_rules():
    """The replacement rules on made-up names (no real project or person)."""
    work = tempfile.mkdtemp()
    m.PSEUDO = m.Pseudo(os.path.join(work, "key"))
    cls, _, _ = extra.install(m, "zorblax-labs", "quuxo_kit", "https://quuxo.dev", ["quuxo.dev", "Quuxo"], "",
                              "Widget Toolkit")
    ids = {k: (m.PSEUDO.name(k) if " " in k else m.PSEUDO.login(k)) for k in ("Zed Quorra", "zq9dev", "page", "vtrondel")}
    a = cls(ids)
    cases = [
        ("escaped underscore", a.text(r"see quuxo\_kit/core.py"), lambda r: "quuxo" not in r.lower()),
        ("ordinary word kept", a.text("split at page boundaries"), lambda r: "at page boundaries" in r),
        ("ordinary word as @login", a.text("thanks @page"), lambda r: "@page" not in r),
        ("merge line", a.text("Merge pull request #5 from zorblax-labs/zq9dev-patch-1"),
         lambda r: "zq9dev" not in r and "zorblax" not in r),
        ("merge branch", a.text("Merge branch 'vtrondel/fix-join' into main"), lambda r: "vtrondel" not in r),
        ("ref name", a.ref("refs/heads/vtrondel/fix-join"), lambda r: "vtrondel" not in r and r.startswith("refs/heads/")),
        ("metadata file", a.meta('{"login": "zq9dev", "name": "Zed Quorra", "role": "page"}'),
         lambda r: "zq9dev" not in r and "Quorra" not in r and '"page"' in r),
        ("TODO(login)", a.code("# TODO(vtrondel): remove"), lambda r: "vtrondel" not in r),
        ("reverse DNS", a.code("appId = 'dev.quuxo.desktop'"), lambda r: "quuxo" not in r.lower()),
        ("CamelCase join", a.code("class QuuxoDriver(BaseQuuxoError)"), lambda r: "Quuxo" not in r),
        ("bot account", a.code("zorblax-labs-release[bot]"), lambda r: "zorblax" not in r),
        ("plain code kept", a.code("page = paginate(page_size)"), lambda r: r == "page = paginate(page_size)"),
    ]
    bad = [name for name, got, ok in cases if not ok(got)]
    print(f"rules: {len(cases) - len(bad)}/{len(cases)} ok" + (f" (failed: {', '.join(bad)})" if bad else ""), flush=True)
    return f"rules failed: {', '.join(bad)}" if bad else None


def main(source):
    if source == "--rules":
        problem = check_rules()
        print("IDENTICAL" if not problem else "PROBLEMS: " + problem)
        return 0 if not problem else 1
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
    problems += [p for p in (check_twins(work, anon),) if p]
    problems += [p for p in (check_rules(),) if p]  # last: it installs a second, made-up project
    print("IDENTICAL" if not problems else "PROBLEMS: " + "; ".join(problems))
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
