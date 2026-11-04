"""Docs fix for repos that were anonymised before the README rule (docfix.yml, user rule 2026-11-04).

For each repo: shallow clone of the default branch, readme.clean_doc on every README and prose document
(.md .mdx .markdown .rst .adoc; README.txt too): informative sections only, no open-source wording, no links.
If anything changed, ONE new commit on top (author and committer = the repo's latest commit author, date = 10 min
after the latest commit, UTC, rounded like the rest of the history), pushed fast-forward. History and commit hashes
stay as they are, so the imported pull requests keep pointing at the right commits.

Env: GH_TOKEN (owner's token), JOB (encrypted JSON list of "owner/repo"), JOB_KEY, BUDGET_MIN, DRY=1 for no push.
Repos created less than BUSY_MIN minutes ago (their anonymise run may still be pushing) are tried again later.
Logs show counts only: every repo name is masked. Writes more=true to GITHUB_OUTPUT while repos are left, and the
leftover list (encrypted) to next-job.txt."""
import base64
import calendar
import json
import os
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import readme  # noqa: E402

TOK = os.environ["GH_TOKEN"]
BUDGET = float(os.environ.get("BUDGET_MIN", "330")) * 60
BUSY_MIN = 120
PROSE = (".md", ".mdx", ".markdown", ".rst", ".adoc")
SKIP_DIRS = ("node_modules/", "vendor/", "third_party/", "third-party/", "thirdparty/", "external/", "deps/")
T0 = time.time()
WORK = os.path.abspath("work-docfix")


def mask(v):
    for x in {v, v.lower()}:
        print(f"::add-mask::{x}", flush=True)


def out(k, v):
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"{k}={v}\n")


def crypt(data, decrypt):
    p = subprocess.run(["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-a", "-A", "-pass", "env:JOB_KEY"]
                       + (["-d"] if decrypt else []), input=data, capture_output=True)
    if p.returncode != 0:
        sys.exit("the job could not be " + ("decrypted" if decrypt else "encrypted"))
    return p.stdout


def git(cwd, *a, env=None, check=True):
    return subprocess.run(["git", *a], cwd=cwd, capture_output=True, check=check, env={**os.environ, **(env or {})})


def api(path):
    p = subprocess.run(["gh", "api", path], capture_output=True, env={**os.environ, "GH_TOKEN": TOK})
    return json.loads(p.stdout) if p.returncode == 0 and p.stdout.strip().startswith(b"{") else None


def wanted(path):
    low = path.lower()
    base = low.rsplit("/", 1)[-1]
    if any(("/" + d) in ("/" + low) for d in SKIP_DIRS):
        return False
    return base.startswith("readme") and (base.endswith(PROSE + (".txt",)) or "." not in base) or low.endswith(PROSE)


def fix(repo):
    """'fixed', 'clean', 'busy' or 'missing'. Prints counts only."""
    info = api(f"repos/{repo}")
    if not info:
        print("  not found")
        return "missing"
    age = time.time() - calendar.timegm(time.strptime(info["created_at"], "%Y-%m-%dT%H:%M:%SZ"))
    if age < BUSY_MIN * 60:
        print(f"  created {age / 60:.0f} min ago (anonymise may still be running): later")
        return "busy"
    if info.get("size", 1) == 0:
        print("  empty repo")
        return "clean"
    branch = info["default_branch"]
    d = os.path.join(WORK, "r")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(WORK, exist_ok=True)
    auth = base64.b64encode(f"x-access-token:{TOK}".encode()).decode()
    hdr = ["-c", f"http.extraheader=Authorization: Basic {auth}"]
    r = subprocess.run(["git", *hdr, "clone", "-q", "--depth", "1", "--branch", branch, "--no-tags",
                        f"https://github.com/{repo}.git", d], capture_output=True,
                       env={**os.environ, "GIT_LFS_SKIP_SMUDGE": "1"})  # LFS files stay pointers (never edited)
    if r.returncode != 0:
        print("  clone failed")
        return "missing"
    files = [f for f in git(d, "ls-files", "-z").stdout.decode("utf-8", "surrogateescape").split("\0") if f]
    changed = 0
    for f in files:
        if not wanted(f):
            continue
        p = os.path.join(d, f)
        if os.path.islink(p) or not os.path.isfile(p) or os.path.getsize(p) > 5 * 2**20:
            continue
        raw = open(p, "rb").read()
        if b"\0" in raw[:8000]:
            continue
        s = raw.decode("utf-8", "surrogateescape")
        crlf = "\r\n" in s
        new = readme.clean_doc(s.replace("\r\n", "\n"), f)
        if crlf:
            new = new.replace("\n", "\r\n")
        if new != s:
            open(p, "wb").write(new.encode("utf-8", "surrogateescape"))
            changed += 1
    if not changed:
        print(f"  {len(files)} files, docs already clean")
        return "clean"
    name, email, ts = git(d, "log", "-1", "--format=%an%x00%ae%x00%ct").stdout.decode().strip().split("\0")
    when = (int(ts) // 600 + 1) * 600 + 600          # 10-20 min after the latest commit, on a 10-minute mark
    stamp = f"{when} +0000"
    env = {"GIT_AUTHOR_NAME": name, "GIT_AUTHOR_EMAIL": email, "GIT_AUTHOR_DATE": stamp,
           "GIT_COMMITTER_NAME": name, "GIT_COMMITTER_EMAIL": email, "GIT_COMMITTER_DATE": stamp}
    git(d, "add", "-A", env=env)
    git(d, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Docs: tidy README and guides", env=env)
    if os.environ.get("DRY") == "1":
        print(f"  {changed} docs would change (dry run)")
        return "fixed"
    for attempt in range(4):
        p = subprocess.run(["git", *hdr, "push", "-q", "origin", f"HEAD:refs/heads/{branch}"], cwd=d,
                           capture_output=True)
        if p.returncode == 0:
            print(f"  {changed} docs cleaned, 1 commit pushed")
            return "fixed"
        time.sleep(20 * (attempt + 1))
    print("  push failed: later")
    return "busy"


def main():
    repos = json.loads(crypt(os.environ["JOB"].strip().encode(), True))
    for x in repos:
        mask(x)
        mask(x.split("/")[1])
    left, n = [], {"fixed": 0, "clean": 0, "busy": 0, "missing": 0}
    for i, repo in enumerate(repos):
        if time.time() - T0 > BUDGET:
            left += repos[i:]
            break
        print(f"repo {i + 1}/{len(repos)}", flush=True)
        try:
            res = fix(repo)
        except Exception as e:  # no message text: it could quote a path or a name
            print(f"  failed: {type(e).__name__}; later")
            res = "busy"
        n[res] += 1
        if res == "busy":
            left.append(repo)
    shutil.rmtree(WORK, ignore_errors=True)
    print("done: " + json.dumps(n) + f"; left for the next run: {len(left)}")
    if left:
        with open("next-job.txt", "w") as f:
            f.write(crypt(json.dumps(left).encode(), False).decode())
        out("more", "true")
    else:
        out("more", "false")


if __name__ == "__main__":
    main()
