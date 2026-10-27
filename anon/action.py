"""Anonymise one GitHub repo and push it to a new PRIVATE repo (run by .github/workflows/anonymise.yml).

Mode "all":
  clone --mirror + PR/issue/review history -> gitleaks scan -> history rewrite (mirror.py: authors -> imaginary
  names, timestamps rounded to 10 min in UTC, secrets -> ***REDACTED***, commit hashes shift) with every LICENSE
  file removed from all history, READMEs and all text anonymised by extra.py (imaginary project name, links,
  emails -> redactedemail@gmail.com) -> verification -> new private repo -> push branches and tags ->
  issue import.
Mode "issues": resume the issue import from state/ (a previous run that hit the time budget).

Issues and pull requests are imported as issues (GitHub cannot recreate PRs) with their original, rounded
dates via the issue import API; PRs carry the label "pull request" (and "merged" when they were merged).
Logs carry counts only, no titles or names.

Public repo: the job (source, name, aliases, target) arrives encrypted in JOB and is decrypted with JOB_KEY; every
name in it is masked in the logs before anything is printed. The name record goes to a private repo (NAMES_REPO).

Env: GH_TOKEN, PSEUDONYM_KEY (hex), JOB (encrypted JSON), JOB_KEY, NAMES_REPO, MODE, OWNER (target account).
Writes state/ (api.json, progress.json) and sets the step output more=true when the import must continue.
"""
import json
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import extra  # noqa: E402
import mirror as m  # noqa: E402

STATE = os.path.abspath("state")
WORK = os.path.abspath("work")
BUDGET = float(os.environ.get("BUDGET_MIN", "320")) * 60  # leave room under the 6 h job limit for the hand-off
T0 = time.time()
TOK = os.environ["GH_TOKEN"]
OWNER = os.environ["OWNER"]


def mask(*values):
    """Tell Actions to hide these strings everywhere in the (public) logs from now on."""
    for v in values:
        for x in {v, v.lower(), v.upper()} if v else ():
            if len(x) >= 3:
                print(f"::add-mask::{x}", flush=True)


def decrypt_job():
    p = subprocess.run(["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-a", "-A", "-pass", "env:JOB_KEY"],
                       input=os.environ["JOB"].strip().encode(), capture_output=True)
    if p.returncode != 0:
        sys.exit("the job could not be decrypted (wrong JOB_KEY?)")
    return json.loads(p.stdout)


JOB = decrypt_job()
SOURCE = JOB["source"].strip()
TARGET = (JOB.get("target") or "").strip()  # empty: the project's imaginary name (set in main)
GIVEN_NAME = (JOB.get("name") or "").strip()
ALIASES = [a.strip() for a in (JOB.get("aliases") or "").split(",") if a.strip()]
mask(SOURCE, *SOURCE.split("/"), TARGET, GIVEN_NAME, *ALIASES)
MODE = os.environ.get("MODE", "all")
PR_LABEL, MERGED_LABEL = "pull request", "merged"
MAX_BODY = 60000

# READMEs stay, anonymised (extra.py); LICENSE files are removed from the whole history (mirror.py).
m.token = lambda acct: TOK
ANON = m.Anon


def out(key, value):
    with open(os.environ.get("GITHUB_OUTPUT", os.devnull), "a") as f:
        f.write(f"{key}={value}\n")


def api(method, path, body=None, accept=None):
    """One REST call through gh (waits for the quota when it is used up). Returns (json, error)."""
    for attempt in range(1, 21):  # rate limits are shared with every other job on the account: be patient
        cmd = ["gh", "api", "-X", method, path]
        if accept:
            cmd += ["-H", f"Accept: {accept}"]
        p = subprocess.run(cmd + (["--input", "-"] if body is not None else []), env=m.gh_env(TOK),
                           input=json.dumps(body).encode() if body is not None else None, capture_output=True)
        if p.returncode == 0:
            return (json.loads(p.stdout) if p.stdout.strip() else {}), None
        err = (p.stderr or p.stdout).decode(errors="replace")
        if m.wait_for_quota(TOK):
            continue
        if "rate limit" in err.lower() or "abuse" in err.lower():
            time.sleep(min(60 * attempt, 600))
            continue
        return None, err[-300:]
    return None, "gave up after repeated rate limits"


def anonymise():
    owner, name = SOURCE.split("/")
    meta, err = m.gh_api(f"repos/{SOURCE}", TOK)
    if err or not meta:
        sys.exit(f"source repo not readable: {err}")
    meta = meta[0]
    os.makedirs(WORK, exist_ok=True)
    repo = os.path.join(WORK, "repo.git")
    m.clone(owner, name, TOK, repo)
    m.log(f"cloned in {round(time.time() - T0)}s")
    data = m.fetch_api(owner, name, TOK, meta["has_issues"])
    data["_upstream_owners"] = sorted(set(data.get("_upstream_owners", [])) | {owner})
    m.log("history fetched: " + ", ".join(f"{k} {len(data.get(k, []))}" for k in
                                         ("issues", "issue_comments", "pulls", "review_comments")))
    findings = m.gitleaks(repo, os.path.join(WORK, "leaks.json"))
    raw = os.path.join(WORK, "api_raw.json")
    with open(raw, "w", encoding="utf-8") as f:
        json.dump(data, f)
    api_findings = m.gitleaks(raw, os.path.join(WORK, "leaks_api.json"), mode="dir")
    os.remove(raw)
    secrets = sorted({f["Secret"].encode("utf-8", "surrogateescape") for f in findings + api_findings
                      if len(f.get("Secret") or "") >= m.MIN_SECRET}, key=len, reverse=True)
    m.log(f"scan: {len(findings) + len(api_findings)} findings, {len(secrets)} secrets")
    ids = m.collect_identities(repo, data)
    anon = ANON(ids)
    cmap, removed, after = m.clean_repo(repo, secrets, anon, WORK, "repo")
    m.log(f"rewritten: {len(cmap)} commits, {removed} LICENSE paths removed, {len(after)} findings left")
    data.pop("_upstream_owners", None)
    # Comment -> issue links are URLs, which the anonymiser replaces: keep the numbers first.
    for c in data.get("issue_comments", []):
        c["_num"] = num(c.get("issue_url"))
    for c in data.get("review_comments", []):
        c["_num"] = num(c.get("pull_request_url"))
    clean = m.anon_api(data, cmap, anon, secrets)
    problems = m.verify_clean(repo, cmap)
    if after:
        problems.append(f"{len(after)} gitleaks finding(s) remain after the rewrite")
    if problems:
        sys.exit("not pushed, verification failed: " + "; ".join(problems))
    os.makedirs(STATE, exist_ok=True)
    with open(os.path.join(STATE, "api.json"), "w", encoding="utf-8") as f:
        json.dump(clean, f)
    push(repo)


def push(repo):
    git = lambda *a: m.run(["git", *a], cwd=repo)  # noqa: E731
    refs = git("for-each-ref", "--format=%(refname)").decode().split()
    for r in refs:  # refs/pull/* and other hidden refs: GitHub refuses them
        if not r.startswith(("refs/heads/", "refs/tags/")):
            git("update-ref", "-d", r)
    head = git("symbolic-ref", "HEAD").decode().strip()
    got, err = api("POST", "user/repos", {"name": TARGET, "private": True, "has_wiki": False,
                                          "has_projects": False, "auto_init": False})
    if err and "already exists" in err:  # a rerun after a failed issue import: reuse it if private and issue-free
        got, _ = api("GET", f"repos/{OWNER}/{TARGET}")
        if not got or got.get("open_issues_count") or api("GET", f"repos/{OWNER}/{TARGET}/issues?state=all&per_page=1")[0]:
            sys.exit("the target repo already exists and has issues; stopping")
        m.log("reusing the existing private repo (no issues yet)")
    elif err:
        sys.exit(f"could not create the private repo: {err}")
    if not got.get("private"):
        sys.exit("the new repo is not private; stopping before any push")
    url = f"https://x-access-token:{TOK}@github.com/{OWNER}/{TARGET}.git"

    def send(*specs):
        p = subprocess.run(["git", "push", "--quiet", url, *specs], cwd=repo, capture_output=True)
        return p.returncode == 0

    branches = [r for r in git("for-each-ref", "--format=%(refname)", "refs/heads").decode().split()]
    branches.sort(key=lambda r: r != head)  # default branch first
    for b in branches:
        if send(f"+{b}:{b}"):
            continue
        # Over GitHub's 2 GB push limit: send the first-parent history in steps, then the tip.
        chain = git("rev-list", "--first-parent", "--reverse", b).decode().split()
        for i in range(2000, len(chain), 2000):
            if not send(f"+{chain[i]}:{b}"):
                sys.exit(f"push failed for a branch at step {i}")
        if not send(f"+{b}:{b}"):
            sys.exit("push failed for a branch")
    tags = git("for-each-ref", "--format=%(refname)", "refs/tags").decode().split()
    for i in range(0, len(tags), 100):
        if not send(*[f"+{t}:{t}" for t in tags[i:i + 100]]):
            m.log(f"warning: a batch of {len(tags[i:i + 100])} tags was not pushed")
    api("PATCH", f"repos/{OWNER}/{TARGET}", {"default_branch": head.removeprefix("refs/heads/")})
    m.log(f"pushed {len(branches)} branches, {len(tags)} tags to a new private repo")
    open(os.path.join(STATE, "pushed"), "w").close()  # a retry after this point only redoes the issue import


def record_name(title):
    """Keeps original name -> imaginary name in names.csv of this (private) anonymiser repo."""
    import base64
    repo = os.environ["NAMES_REPO"]  # private: the record must never sit in the public repo
    line = f"{time.strftime('%Y-%m-%d')},{SOURCE},{title},{OWNER}/{TARGET}\n"
    for _ in range(8):  # parallel runs: retry on a stale file version
        cur, err = api("GET", f"repos/{repo}/contents/names.csv")
        text = base64.b64decode(cur["content"]).decode() if cur else "date,original repo,imaginary name,new repo\n"
        body = {"message": "Record a project name", "content": base64.b64encode((text + line).encode()).decode()}
        if cur:
            body["sha"] = cur["sha"]
        if api("PUT", f"repos/{repo}/contents/names.csv", body)[0] is not None:
            return
        time.sleep(5)
    m.log("warning: the name record could not be saved")


def num(url):
    return int(url.rstrip("/").rsplit("/", 1)[1]) if url else None


def items(data):
    """Issues and PRs as import payloads, oldest number first."""
    by = {}
    for it in data.get("issues", []):
        by[it["number"]] = dict(it)
    for pr in data.get("pulls", []):
        by.setdefault(pr["number"], {}).update({k: v for k, v in pr.items() if k not in by.get(pr["number"], {})})
        by[pr["number"]]["_pr"] = pr
    comments = {}
    for c in data.get("issue_comments", []):
        comments.setdefault(c.get("_num"), []).append((c.get("created_at"), c.get("user"), c.get("body")))
    for c in data.get("review_comments", []):
        where = f"`{c['path']}`: " if c.get("path") else ""
        comments.setdefault(c.get("_num"), []).append(
            (c.get("created_at"), c.get("user"), f"Review comment on {where}\n\n{c.get('body') or ''}"))
    for n, reviews in (data.get("reviews") or {}).items():
        for r in reviews:
            if r.get("body") or r.get("state") in ("APPROVED", "CHANGES_REQUESTED"):
                state = (r.get("state") or "").replace("_", " ").lower()
                comments.setdefault(int(n), []).append(
                    (r.get("submitted_at"), r.get("user"), f"Review ({state})\n\n{r.get('body') or ''}".strip()))
    for n in sorted(by):
        it = by[n]
        pr = it.get("_pr") or (it if it.get("pull_request") else None)
        who = (it.get("user") or {}).get("login")
        labels = [lb["name"] for lb in it.get("labels") or [] if isinstance(lb, dict) and lb.get("name")]
        if pr is not None:
            labels.append(PR_LABEL)
            if (pr.get("merged_at") or (it.get("pull_request") or {}).get("merged_at")):
                labels.append(MERGED_LABEL)
        body = (f"_Opened by {who}_\n\n" if who else "") + (it.get("body") or "")
        issue = {"title": (it.get("title") or f"Item {n}")[:250], "body": (body.strip() or "(no description)")[:MAX_BODY],
                 "created_at": it.get("created_at"), "closed": it.get("state") == "closed",
                 "labels": sorted(set(labels))}
        if it.get("closed_at"):
            issue["closed_at"] = it["closed_at"]
        if it.get("updated_at"):
            issue["updated_at"] = it["updated_at"]
        cs = []
        for when, user, text in sorted(comments.get(n, []), key=lambda c: c[0] or ""):
            if not when or not (text or "").strip():
                continue
            who_c = (user or {}).get("login")
            cs.append({"created_at": when, "body": ((f"_Comment by {who_c}_\n\n" if who_c else "") + text)[:MAX_BODY]})
        yield n, {"issue": issue, "comments": cs}


def import_issues():
    with open(os.path.join(STATE, "api.json"), encoding="utf-8") as f:
        data = json.load(f)
    prog_path = os.path.join(STATE, "progress.json")
    prog = {"done": 0, "failed": 0}
    if os.path.exists(prog_path):
        with open(prog_path) as f:
            prog = json.load(f)
    todo = list(items(data))
    accept = "application/vnd.github.golden-comet-preview+json"
    m.log(f"issue import: {len(todo)} items, {prog['done']} already done")
    for i, (_, payload) in enumerate(todo):
        if i < prog["done"]:
            continue
        if time.time() - T0 > BUDGET:
            break
        res, err = api("POST", f"repos/{OWNER}/{TARGET}/import/issues", payload, accept)
        status = (res or {}).get("status")
        while res and status == "pending":
            time.sleep(1)
            res, err = api("GET", f"repos/{OWNER}/{TARGET}/import/issues/{res['id']}", accept=accept)
            status = (res or {}).get("status")
        if status != "imported":
            prog["failed"] += 1
            m.log(f"item {i + 1} not imported ({status or 'error'})")
        prog["done"] = i + 1
        with open(prog_path, "w") as f:
            json.dump(prog, f)
    more = prog["done"] < len(todo)
    m.log(f"issue import: {prog['done']}/{len(todo)} done, {prog['failed']} failed" + (", continuing in a new run" if more else ""))
    out("more", "true" if more else "false")


def main():
    os.makedirs(WORK, exist_ok=True)
    m.LOG = open(os.path.join(WORK, "run.log"), "a", encoding="utf-8")
    m.log = lambda msg: (print(msg, flush=True), m.LOG.write(msg + "\n"), m.LOG.flush())
    key = os.path.join(WORK, "pseudonym.key")
    with open(key, "wb") as f:
        f.write(bytes.fromhex(os.environ["PSEUDONYM_KEY"]))
    m.PSEUDO = m.Pseudo(key)
    out("more", "false")
    global TARGET, ANON
    owner, name = SOURCE.split("/")
    meta, _ = m.gh_api(f"repos/{SOURCE}", TOK)
    meta = (meta or [{}])[0]
    about = " ".join([meta.get("description") or "", " ".join(meta.get("topics") or []), name.replace("-", " ")])
    mask(meta.get("homepage") or "")
    ANON, title, slug = extra.install(m, owner, name, meta.get("homepage") or "", ALIASES, about, GIVEN_NAME)
    TARGET = TARGET or slug
    mask(title, slug, title.replace(" ", ""))
    if MODE == "all":
        anonymise()
        record_name(title)
    import_issues()


if __name__ == "__main__":
    main()
