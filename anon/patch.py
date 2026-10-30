"""In-place patch of an already-anonymised private repo (patch.yml). It is NOT a second anonymisation: authors,
dates and the shape of the history stay as they are; only leftover strings found by an audit are replaced, with
the same replacement everywhere (files, paths, commit and tag messages, branch and tag names, issues).

The rules hold real names, so they never live in this public repo: they are fetched at run time from the private
names repo (NAMES_REPO, path patch-rules/<target>.json, key patch-rules/patch.key) and every string in them is
masked in the log at once. The log shows counts only; saved state is encrypted by the workflow (JOB_KEY).

Steps (STEP):
  rewrite  clone, apply the rules, check the shape (same commits with the same parents, same refs), audit the
           result (leftover hits in the latest files, messages, refs and the issues as they would be after the
           edits); writes state/rewrite.json and state/commit-map. Never pushes.
  push     the same rewrite (must give the same commit map as the rewrite run it continues from), force-push of
           branches and tags (renamed refs: old names deleted), then every ref must match ls-remote. Then issues.
  issues   paced issue edits (titles, bodies, comments with a hit, and commit hashes the new history changed);
           progress in state/issues.json; hands over to a new run before the 6 h limit.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mirror as m  # noqa: E402  (FIRST/LAST name lists)
import extra  # noqa: E402

T0 = time.time()
BUDGET = 5 * 3600 + 1200  # hand over before the 6 h job limit
OWNER = os.environ.get("OWNER", "")
TARGET = os.environ["TARGET"]
STEP = os.environ.get("STEP", "rewrite")
STATE = os.path.abspath("state")
WORK = os.path.abspath("work")
GAP, PER_HOUR = 3.5, 450  # issue edits: GitHub's content-creation limits, with room for other jobs
ONLY_PRS = os.environ.get("ONLY_PRS") == "true"  # edit only the imported pull requests (label "pull request")

SAFE_HOME = {"user", "username", "runner", "root", "admin", "ubuntu", "me", "you", "yourname", "your-name", "name",
             "shared", "public", "default", "home", "vagrant", "docker", "node", "app", "jenkins", "travis", "circleci",
             "builder", "build", "dev", "developer", "test", "tester", "work", "<user>", "<username>", "$user",
             "runneradmin", "administrator", "guest", "linuxbrew", "pi", "codespace", "vscode", "gitpod", "x", "foo",
             "john", "jane", "johndoe", "alice", "bob", "example"}
HOME_RE = re.compile(r"(/Users/|/home/|[A-Za-z]:\\\\?Users\\\\?)([A-Za-z0-9._-]{2,40})(?=[/\\])")
CFF_RE = re.compile(r"(?m)^(\s*-?\s*(?:given-names|family-names):\s*)(\S[^\n]*?)\s*$")
ORCID_RE = re.compile(r"orcid\.org/\d{4}-\d{4}-\d{4}-\d{3}[\dX]")
SHA40 = re.compile(r"\b[0-9a-f]{40}\b")
SHORT = re.compile(r"\b[0-9a-f]{7,12}\b")
EMAIL = re.compile(r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63})*\.[A-Za-z]{2,24}\b")
OK_MAIL = re.compile(r"^(redactedemail@gmail\.com|[^@]+@(example\.(com|org|net)|users\.noreply\.github\.com|"
                     r"noreply\.github\.com|localhost)|(noreply|no-reply|support|info|security|git|example|test|"
                     r"user|admin|you|your\.?name|name|email|foo|bar|john\.?doe|jane\.?doe)@.*)$", re.I)
PHONE = re.compile(r"(?i)(?:(?:phone|tel|telephone|mobile|mob|cell|whatsapp|📞|☎)\s*(?:\([^)]{0,20}\))?\s*[:.]?\s*)"
                   r"(\+?\d[\d\s().\-]{7,18}\d)|(?<![\w+])(\+\d{1,3}[\s.\-]?\(?\d{1,4}\)?(?:[\s.\-]?\d{2,4}){2,5})(?![\w.\-])")
IBAN = re.compile(r"\b([A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,4})?)\b")
HANDLE = [(re.compile(r"(?i)(linkedin\.com/in/)[A-Za-z0-9_%-]+"), r"\1example"),
          (re.compile(r"(?i)\b(telegram|tg|skype|discord|wechat|signal)(\s*[:(]\s*@?)([A-Za-z0-9_.]{3,40})"), r"\1\2example"),
          (re.compile(r"(?i)\b(t\.me/)[A-Za-z0-9_]{3,40}"), r"\1example")]


def log(msg):
    print(msg, flush=True)


def out(key, value):
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"{key}={value}\n")


def mask(*values):
    for v in values:
        for part in str(v).splitlines():
            if len(part.strip()) >= 3:
                print(f"::add-mask::{part.strip()}", flush=True)


def gh_raw(path):
    p = subprocess.run(["gh", "api", f"repos/{os.environ['NAMES_REPO']}/contents/{path}",
                        "-H", "Accept: application/vnd.github.raw"], capture_output=True)
    if p.returncode != 0:
        sys.exit(f"could not read the rules ({path.rsplit('/', 1)[-1]})")
    return p.stdout


class Rules:
    """The rules of one target; every string in them is masked before anything else is printed."""

    def __init__(self, cfg, key):
        for k in ("pre", "post", "issues_only", "issue_literals"):
            for a, b in cfg.get(k, []):
                mask(a)
        mask(*cfg.get("people", []), *cfg.get("audit", []), *cfg.get("anchors", []))
        self.key = key
        people = {p for p in cfg.get("people", []) if len(p) >= 3}
        self.map = {}
        for p in sorted(people, key=len, reverse=True):
            self.map.setdefault(re.sub(r"\s+", " ", p).lower(), self.pseudo(p))
            w = p.split()
            if len(w) >= 2 and p.isascii():  # "Last, First" (citations) and the joined handle (@firstlast)
                f, l_ = self.pick(p)
                self.map.setdefault(f"{w[-1]}, {' '.join(w[:-1])}".lower(), f"{l_}, {f}")
                joined = "".join(w).lower()
                if len(joined) >= 6:
                    self.map.setdefault(joined, f"{f.lower()}-{l_.lower()}")
                    self.map.setdefault("-".join(w).lower(), f"{f.lower()}-{l_.lower()}")  # first-last
            parts = re.split(r"[-_]+", p)
            if len(w) == 1 and len(parts) >= 2 and all(len(x) >= 3 and x.isalpha() for x in parts):
                f, l_ = self.pick(p)  # a login like first-last also written as "First Last"
                self.map.setdefault(" ".join(parts).lower(), f"{f} {l_}")
        mask(*self.map)
        alts = sorted(self.map, key=len, reverse=True)
        self.steps = [(re.compile(a), b) for a, b in cfg.get("pre", [])]
        self.steps.append((ORCID_RE, "orcid.org/0000-0000-0000-0000"))
        if alts:
            rx = re.compile(r"(?<![A-Za-z0-9])(?:" + "|".join(r"\s+".join(map(re.escape, a.split())) for a in alts)
                            + r")(?![A-Za-z0-9])", re.I)
            self.steps.append((rx, lambda mt: self.map[re.sub(r"\s+", " ", mt.group()).lower()]))
        self.steps += [(re.compile(a), b) for a, b in cfg.get("post", [])]
        self.issue_steps = [(re.compile(a), b) for a, b in cfg.get("issues_only", [])]
        imag = {w.lower() for w in m.FIRST + m.LAST}
        self.literals = sorted([(a, b) for a, b in cfg.get("issue_literals", [])
                                if not (re.findall(r"[A-Za-z]+", a) and
                                        all(w.lower() in imag for w in re.findall(r"[A-Za-z]+", a)))],
                               key=lambda x: -len(x[0]))
        self.anchors = sorted({a.lower() for a in cfg.get("anchors", [])} | {p.split()[0].lower() for p in people} |
                              {"orcid.org", "/users/", "/home/", "\\users\\", "given-names", "family-names"})
        aud = [a for a in cfg.get("audit", []) if len(a) >= 3]
        self.audit_re = re.compile(r"(?<![A-Za-z0-9])(?:" + "|".join(
            r"[\s_-]+".join(map(re.escape, re.split(r"[\s_-]+", a))) for a in sorted(aud, key=len, reverse=True))
            + r")(?![A-Za-z0-9])", re.I) if aud else None
        self.imag = imag

    def pick(self, ident):
        h = hmac.new(self.key, re.sub(r"[^a-z0-9]", "", ident.lower()).encode() or ident.encode(), hashlib.sha256).digest()
        return m.FIRST[int.from_bytes(h[:4], "big") % len(m.FIRST)], m.LAST[int.from_bytes(h[4:8], "big") % len(m.LAST)]

    def pseudo(self, ident):
        f, l_ = self.pick(ident)
        return f"{f} {l_}" if (" " in ident.strip() or not ident.isascii()) else f"{f.lower()}-{l_.lower()}"

    @staticmethod
    def _rep(rep):
        if isinstance(rep, dict):
            base = rep["case"]
            return lambda mt: base.upper() if (mt.group().isupper() and len(mt.group()) > 1) else \
                base.lower() if mt.group().islower() else base
        return rep

    def apply(self, s, issue=False):
        if s.isascii() and not any(a in s.lower() for a in self.anchors):
            return s
        for rx, rep in self.steps + (self.issue_steps if issue else []):
            s = rx.sub(self._rep(rep), s)
        s = HOME_RE.sub(lambda mt: mt.group(1) + (mt.group(2) if mt.group(2).lower() in SAFE_HOME else "user"), s)
        s = CFF_RE.sub(lambda mt: mt.group(1) + (mt.group(2) if mt.group(2).strip("'\"").lower() in self.imag else
                                                 self.pick(mt.group(2))[0 if "given" in mt.group(1) else 1]), s)
        return s

    def hits(self, s):
        if not self.audit_re or not s:
            return 0
        return sum(1 for mt in self.audit_re.finditer(s) if mt.group().lower() not in self.imag)


def iban_ok(s):
    s = s.replace(" ", "")
    if not 15 <= len(s) <= 34:
        return False
    try:
        return int("".join(str(int(c, 36)) for c in s[4:] + s[:4])) % 97 == 1
    except ValueError:
        return False


def fix_issue_text(R, s, cmap, short, st):
    """An issue title/body/comment as it must be after the patch."""
    if not s:
        return s
    n = R.apply(s, issue=True)
    if cmap:
        n = SHA40.sub(lambda mt: cmap.get(mt.group(), mt.group()), n)

        def rs(mt):
            h = mt.group()
            if any(c.isalpha() for c in h) and any(c.isdigit() for c in h):
                hits = [o for o in short.get(h[:7], []) if o.startswith(h)]
                if len(hits) == 1:
                    return cmap[hits[0]][:len(h)]
            return h
        n = SHORT.sub(rs, n)
    n = EMAIL.sub(lambda mt: mt.group() if OK_MAIL.match(mt.group()) else "redactedemail@gmail.com", n)

    def phone(mt):
        num = mt.group(1) or mt.group(2)
        d = re.sub(r"\D", "", num)
        if not 9 <= len(d) <= 15 or re.fullmatch(r"(\d)\1+", d) or re.match(r"^(19|20)\d\d[\s.\-]\d", num):
            return mt.group()
        st["pii"] = st.get("pii", 0) + 1
        return mt.group().replace(num, "+00 000 000 0000")
    n = PHONE.sub(phone, n)
    n = IBAN.sub(lambda mt: "XX00 0000 0000 0000" if iban_ok(mt.group(1)) else mt.group(), n)
    for rx, rep in HANDLE:
        n = rx.sub(rep, n)
    for a, b in R.literals:
        if a in n:
            n = n.replace(a, b)
    return n


def git(repo, *a):
    return subprocess.run(["git", *a], cwd=repo, capture_output=True, check=True).stdout


def refs(repo):
    res = {}
    for line in git(repo, "for-each-ref", "--format=%(objectname) %(refname)").decode().splitlines():
        oid, name = line.split(" ", 1)
        res[name] = oid
    return res


def quiet(fn):
    """Run fn with stdout/stderr (also of child processes) sent nowhere: filter-repo prints ref names."""
    sys.stdout.flush()
    sys.stderr.flush()
    saved = os.dup(1), os.dup(2)
    null = os.open(os.devnull, os.O_WRONLY)
    os.dup2(null, 1)
    os.dup2(null, 2)
    try:
        return fn()
    finally:
        sys.stdout.flush()
        sys.stderr.flush()
        os.dup2(saved[0], 1)
        os.dup2(saved[1], 2)
        os.close(null)


def path_map(repo, R):
    """Old path -> new path for every path the rules change. A new path that another path in the history already
    has (or that two changed paths would share) gets -2, -3 ... on its file name, so no rename collides."""
    out = subprocess.run(["git", "-C", repo, "log", "--all", "--no-renames", "--diff-merges=first-parent",
                          "--name-only", "--format=", "-z"], check=True, capture_output=True).stdout
    every = sorted({p for p in out.split(b"\0") if p})
    taken, res = set(every), {}
    for fn in every:
        s = fn.decode("utf-8", "surrogateescape")
        n = R.apply(s)
        if n == s:
            continue
        cand, k = n, 1
        while cand.encode("utf-8", "surrogateescape") in taken:
            k += 1
            d, _, b = n.rpartition("/")
            stem, dot, ext = b.partition(".") if not b.startswith(".") else (b, "", "")
            cand = (d + "/" if d else "") + f"{stem}-{k}" + (dot + ext if dot else "")
        e = cand.encode("utf-8", "surrogateescape")
        taken.add(e)
        res[fn] = e
    return res


def rewrite(R):
    import git_filter_repo as fr
    repo = os.path.join(WORK, "repo.git")
    m.rmtree(repo) if os.path.exists(repo) else None
    os.makedirs(WORK, exist_ok=True)
    subprocess.run(["git", "clone", "-q", "--mirror", f"https://github.com/{OWNER}/{TARGET}.git", repo], check=True,
                   capture_output=True)
    extra.keep_published_refs(repo)
    before = extra.shape(repo)
    old_refs = refs(repo)
    head = git(repo, "symbolic-ref", "HEAD").decode().strip()
    st = {"blobs_changed": 0, "messages_changed": 0, "tags_changed": 0, "refs_renamed": 0, "paths_renamed": 0}

    def blob_cb(blob, _meta):
        d = blob.data
        if b"\0" in d[:8000] or len(d) > 50 * 2**20:
            return
        s = d.decode("utf-8", "surrogateescape")
        n = R.apply(s)
        if n != s:
            blob.data = n.encode("utf-8", "surrogateescape")
            st["blobs_changed"] += 1

    paths = path_map(repo, R)

    def filename_cb(fn):
        n = paths.get(fn)
        if n is not None:
            st["paths_renamed"] += 1
            return n
        return fn

    def refname_cb(ref):
        s = ref.decode("utf-8", "surrogateescape")
        for pre in ("refs/heads/", "refs/tags/"):
            if s.startswith(pre):
                n = extra.safe_ref(pre + R.apply(s[len(pre):]))
                if n != s:
                    st["refs_renamed"] += 1
                    return n.encode("utf-8", "surrogateescape")
        return ref

    def msg(b, k):
        s = b.decode("utf-8", "surrogateescape")
        n = R.apply(s)
        st[k] += n != s
        return n.encode("utf-8", "surrogateescape")

    def commit_cb(c, _meta):
        c.message = msg(c.message, "messages_changed")

    def tag_cb(t, _meta):
        t.message = msg(t.message, "tags_changed")

    args = fr.FilteringOptions.parse_args(["--force", "--quiet", "--replace-refs", "delete-no-add",
                                           "--prune-empty", "never", "--prune-degenerate", "never"])
    cwd = os.getcwd()
    os.chdir(repo)
    try:
        quiet(lambda: fr.RepoFilter(args, blob_callback=blob_cb, filename_callback=filename_cb,
                                    refname_callback=refname_cb, commit_callback=commit_cb, tag_callback=tag_cb).run())
    finally:
        os.chdir(cwd)
    cmap = {}
    with open(os.path.join(repo, "filter-repo", "commit-map"), encoding="ascii") as f:
        next(f)
        for line in f:
            o, n = line.split()
            cmap[o] = n
    m.rmtree(os.path.join(repo, "filter-repo"))
    problems = extra.shape_problems(before, repo, cmap)
    after = extra.shape(repo)
    rep = {"commits_before": len(before["parents"]), "commits_after": len(after["parents"]),
           "refs_before": len(old_refs), "refs_after": len(refs(repo)),
           "default_branch_same": git(repo, "symbolic-ref", "HEAD").decode().strip() == head,
           "changed_commits": sum(1 for o, n in cmap.items() if o != n), "shape_ok": not problems,
           "shape_problems": len(problems), **st}
    return repo, cmap, rep


def audit_history(R, repo):
    """Leftover hits of the audit's identifiers in the latest files, all commit messages, refs (counts only)."""
    a = {"files": 0, "messages": 0, "refs": 0}
    ls = git(repo, "ls-tree", "-r", "-z", "HEAD").decode("utf-8", "surrogateescape").split("\0")
    p = subprocess.Popen(["git", "cat-file", "--batch"], cwd=repo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    for e in ls:
        if not e:
            continue
        meta, path = e.split("\t", 1)
        if meta.split()[1] != "blob":
            continue
        p.stdin.write(meta.split()[2].encode() + b"\n")
        p.stdin.flush()
        size = int(p.stdout.readline().split()[2])
        data = p.stdout.read(size)
        p.stdout.read(1)
        a["files"] += R.hits(path)
        if b"\0" not in data[:8000] and size < 8 * 2**20:
            a["files"] += R.hits(data.decode("utf-8", "surrogateescape"))
    p.stdin.close()
    p.wait()
    for msg in git(repo, "log", "--all", "--format=%B%x00").decode("utf-8", "surrogateescape").split("\0"):
        a["messages"] += R.hits(msg)
    for r in refs(repo):
        a["refs"] += R.hits(r)
    return a


GQL_ISSUES = """query($o:String!,$n:String!,$c:String){repository(owner:$o,name:$n){issues(first:50,after:$c,
orderBy:{field:CREATED_AT,direction:ASC}){pageInfo{hasNextPage endCursor} nodes{id number title body
labels(first:20){nodes{name}} comments(first:100){totalCount pageInfo{endCursor} nodes{id body}}}}}}"""
GQL_MORE = """query($o:String!,$n:String!,$i:Int!,$c:String){repository(owner:$o,name:$n){issue(number:$i){
comments(first:100,after:$c){pageInfo{hasNextPage endCursor} nodes{id body}}}}}"""


def gql(query, **v):
    args = ["gh", "api", "graphql", "-f", "query=" + query]
    for k, x in v.items():
        if x is None:
            continue
        args += (["-F", f"{k}={x}"] if isinstance(x, int) else ["-f", f"{k}={x}"])
    wait = 300
    while True:
        time.sleep(1.0)  # one call at a time, no bursts
        p = subprocess.run(args, capture_output=True, text=True, encoding="utf-8")
        if p.returncode == 0 and '"errors"' not in p.stdout:
            return json.loads(p.stdout)["data"]
        low = (p.stdout + p.stderr).lower()
        if any(x in low for x in ("403", "429", "rate limit", "secondary", "abuse", "too quickly")):
            log(f"  rate limited: waiting {wait // 60} min")
            time.sleep(wait)
            wait = min(wait * 2, 3600)
            continue
        raise RuntimeError("GraphQL call failed")


def issues_iter(after=None):
    """(issue, cursor after this page) for every issue, oldest first, with all comments."""
    c = after
    while True:
        d = gql(GQL_ISSUES, o=OWNER, n=TARGET, c=c)["repository"]["issues"]
        for x in d["nodes"]:
            coms = list(x["comments"]["nodes"])
            cc = x["comments"]["pageInfo"]["endCursor"]
            while len(coms) < x["comments"]["totalCount"]:
                e = gql(GQL_MORE, o=OWNER, n=TARGET, i=x["number"], c=cc)["repository"]["issue"]["comments"]
                coms += e["nodes"]
                cc = e["pageInfo"]["endCursor"]
                if not e["pageInfo"]["hasNextPage"]:
                    break
            x["comments"] = coms
            yield x, d["pageInfo"]["endCursor"]
        if not d["pageInfo"]["hasNextPage"]:
            return
        c = d["pageInfo"]["endCursor"]


def shorts(cmap):
    s = {}
    for o in cmap:
        s.setdefault(o[:7], []).append(o)
    return s


def audit_issues(R, cmap):
    a = {"issues": 0, "issues_to_edit": 0, "fields_to_edit": 0, "hits_before": 0, "hits_after": 0}
    ch = {o: n for o, n in cmap.items() if o != n}
    sh = shorts(ch)
    st = {}
    for x, _ in issues_iter():
        a["issues"] += 1
        edit = 0
        for s in [x["title"], x["body"]] + [c["body"] for c in x["comments"]]:
            new = fix_issue_text(R, s or "", ch, sh, st)
            a["hits_before"] += R.hits(s or "")
            a["hits_after"] += R.hits(new)
            edit += new != (s or "")
        a["fields_to_edit"] += edit
        a["issues_to_edit"] += edit > 0
    a["personal_data_fixed"] = st.get("pii", 0)
    return a


def load():
    cfg = json.loads(gh_raw(f"patch-rules/{TARGET}.json"))
    key = bytes.fromhex(gh_raw("patch-rules/patch.key").decode().strip())
    return Rules(cfg, key)


def step_rewrite(R, push=False):
    repo, cmap, rep = rewrite(R)
    log("rewrite: " + json.dumps(rep))
    os.makedirs(STATE, exist_ok=True)
    if not push:
        rep["after_audit_history"] = audit_history(R, repo)
        log("after-audit, history (leftover hits): " + json.dumps(rep["after_audit_history"]))
        rep["after_audit_issues"] = audit_issues(R, cmap)
        log("after-audit, issues: " + json.dumps(rep["after_audit_issues"]))
        rep["clean"] = rep["shape_ok"] and not sum(rep["after_audit_history"].values()) and \
            not rep["after_audit_issues"]["hits_after"]
        with open(os.path.join(STATE, "commit-map"), "w") as f:
            f.write("".join(f"{o} {n}\n" for o, n in cmap.items()))
        with open(os.path.join(STATE, "rewrite.json"), "w") as f:
            json.dump(rep, f)
        log(f"RESULT {TARGET}: commits {rep['commits_before']} = {rep['commits_after']}, refs {rep['refs_after']}, "
            f"shape {'same' if rep['shape_ok'] else 'DIFFERENT'}, audit {'clean' if rep['clean'] else 'NOT clean'}")
        if not rep["shape_ok"]:
            sys.exit(1)
    return repo, cmap, rep


def step_push(R):
    old = os.path.join(STATE, "commit-map")
    if not os.path.exists(old):
        sys.exit("no rewrite state: start push with from_run = a verified rewrite run")
    with open(old) as f:
        saved = dict(line.split() for line in f if line.strip())
    repo, cmap, rep = step_rewrite(R, push=True)
    if cmap != saved or not rep["shape_ok"] or not rep["default_branch_same"]:
        sys.exit("the rewrite differs from the verified one (or its shape is wrong): not pushed")
    url = f"https://github.com/{OWNER}/{TARGET}.git"

    def remote():
        r = {}
        for line in git(repo, "ls-remote", url).decode().splitlines():
            oid, name = line.split("\t")
            if name.startswith(("refs/heads/", "refs/tags/")) and not name.endswith("^{}"):
                r[name] = oid
        return r
    local, rem = refs(repo), remote()
    head = git(repo, "symbolic-ref", "HEAD").decode().strip()
    upd = sorted(r for r in local if rem.get(r) != local[r])
    if head in upd:
        upd.remove(head)
        upd.insert(0, head)
    dele = [r for r in rem if r not in local]
    for i in range(0, len(upd), 300):
        quiet(lambda: subprocess.run(["git", "push", "-q", url] + [f"+{r}:{r}" for r in upd[i:i + 300]], cwd=repo,
                                     check=True))
        time.sleep(3.5)
    for i in range(0, len(dele), 300):
        quiet(lambda: subprocess.run(["git", "push", "-q", url] + [f":{r}" for r in dele[i:i + 300]], cwd=repo,
                                     check=True))
        time.sleep(3.5)
    rem = remote()
    ok = rem == local
    log(f"push: {len(upd)} refs updated, {len(dele)} old names deleted; ls-remote {len(rem)} refs, "
        f"local {len(local)}, all match: {ok}")
    if not ok:
        sys.exit("refs do not match after the push")
    with open(os.path.join(STATE, "pushed"), "w") as f:
        f.write("ok")
    with open(os.path.join(STATE, "commit-map"), "w") as f:
        f.write("".join(f"{o} {n}\n" for o, n in cmap.items()))
    out("more", "true")
    out("next", "issues")


def step_issues(R):
    if not os.path.exists(os.path.join(STATE, "pushed")):
        sys.exit("history not pushed and verified: no issue edits")
    with open(os.path.join(STATE, "commit-map")) as f:
        cmap = {o: n for o, n in (line.split() for line in f if line.strip()) if o != n}
    sh = shorts(cmap)
    pp = os.path.join(STATE, "issues.json")
    prog = json.load(open(pp)) if os.path.exists(pp) else {"cursor": None, "done": [], "edited": 0, "issues": 0}
    done = set(prog["done"])
    writes = []

    def pace():
        now = time.time()
        while writes and now - writes[0] > 3600:
            writes.pop(0)
        if len(writes) >= PER_HOUR:
            time.sleep(3600 - (now - writes[0]) + 5)
        if writes and time.time() - writes[-1] < GAP:
            time.sleep(GAP - (time.time() - writes[-1]))
        writes.append(time.time())
    st = {}
    for x, cursor in issues_iter(prog["cursor"]):
        if time.time() - T0 > BUDGET:
            json.dump(prog, open(pp, "w"))
            log(f"issues: {prog['issues']} checked, {prog['edited']} fields edited so far; continuing in a new run")
            out("more", "true")
            out("next", "issues")
            return
        if x["number"] in done:
            continue
        if ONLY_PRS and "pull request" not in [lb["name"] for lb in x["labels"]["nodes"]]:
            continue
        upd = {}
        for k in ("title", "body"):
            new = fix_issue_text(R, x[k] or "", cmap, sh, st)
            if new != (x[k] or ""):
                upd[k] = new
        for c in x["comments"]:
            new = fix_issue_text(R, c["body"] or "", cmap, sh, st)
            if new != (c["body"] or ""):
                pace()
                gql("mutation($id:ID!,$b:String!){updateIssueComment(input:{id:$id,body:$b}){issueComment{id}}}",
                    id=c["id"], b=new)
                prog["edited"] += 1
        if upd:
            pace()
            decl = "".join(f",${k}:String!" for k in upd)
            fields = ",".join(f"{k}:${k}" for k in upd)
            gql(f"mutation($id:ID!{decl}){{updateIssue(input:{{id:$id,{fields}}}){{issue{{id}}}}}}", id=x["id"], **upd)
            prog["edited"] += len(upd)
        prog["issues"] += 1
        prog["done"].append(x["number"])
        if prog["issues"] % 200 == 0:
            prog["cursor"] = cursor
            json.dump(prog, open(pp, "w"))
            log(f"  issues: {prog['issues']} checked, {prog['edited']} fields edited")
    json.dump(prog, open(pp, "w"))
    log(f"issues: done, {prog['issues']} checked, {prog['edited']} fields edited")
    out("more", "false")


def main():
    out("more", "false")
    try:
        R = load()
        {"rewrite": step_rewrite, "push": step_push, "issues": step_issues}[STEP](R)
    except SystemExit:
        raise
    except Exception as e:  # no message text: it could quote a rule or a file
        sys.exit(f"failed: {type(e).__name__}")


if __name__ == "__main__":
    main()
