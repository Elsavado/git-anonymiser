"""Mirror every repo of the given accounts, scrub secrets, anonymise, and pack into one zip.

Per repo: git clone --mirror -> fetch PR/issue/review history -> gitleaks scan ->
git-filter-repo rewrite (authors -> Redacted Name, secrets redacted, LICENSE files
removed, README identities redacted, all commit hashes shift) -> remap hashes in the
API data -> gitleaks re-scan -> append to the zip -> delete the working copy.

Usage: python -I mirror.py [--only owner/name ...] [--zip PATH]
"""
import base64
import datetime
import hashlib
import hmac
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import traceback
import urllib.parse
import zipfile
from concurrent.futures import ThreadPoolExecutor

import git_filter_repo as fr

# Bare mirrors are never checked out, so let git accept Windows-reserved paths (CON.png, aux.c ...) in history;
# otherwise fast-import dies with "invalid path" and the rewrite fails with a broken pipe.
os.environ.update({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.protectNTFS", "GIT_CONFIG_VALUE_0": "false"})

ACCOUNTS = [a for a in os.environ.get("ANON_ACCOUNTS", "").split(",") if a]  # extra identities to replace
WORK = os.path.abspath("work")
OUT_ZIP = os.path.abspath("mirror.zip")
RN = "Redacted Name"
RE_MAIL = "redacted@redacted.invalid"
SECRET_MARK = b"***REDACTED***"
MIN_SECRET = 8
SALT = os.urandom(16)  # for commit hashes the rewrite cannot map; never stored
STOP = {"root", "admin", "user", "test", "github", "git", "none", "unknown", "localhost",
        "ubuntu", "travis", "runner", "build", "main", "master", "dev", "the", "and",
        "for", "web", "app", "api", "bot", "ci", "server", "system", "info", "contact",
        "support", "noreply", "users", "example", "docs", "readme", "license", "github actions"}
LICENSE_RE = re.compile(rb"^(licen[cs]e|copying|unlicense|copyright)([._\-].*)?$", re.I)
TOKEN_RE = re.compile(r"\w[\w.+\-@]*\w|\w")
SHA40 = re.compile(r"\b[0-9a-f]{40}\b")
SHORT = re.compile(r"\b[0-9a-f]{7,12}\b")
MERGE_FROM = re.compile(r"Merge pull request #\d+ from ([A-Za-z0-9][A-Za-z0-9-]{0,38})/")
MERGE_BRANCH = re.compile(r"Merge (?:remote-tracking )?branch '[^']*' of (?:https?://|git@)github\.com[:/]([A-Za-z0-9][A-Za-z0-9-]{0,38})/")
TRAILER = re.compile(r"^[\w-]*-by:\s*(.+?)\s*<([^>\s]+)>", re.M | re.I)
MENTION = re.compile(r"(?<![\w.@/])@([A-Za-z0-9][A-Za-z0-9-]{1,38})\b(?![.@\w-])")

LOG = None
PARA_CACHE, PARA_CACHE_PATH, PARA_CWD = {}, None, None

# Timestamps: round UP to the next 10 minutes and drop the time zone (it reveals location).
# Rounding up is monotone, so the order of any two events never flips.
ROUND = 600
ISO_TS = re.compile(r"\b(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})\b")


def round_epoch(t):
    return -(-t // ROUND) * ROUND


def git_date(raw):
    """b'1700000000 +0300' -> b'1700000400 +0000'"""
    secs = int(raw.split()[0])
    return b"%d +0000" % round_epoch(secs)


def iso_date(m):
    tz = m.group(4)
    tz = "+00:00" if tz == "Z" else (tz if ":" in tz else tz[:3] + ":" + tz[3:])
    dt = datetime.datetime.fromisoformat(f"{m.group(1)}T{m.group(2)}{m.group(3) or ''}{tz}")
    t = round_epoch(int(dt.timestamp()) + (1 if dt.microsecond else 0))
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

FIRST = """Aldric Amara Anouk Arlo Aurelie Bastien Belen Bram Calla Caspian Celeste Corin Dalia Damek Delphine Desmond
Edda Elian Elodie Emeric Esme Evander Fenna Florin Freya Gideon Greta Halden Hana Idris Ilse Imogen Ione Isak Jarek
Juno Kael Kaia Kasimir Lark Leander Liora Lorcan Lysander Maelle Magnus Mara Marek Mirela Nadia Nils Noor Oriel
Orla Osric Petra Quillon Rafe Rhea Rosalind Rowan Saskia Silas Soren Talia Tamsin Theron Thea Ulric Una Vale
Vesna Wren Xavi Yara Yorick Zara Zephyr Ansel Brielle Cyrus Dagny Eira Fintan Gwen Hollis Inara Joaquin Kestrel
Linnea Matthis Nerys Oskar Philippa Quinn Ronan Selma Tobias Ursa Viggo Wilhelmina Ximena Yusuf Zoltan""".split()
LAST = """Abernath Ashgrove Bellwether Brackenridge Calloway Cindervale Dunmore Elderwood Fairhollow Fenwick Galloway
Greaves Halloran Hawthorne Ironside Juniper Kestrelton Larkspur Lindqvist Marchetti Mossgrove Northcott Oakhaven
Penhallow Quarrington Ravensworth Rookwood Saltmarsh Silverlake Thornbury Underhill Valcourt Westbrook Whitlock
Yarrowby Zellweger Amberly Blackwood Coldbrook Driftwell Emberton Foxglove Glenmoor Hollowell Ivesdale Jessop
Kingsley Lowenthal Merriweather Nettlefield Orchard Pemberton Quillfeather Redfern Stonebridge Tamberlane Umberfield
Vantreight Wexford Yelverton Ashdown Briarcliff Copperfield Dovecote Eastwick Farrowmere Gristmill Heatherton
Inglewood Kettering Loxley Mirrowdale Netherby Oakenshaw Pinkerton Rushworth Sablewood Thistlewood Vexley Wintermere
Alderney Bramblecote Cresswell Dunleavy Evershed Fallowfield Greywater Harrowgate Kilbride Lanthorne Mortlake""".split()


class Pseudo:
    """Consistent imaginary person per real identity (HMAC with a key that is deleted after the run)."""

    def __init__(self, key_path):
        if not os.path.exists(key_path):
            with open(key_path, "wb") as f:
                f.write(os.urandom(32))
        with open(key_path, "rb") as f:
            self.key = f.read()
        self.made = set()

    def _pick(self, ident):
        h = hmac.new(self.key, ident.strip().lower().encode("utf-8", "surrogateescape"), hashlib.sha256).digest()
        return FIRST[int.from_bytes(h[:4], "big") % len(FIRST)], LAST[int.from_bytes(h[4:8], "big") % len(LAST)]

    def name(self, ident):
        n = "%s %s" % self._pick(ident)
        self.made.add(n)
        return n

    def email(self, ident):
        return "%s.%s@example.com" % tuple(x.lower() for x in self._pick(ident))

    def login(self, ident):
        return "%s-%s" % tuple(x.lower() for x in self._pick(ident))


PSEUDO = None


def log(msg):
    line = time.strftime("%Y-%m-%d %H:%M:%S ") + msg
    print(line, flush=True)
    LOG.write(line + "\n")
    LOG.flush()


def run(cmd, cwd=None, env=None, ok=(0,)):
    p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True)
    if p.returncode not in ok:
        raise RuntimeError(f"{cmd[:3]} exit {p.returncode}: {p.stderr.decode(errors='replace')[-800:]}")
    return p.stdout


def rmtree(path):
    """Delete a tree; retry while a just-exited git still holds a handle, then log instead of crashing."""
    def onerr(func, p, _):
        os.chmod(p, stat.S_IWRITE)
        func(p)
    for attempt in range(6):
        if not os.path.exists(path):
            return
        try:
            shutil.rmtree(path, onerror=onerr)
            return
        except OSError as e:
            err = e
            time.sleep(5)
    log(f"  could not delete {path}: {err}")


def token(acct):
    return run(["gh", "auth", "token", "-u", acct]).decode().strip()


def gh_env(tok):
    env = dict(os.environ)
    env["GH_TOKEN"] = tok
    return env


def wait_for_quota(tok):
    """If the account's core API quota is used up (shared with other tools on the same account),
    sleep until it resets. Returns True if it waited."""
    q = subprocess.run(["gh", "api", "rate_limit", "--jq", ".resources.core | [.remaining, .reset] | @tsv"],
                       env=gh_env(tok), capture_output=True, text=True)
    try:
        remaining, reset = (int(x) for x in q.stdout.split())
    except ValueError:
        return False
    if remaining > 20:
        return False
    secs = max(reset - time.time(), 0) + 30
    log(f"  API quota used up ({remaining} left); waiting {round(secs / 60)} min for the reset")
    time.sleep(secs)
    return True


def gh_api(path, tok):
    for _ in range(6):
        p = subprocess.run(["gh", "api", "--paginate", "--slurp", path], env=gh_env(tok), capture_output=True)
        if p.returncode == 0 or not wait_for_quota(tok):
            break
    if p.returncode != 0:
        return None, (p.stderr.decode(errors="replace").strip() or p.stdout.decode(errors="replace"))[-300:]
    pages = json.loads(p.stdout or b"[]")
    out = []
    for page in pages:
        out.extend(page if isinstance(page, list) else [page])
    return out, None


def list_repos(acct, tok):
    data, err = gh_api("user/repos?affiliation=owner&per_page=100", tok)
    if err:
        raise RuntimeError(err)
    return [{"owner": r["owner"]["login"], "name": r["name"], "fork": r["fork"], "archived": r["archived"],
             "private": r["private"], "size_kb": r["size"], "has_wiki": r["has_wiki"],
             "has_issues": r["has_issues"]} for r in data]


def clone(owner, name, tok, dest, wiki=False):
    url = f"https://github.com/{owner}/{name}{'.wiki' if wiki else ''}.git"
    auth = base64.b64encode(f"x-access-token:{tok}".encode()).decode()
    tries = 1 if wiki else 4  # a missing wiki fails at once; dropped connections (early EOF) are worth retrying
    for attempt in range(1, tries + 1):
        try:
            run(["git", "-c", "credential.helper=", "-c", f"http.https://github.com/.extraheader=AUTHORIZATION: basic {auth}",
                 "clone", "--mirror", "--quiet", url, dest],
                env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
            break
        except RuntimeError as e:
            if attempt == tries or "not found" in str(e).lower():
                raise
            log(f"  clone attempt {attempt} failed ({str(e)[-120:].strip()}); retrying in {attempt} min")
            rmtree(dest)
            time.sleep(60 * attempt)
    for k, v in (("pack.threads", "1"), ("pack.windowMemory", "256m"), ("pack.deltaCacheSize", "64m"),
                 ("core.packedGitLimit", "256m")):  # low-RAM laptop: keep repacks small
        run(["git", "config", k, v], cwd=dest)


def fetch_api(owner, name, tok, has_issues):
    base = f"repos/{owner}/{name}"
    api = {"errors": {}}
    for key, path in [("issues", f"{base}/issues?state=all&per_page=100"),
                      ("issue_comments", f"{base}/issues/comments?per_page=100"),
                      ("pulls", f"{base}/pulls?state=all&per_page=100"),
                      ("review_comments", f"{base}/pulls/comments?per_page=100")]:
        if key.startswith("issue") and not has_issues:
            api["errors"][key] = "issues disabled on this repo"
            api[key] = []
            continue
        data, err = gh_api(path, tok)
        api[key] = data or []
        if err:
            api["errors"][key] = err
    meta, _ = gh_api(base, tok)
    owners = set()
    for m in meta or []:
        for k in ("parent", "source"):
            if m.get(k):
                owners.add(m[k]["owner"]["login"])
    api["_upstream_owners"] = sorted(owners)
    api["reviews"] = {}
    for pr in api["pulls"]:
        data, err = gh_api(f"{base}/pulls/{pr['number']}/reviews?per_page=100", tok)
        api["reviews"][str(pr["number"])] = data or []
        if err:
            api["errors"][f"reviews/{pr['number']}"] = err
    return api


# 2026-10-18 user: skip files over 5 MB in scans (generated bundles/binaries made one scan take 3.5 h).
# Secrets found elsewhere are still replaced inside those files by the rewrite.
MAX_SCAN_MB = 5


def large_blobs(repo):
    """Paths of history blobs over MAX_SCAN_MB (not scanned by gitleaks)."""
    objs = run(["git", "rev-list", "--all", "--objects"], cwd=repo)
    out = subprocess.run(["git", "cat-file", "--batch-check=%(objecttype) %(objectsize) %(rest)"], cwd=repo,
                         input=objs, capture_output=True).stdout.decode("utf-8", "replace")
    paths = set()
    for line in out.splitlines():
        p = line.split(" ", 2)
        if len(p) == 3 and p[0] == "blob" and int(p[1]) > MAX_SCAN_MB * 1048576:
            paths.add(p[2])
    return sorted(paths)


def scan_excludes(repo):
    """Git pathspecs excluding the large files (their diffs made `git log -p` 20 GB for one repo;
    gitleaks' own size limit does not apply in git mode). Same dir + extension -> one glob."""
    def esc(s):  # gitleaks splits --log-opts on whitespace; glob-match those characters instead
        return re.sub(r"[\s\[\]*?]", "?", s)
    pats = set()
    for p in large_blobs(repo):
        d, _, base = p.rpartition("/")
        ext = base.rsplit(".", 1)[1] if "." in base[1:] else None
        name = f"*.{esc(ext)}" if ext else esc(base)
        pats.add(f"{esc(d)}/{name}" if d else name)
    return sorted(pats)


def gitleaks(target, report, mode="git"):
    cmd = ["gitleaks", mode, "--no-banner", "--exit-code", "0", "--report-format", "json",
           "--report-path", report, "--log-level", "error", "--max-target-megabytes", str(MAX_SCAN_MB)]
    if mode == "git":
        excl = scan_excludes(target)
        opts = "--all" + ("" if not excl else " -- . " + " ".join(f":(exclude,glob){p}" for p in excl))
        if len(opts) > 20000:  # Windows command-line limit: fall back to whole directories
            excl = sorted({p.rpartition("/")[0] + "/**" if "/" in p else p for p in excl})
            opts = "--all -- . " + " ".join(f":(exclude,glob){p}" for p in excl)
        cmd += [f"--log-opts={opts}"]
    run(cmd + [target])
    with open(report, encoding="utf-8") as f:
        return json.load(f) or []


class Anon:
    """Token-based identity replacement (fast on large histories, unlike a giant regex)."""

    def __init__(self, identities):
        self.first, self.repl = {}, {}
        for ident, repl in identities.items():
            toks = tuple(t.lower() for t in TOKEN_RE.findall(ident))
            if toks:
                self.first.setdefault(toks[0], set()).add(toks)
                self.repl.setdefault(toks, repl)
        for k in self.first:
            self.first[k] = sorted(self.first[k], key=len, reverse=True)

    def text(self, s):
        if not self.first:
            return s
        toks = list(TOKEN_RE.finditer(s))
        out, pos, i = [], 0, 0
        while i < len(toks):
            m = toks[i]
            hit, repl = 0, None
            for cand in self.first.get(m.group().lower(), ()):
                k = len(cand)
                if i + k > len(toks):
                    continue
                if all(toks[i + j].group().lower() == cand[j] and
                       (j == 0 or not s[toks[i + j - 1].end():toks[i + j].start()].strip())
                       for j in range(k)):
                    hit, repl = k, self.repl[cand]
                    break
            if hit:
                out.append(s[pos:m.start()])
                out.append(repl)
                pos = toks[i + hit - 1].end()
                i += hit
            else:
                i += 1
        out.append(s[pos:])
        return "".join(out)

    def bytes(self, b):
        return self.text(b.decode("utf-8", "surrogateescape")).encode("utf-8", "surrogateescape")


def keep_ident(x):
    x = x.strip().strip("<>").strip()
    if len(x) < 3 or x.lower() in STOP or x.isdigit():
        return None
    return x


def collect_identities(repo, api):
    """{real identity text: imaginary replacement}. Names -> 'First Last', emails -> first.last@example.com,
    logins and email local parts -> first-last. An email maps to the person whose name it was used with."""
    ids = {}

    def add(ident, repl):
        k = keep_ident(ident)
        if k and k not in ids:
            ids[k] = repl

    for acct in ACCOUNTS:
        add(acct, PSEUDO.login(acct))
    raw = run(["git", "log", "--all", "--format=%an%x00%ae%x00%cn%x00%ce"], cwd=repo)
    raw += run(["git", "for-each-ref", "--format=%(taggername)%00%(taggeremail)", "refs/tags"], cwd=repo)
    for line in raw.decode("utf-8", "replace").splitlines():
        parts = line.split("\x00")
        for name, mail in zip(parts[0::2], parts[1::2]):
            mail = mail.strip().strip("<>")
            add(name, PSEUDO.name(name))
            if mail:
                add(mail, PSEUDO.email(name))
                local = mail.split("@")[0]
                if "noreply" in mail and "+" in local:  # 123+login@users.noreply.github.com
                    local = local.split("+")[-1]
                if "noreply" not in local:
                    add(local, PSEUDO.login(name))

    def walk(o):
        if isinstance(o, dict):
            if isinstance(o.get("login"), str):
                add(o["login"], PSEUDO.login(o["login"]))
                if isinstance(o.get("name"), str):
                    add(o["name"], PSEUDO.name(o["name"]))
                if isinstance(o.get("email"), str):
                    add(o["email"], PSEUDO.email(o.get("name") or o["login"]))
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(api)
    for o in api.get("_upstream_owners", []):
        add(o, PSEUDO.login(o))
    msgs = run(["git", "log", "--all", "--format=%B%x00"], cwd=repo).decode("utf-8", "replace")
    for m in MERGE_FROM.findall(msgs) + MERGE_BRANCH.findall(msgs) + MENTION.findall(msgs):
        add(m, PSEUDO.login(m))
    for name, mail in TRAILER.findall(msgs):
        add(name, PSEUDO.name(name))
        add(mail, PSEUDO.email(name))
    return ids


HEX_ANY = re.compile(r"\b[0-9a-f]{7,40}\b")
KEEP_TOKENS = re.compile(r"#\d+|<H\d+>|\*\*\*REDACTED\*\*\*|[\w.]+@example\.com")


def keep_tokens(text):
    toks = KEEP_TOKENS.findall(text)
    for n in PSEUDO.made:
        toks += [n] * text.count(n)
    for f, l in {tuple(n.lower().split()) for n in PSEUDO.made}:
        toks += [f"{f}-{l}"] * len(re.findall(rf"(?<![\w-]){f}-{l}(?![\w-])", text))
    return sorted(toks)
MERGE_ONLY = re.compile(r"^Merge (pull request #\d+ from \S+|(remote-tracking )?branch '[^']*'( of \S+)?( into \S+)?)\s*$")
PARA_BATCH, PARA_JOBS, PARA_MAX = 60, 2, 1500
PARAPHRASE = False  # 2026-10-16: user turned paraphrasing off for speed; messages keep wording (names/secrets still swapped)
PARA_PROMPT = """Paraphrase each git commit message below so the wording and style change but the technical meaning stays exactly the same.
Rules:
- Keep it a commit message: a short subject line, then the body (if any) after a blank line.
- Copy these tokens exactly, unchanged: placeholders like <H1>, issue/PR references like #123, ***REDACTED***, person names, logins and email addresses.
- Do not add or remove facts, file names, versions or code identifiers.
Return ONLY a JSON array of strings, same length and order as the input array.

Input:
"""


def hex_template(msg):
    """Swap commit hashes for <H1>.. so the paraphrase survives filter-repo's own hash rewriting."""
    found = []

    def rep(m):
        h = m.group()
        if any(c.isalpha() for c in h) and any(c.isdigit() for c in h):
            found.append(h)
            return f"<H{len(found)}>"
        return h
    return HEX_ANY.sub(rep, msg), found


def fill_template(t, found):
    for i, h in enumerate(found, 1):
        t = t.replace(f"<H{i}>", h)
    return t


def ask_claude(batch):
    p = subprocess.run([shutil.which("claude"), "-p", "--model", "sonnet", "--output-format", "json", "--max-turns", "1",
                        "--disallowedTools", "Bash,Edit,Write,Read,Glob,Grep,WebFetch,WebSearch,Agent"],
                       input=(PARA_PROMPT + json.dumps(batch, ensure_ascii=False)).encode("utf-8"),
                       capture_output=True, cwd=PARA_CWD, timeout=900)
    if p.returncode != 0:
        return None
    text = json.loads(p.stdout).get("result", "")
    m = re.search(r"\[.*\]", text, re.S)
    out = json.loads(m.group()) if m else None
    return out if isinstance(out, list) and len(out) == len(batch) else None


def paraphrase_identifying(repo, anon, secrets, scrub_fn):
    """{template of cleaned message: paraphrased template} for messages where something identifying was replaced."""
    raw = run(["git", "log", "--all", "--format=%B%x00"], cwd=repo).decode("utf-8", "surrogateescape").split("\x00")
    todo = {}
    for msg in raw:
        msg = msg.strip("\n")
        if not msg:
            continue
        b = msg.encode("utf-8", "surrogateescape")
        cleaned = anon.bytes(scrub_fn(b)).decode("utf-8", "surrogateescape")
        if cleaned == msg or MERGE_ONLY.match(cleaned) or len(cleaned) > PARA_MAX:
            continue
        t, _ = hex_template(cleaned)
        if t not in PARA_CACHE:
            todo[t] = None
    items = list(todo)
    batches = [items[i:i + PARA_BATCH] for i in range(0, len(items), PARA_BATCH)]
    with ThreadPoolExecutor(PARA_JOBS) as ex:
        for batch, out in zip(batches, ex.map(ask_claude, batches)):
            for src, dst in zip(batch, out or [None] * len(batch)):
                ok = isinstance(dst, str) and dst.strip() and \
                    keep_tokens(src) == keep_tokens(dst)
                PARA_CACHE[src] = dst.strip() if ok else src
            with open(PARA_CACHE_PATH, "a", encoding="utf-8") as f:
                for src in batch:
                    f.write(json.dumps([src, PARA_CACHE[src]], ensure_ascii=False) + "\n")
    return sum(1 for t in todo if PARA_CACHE.get(t) != t), len(todo)


def readme_blobs(repo):
    ids = set()
    for line in run(["git", "rev-list", "--all", "--objects"], cwd=repo).splitlines():
        parts = line.split(b" ", 1)
        if len(parts) == 2 and parts[1].rsplit(b"/", 1)[-1].lower().startswith(b"readme"):
            ids.add(parts[0])
    return ids


WIN_BAD = re.compile(rb'[<>:"|?*\x00-\x1f]')
WIN_RESERVED = re.compile(rb"^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$", re.I)


def win_path(fn):
    """Git for Windows' fast-import refuses paths Windows cannot hold (e.g. a stray vim file '_:wq'),
    whatever core.protectNTFS says; such names get '_' in place of the bad characters."""
    parts = []
    for p in fn.split(b"/"):
        q = WIN_BAD.sub(b"_", p)
        if q.endswith((b".", b" ")) and q.strip(b"."):
            q = q.rstrip(b". ") + b"_"
        if WIN_RESERVED.match(q):
            q = b"_" + q
        parts.append(q)
    return b"/".join(parts)


def rewrite(repo, secrets, anon, readmes):
    stats = {"licenses_removed": set()}

    def scrub(b):
        for s in secrets:
            if s in b:
                b = b.replace(s, SECRET_MARK)
        return b

    def blob_cb(blob, _meta):
        data = scrub(blob.data)
        if blob.original_id in readmes:
            data = anon.bytes(data)
        blob.data = data

    def filename_cb(fn):
        parts = fn.split(b"/")
        if LICENSE_RE.match(parts[-1]) or any(p.lower() == b"licenses" for p in parts[:-1]):
            stats["licenses_removed"].add(fn)
            return None
        return win_path(fn)

    def commit_cb(c, _meta):
        an, cn = c.author_name.decode("utf-8", "replace"), c.committer_name.decode("utf-8", "replace")
        c.author_name, c.author_email = PSEUDO.name(an).encode(), PSEUDO.email(an).encode()
        c.committer_name, c.committer_email = PSEUDO.name(cn).encode(), PSEUDO.email(cn).encode()
        c.author_date, c.committer_date = git_date(c.author_date), git_date(c.committer_date)
        cleaned = anon.bytes(scrub(c.message))
        if PARAPHRASE and cleaned != c.message:
            msg = cleaned.decode("utf-8", "surrogateescape")
            core = msg.strip("\n")
            t, found = hex_template(core)
            para = PARA_CACHE.get(t)
            if para and para != t:
                cleaned = (msg[:len(msg) - len(msg.lstrip("\n"))] + fill_template(para, found) +
                           msg[len(msg.rstrip("\n")):]).encode("utf-8", "surrogateescape")
        c.message = cleaned

    def tag_cb(t, _meta):
        if t.tagger_name is not None:
            tn = t.tagger_name.decode("utf-8", "replace")
            t.tagger_name, t.tagger_email = PSEUDO.name(tn).encode(), PSEUDO.email(tn).encode()
            t.tagger_date = git_date(t.tagger_date)
        t.message = anon.bytes(scrub(t.message))

    args = fr.FilteringOptions.parse_args(["--force", "--quiet", "--replace-refs", "delete-no-add",
                                           "--prune-empty", "never", "--prune-degenerate", "never"])
    cwd = os.getcwd()
    os.chdir(repo)
    try:
        fr.RepoFilter(args, blob_callback=blob_cb, filename_callback=filename_cb,
                      commit_callback=commit_cb, tag_callback=tag_cb).run()
    finally:
        os.chdir(cwd)
    cmap = {}
    path = os.path.join(repo, "filter-repo", "commit-map")
    with open(path, encoding="ascii") as f:
        next(f)
        for line in f:
            old, new = line.split()
            cmap[old] = new
    rmtree(os.path.join(repo, "filter-repo"))
    subprocess.run(["git", "config", "--remove-section", "remote.origin"], cwd=repo, capture_output=True)
    for junk in ("FETCH_HEAD", "ORIG_HEAD", "logs"):
        p = os.path.join(repo, junk)
        rmtree(p) if os.path.isdir(p) else (os.path.exists(p) and os.remove(p))
    run(["git", "reflog", "expire", "--expire=now", "--all"], cwd=repo)
    run(["git", "-c", "pack.threads=1", "-c", "pack.windowMemory=256m", "-c", "pack.deltaCacheSize=64m", "gc", "--prune=now", "--quiet"], cwd=repo)
    return cmap, len(stats["licenses_removed"])


def zip_checkpoint(zf_path, work):
    """Save the zip's central directory (small) so an append killed mid-write can be rolled back."""
    if not os.path.exists(zf_path):
        return
    with zipfile.ZipFile(zf_path) as zf:
        start = zf.start_dir
    with open(zf_path, "rb") as f:
        f.seek(start)
        tail = f.read()
    with open(os.path.join(work, "zip_tail.bin"), "wb") as f:
        f.write(tail)
    with open(os.path.join(work, "zip_tail.json"), "w") as f:
        json.dump({"offset": start}, f)


def zip_recover(zf_path, work):
    """Truncate a half-written append back to the last checkpoint and restore its central directory."""
    with open(os.path.join(work, "zip_tail.json")) as f:
        off = json.load(f)["offset"]
    with open(os.path.join(work, "zip_tail.bin"), "rb") as f:
        tail = f.read()
    with open(zf_path, "r+b") as f:
        f.seek(off)
        f.write(tail)
        f.truncate()


def zip_repo(zf, repo, base):
    for root, dirs, files in os.walk(repo):
        rel_root = os.path.relpath(root, repo).replace(os.sep, "/")
        if not files and not dirs:  # git needs empty refs/heads, refs/tags, objects/info ...
            zf.writestr(f"{base}/{rel_root}/", b"")
        for fn in files:
            full = os.path.join(root, fn)
            zf.write(full, f"{base}/" + os.path.relpath(full, repo).replace(os.sep, "/"))


def verify_clean(repo, cmap):
    """Return a list of problems; empty means the repo is fit for the zip."""
    problems = []
    raw = run(["git", "log", "--all", "--format=%an%x00%ae%x00%cn%x00%ce"], cwd=repo)
    raw += run(["git", "for-each-ref", "--format=%(taggername)%00%(taggeremail)", "refs/tags"], cwd=repo)
    bad = set()
    for line in raw.decode("utf-8", "replace").splitlines():
        parts = line.split("\x00")
        for name, mail in zip(parts[0::2], parts[1::2]):
            if not name and not mail:
                continue  # lightweight tag
            if name not in PSEUDO.made or not mail.strip("<>").endswith("@example.com"):
                bad.add(name)
    if bad:
        problems.append(f"real identities left: {len(bad)}")
    dates = run(["git", "log", "--all", "--date=raw", "--format=%ad %cd"], cwd=repo).decode().split()
    dates += run(["git", "for-each-ref", "--format=%(taggerdate:raw)", "refs/tags"], cwd=repo).decode().split()
    if any((d.isdigit() and int(d) % ROUND) or (d[0] in "+-" and d != "+0000") for d in dates):
        problems.append("unrounded timestamps or time zones left")
    paths = run(["git", "log", "--all", "--name-only", "--format="], cwd=repo).splitlines()
    if any(LICENSE_RE.match(p.rsplit(b"/", 1)[-1]) for p in paths):
        problems.append("LICENSE path left")
    new_ids = set(run(["git", "rev-list", "--all"], cwd=repo).decode().split())
    if new_ids & {o for o, n in cmap.items() if o != n}:
        problems.append("original commit hashes left")
    if run(["git", "config", "--get-regexp", "remote"], cwd=repo, ok=(0, 1)).strip():
        problems.append("remote config left")
    return problems


def decoded_forms(tok):
    """Percent- and base64-decodings of a token (what gitleaks' decoder sees), joined for a substring test."""
    out = [tok, urllib.parse.unquote_to_bytes(tok)]
    for t in (tok, out[1]):
        try:
            out.append(base64.b64decode(t + b"=" * (-len(t) % 4), altchars=b"-_" if b"-" in t or b"_" in t else None))
        except ValueError:
            pass
    return b"\x00".join(out)


def clean_repo(repo, secrets, anon, workdir, tag):
    """Rewrite, then re-scan; leftover findings get another pass (any length). Returns (cmap, licenses, findings_after)."""
    readmes = readme_blobs(repo) if tag != "wiki" else set(
        l.split()[0] for l in run(["git", "rev-list", "--all", "--objects"], cwd=repo).splitlines() if len(l.split()) == 2)
    if tag == "repo" and PARAPHRASE:
        def scrub_fn(b):
            for x in secrets:
                b = b.replace(x, SECRET_MARK)
            return b
        n_para, n_cand = paraphrase_identifying(repo, anon, secrets, scrub_fn)
        log(f"  paraphrased {n_para}/{n_cand} identifying commit messages")
    cmap, lic = rewrite(repo, secrets, anon, readmes)
    for _ in range(2):
        after = gitleaks(repo, os.path.join(workdir, f"leaks_after_{tag}.json"))
        extra = {f["Secret"].encode("utf-8", "surrogateescape") for f in after if f.get("Secret")}
        for f in after:
            if f.get("Commit") and f.get("File") and f.get("StartLine"):
                blob = subprocess.run(["git", "show", f"{f['Commit']}:{f['File']}"], cwd=repo, capture_output=True).stdout
                lines = blob.split(b"\n")
                sec = (f.get("Secret") or "").encode("utf-8", "surrogateescape")
                for ln in lines[max(0, f["StartLine"] - 1):f.get("EndLine", f["StartLine"])]:
                    for tok in re.findall(rb"[A-Za-z0-9+/=_\-.%]{8,}", ln):
                        if sec and sec in decoded_forms(tok):  # only the encoded form of this secret
                            extra.add(tok)
        extra = sorted(extra, key=len, reverse=True)
        if not after or not extra:
            return cmap, lic, after
        m2, _ = rewrite(repo, extra, anon, set())
        cmap = {o: m2.get(n, n) for o, n in cmap.items()}
    return cmap, lic, gitleaks(repo, os.path.join(workdir, f"leaks_after_{tag}.json"))


def shift_sha(old, cmap):
    new = cmap.get(old)
    if new and new != "0" * 40:
        return new
    return hashlib.sha1(SALT + old.encode()).hexdigest()


def anon_api(api, cmap, anon, secrets):
    short = {}
    for old, new in cmap.items():
        short.setdefault(old[:7], []).append((old, new))
    str_secrets = [s.decode("utf-8", "ignore") for s in secrets]

    def fix(s):
        for sec in str_secrets:
            if sec and sec in s:
                s = s.replace(sec, SECRET_MARK.decode())
        s = SHA40.sub(lambda m: shift_sha(m.group(), cmap), s)
        s = ISO_TS.sub(iso_date, s)

        def sh(m):
            h = m.group()
            if any(c.isalpha() for c in h) and any(c.isdigit() for c in h):
                hits = [n for o, n in short.get(h[:7], []) if o.startswith(h)]
                if len(hits) == 1:
                    return hits[0][:len(h)]
            return h
        return anon.text(SHORT.sub(sh, s))

    def walk(o):
        if isinstance(o, dict):
            if "login" in o:
                return {"login": PSEUDO.login(o["login"]), "type": o.get("type")}
            return {k: walk(v) for k, v in o.items()}
        if isinstance(o, list):
            return [walk(v) for v in o]
        if isinstance(o, str):
            return fix(o)
        return o
    return walk(api)


def safe_report(findings, cmap):
    keep = ("RuleID", "Description", "File", "StartLine", "EndLine", "Entropy", "Tags")
    out = []
    for f in findings:
        r = {k: f.get(k) for k in keep}
        if f.get("Commit"):
            r["Commit"] = shift_sha(f["Commit"], cmap)
        out.append(r)
    return out


def process(r, tok, zf_path, workdir):
    """Every repo goes into the zip. Each stage is guarded; whatever a stage could not achieve is
    recorded in rec["problems"] and in <work>/reports/<owner>/<name>.problems.json (not in the zip)."""
    owner, name = r["owner"], r["name"]
    rec = {"repo": f"{owner}/{name}", "fork": r["fork"], "size_kb": r["size_kb"]}
    problems = []
    t0 = time.time()

    def step(label, fn, default=None):
        try:
            return fn()
        except Exception as e:
            problems.append(f"{label}: {str(e)[:300]}")
            log(f"  STEP FAILED {label}: {str(e)[:200]}\n{traceback.format_exc()[-1500:]}")
            return default

    repo = os.path.join(workdir, f"{name}.git")
    wiki = os.path.join(workdir, f"{name}.wiki.git")
    rmtree(wiki)
    # Resume: reuse a finished mirror left by an interrupted run (has refs, no filter-repo rewrite yet).
    marker = repo + ".cloned"
    reuse = (os.path.exists(marker) and os.path.isdir(repo) and not os.path.exists(os.path.join(repo, "filter-repo"))
             and subprocess.run(["git", "-C", repo, "for-each-ref", "--count=1"],
                                capture_output=True, text=True).stdout.strip() != "")
    if reuse:
        cloned = True
        log("  reusing existing clone")
    else:
        rmtree(repo)
        cloned = step("clone failed: repo could not be downloaded, nothing of its git history is in the zip",
                      lambda: clone(owner, name, tok, repo) or True, False)
        if cloned:
            open(marker, "w").close()
        log(f"  cloned in {round(time.time() - t0)}s")
    api = step("API fetch failed: no PR/issue/review history", lambda: fetch_api(owner, name, tok, r["has_issues"]),
               {"errors": {}, "issues": [], "issue_comments": [], "pulls": [], "review_comments": [], "reviews": {}})
    rec["api"] = {k: len(api.get(k, [])) for k in ("issues", "issue_comments", "pulls", "review_comments")}
    rec["api_errors"] = len(api.get("errors", {}))

    def scan():
        f1 = gitleaks(repo, os.path.join(workdir, "leaks.json")) if cloned else []
        api_path = os.path.join(workdir, "api_raw.json")
        with open(api_path, "w", encoding="utf-8") as f:
            json.dump(api, f)
        f2 = gitleaks(api_path, os.path.join(workdir, "leaks_api.json"), mode="dir")
        os.remove(api_path)
        return f1, f2
    findings, api_findings = step("secrets scan failed: history was NOT checked for secrets", scan, ([], []))
    if cloned:
        big = step("large-file listing failed", lambda: scan_excludes(repo), []) or []
        rec["scan_skipped_patterns"] = big
        if big:
            log(f"  not scanned (files over {MAX_SCAN_MB} MB; known secrets still replaced in them): {', '.join(big)[:300]}")
    secrets = sorted({f["Secret"].encode("utf-8", "surrogateescape") for f in findings + api_findings
                      if len(f.get("Secret") or "") >= MIN_SECRET}, key=len, reverse=True)
    rec["leaks_found"] = len(findings) + len(api_findings)
    rec["secrets_redacted"] = len(secrets)
    log(f"  api + scan done at {round(time.time() - t0)}s: {rec['leaks_found']} findings, {len(secrets)} secrets")

    anon = step("identity collection failed: names in README/messages/API NOT replaced",
                lambda: Anon(collect_identities(repo, api) if cloned else {}), Anon({}))
    cmap, lic, after = {}, 0, []
    if cloned:
        res = step("history rewrite failed: authors, dates, commit hashes, secrets and LICENSE files are NOT anonymised",
                   lambda: (os.path.exists(marker) and os.remove(marker),
                            clean_repo(repo, secrets, anon, workdir, "repo"))[1])
        if res:
            cmap, lic, after = res
    rec["commits"] = len(cmap)
    rec["license_paths_removed"] = lic
    rec["leaks_after"] = len(after)
    log(f"  rewritten at {round(time.time() - t0)}s")
    api.pop("_upstream_owners", None)
    api_clean = step("API anonymisation failed: PR/issue data is included UNANONYMISED",
                     lambda: anon_api(api, cmap, anon, secrets), api)
    report = {"before": safe_report(findings, cmap), "api": safe_report(api_findings, cmap),
              "after_rewrite": safe_report(after, cmap)}
    if cloned:
        problems += step("verification failed", lambda: verify_clean(repo, cmap), []) or []
    if after:
        problems.append(f"{len(after)} gitleaks finding(s) remain after the rewrite (see the gitleaks report)")

    rec["wiki"] = False
    if r["has_wiki"]:
        try:
            clone(owner, name, tok, wiki, wiki=True)
        except Exception:
            pass  # wiki enabled but never created: no git repo exists
        else:
            rec["wiki"] = True

            def do_wiki():
                wf = gitleaks(wiki, os.path.join(workdir, "leaks_wiki.json"))
                wsec = sorted({f["Secret"].encode("utf-8", "surrogateescape") for f in wf
                               if len(f.get("Secret") or "") >= MIN_SECRET}, key=len, reverse=True)
                wmap, _, wafter = clean_repo(wiki, wsec, anon, workdir, "wiki")
                return [f"wiki: {p}" for p in verify_clean(wiki, wmap)] + \
                    ([f"wiki: {len(wafter)} gitleaks finding(s) remain"] if wafter else [])
            problems += step("wiki cleaning failed: wiki included UNCLEANED", do_wiki, []) or []

    rec["problems"] = problems
    rec["zipped"] = True
    if problems:
        log(f"  PROBLEMS {owner}/{name}: {problems}")
    # Reports stay OUT of the zip (user: zip holds only the repos); kept in the work dir.
    rdir = os.path.join(workdir, "reports", owner)
    os.makedirs(rdir, exist_ok=True)
    with open(os.path.join(rdir, f"{name}.gitleaks.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=1)
    if problems:
        with open(os.path.join(rdir, f"{name}.problems.json"), "w", encoding="utf-8") as f:
            json.dump(problems, f, indent=1)
    zip_checkpoint(zf_path, workdir)
    with zipfile.ZipFile(zf_path, "a", zipfile.ZIP_DEFLATED, allowZip64=True, compresslevel=6) as zf:
        if cloned and os.path.isdir(repo):
            zip_repo(zf, repo, f"{owner}/{name}.git")
        if rec["wiki"] and os.path.isdir(wiki):
            zip_repo(zf, wiki, f"{owner}/{name}.wiki.git")
        zf.writestr(f"{owner}/{name}.api.json", json.dumps(api_clean, indent=1, ensure_ascii=False))
    rmtree(wiki)
    rmtree(repo)
    rec["seconds"] = round(time.time() - t0)
    return rec


def main():
    global LOG
    args = sys.argv[1:]
    only = set()
    zf_path = OUT_ZIP
    while args:
        a = args.pop(0)
        if a == "--only":
            while args and not args[0].startswith("--"):
                only.add(args.pop(0))
        elif a == "--zip":
            zf_path = args.pop(0)
    work = WORK if zf_path == OUT_ZIP else zf_path + ".work"
    os.makedirs(work, exist_ok=True)
    LOG = open(os.path.join(work, "run.log"), "a", encoding="utf-8")
    done_path = os.path.join(work, "done.jsonl")
    done = {}
    if os.path.exists(done_path):
        with open(done_path, encoding="utf-8") as f:
            for line in f:
                d = json.loads(line)
                if d.get("zipped", True):
                    done[d["repo"]] = d
    if os.path.exists(zf_path) and not zipfile.is_zipfile(zf_path):
        if not os.path.exists(os.path.join(work, "zip_tail.json")):
            sys.exit(f"{zf_path} is damaged and there is no checkpoint; move it aside before resuming")
        zip_recover(zf_path, work)
        if not zipfile.is_zipfile(zf_path):
            sys.exit(f"{zf_path} could not be restored from the checkpoint")
        print("zip restored to its last complete repo", flush=True)

    global PSEUDO, PARA_CACHE_PATH, PARA_CWD
    PSEUDO = Pseudo(os.path.join(work, "pseudonym.key"))
    PARA_CACHE_PATH = os.path.join(work, "paraphrase_cache.jsonl")
    PARA_CWD = os.path.join(work, "claude_cwd")  # empty dir: no project files or CLAUDE.md for headless claude
    os.makedirs(PARA_CWD, exist_ok=True)
    if os.path.exists(PARA_CACHE_PATH):
        with open(PARA_CACHE_PATH, encoding="utf-8") as f:
            for line in f:
                src, dst = json.loads(line)
                if dst != src:
                    PARA_CACHE[src] = dst
    toks = {a: token(a) for a in ACCOUNTS}
    repos = [r for a in ACCOUNTS for r in list_repos(a, toks[a])]
    if only:
        repos = [r for r in repos if f"{r['owner']}/{r['name']}" in only]
    todo = [r for r in repos if f"{r['owner']}/{r['name']}" not in done]
    log(f"{len(repos)} repos, {len(done)} done, {len(todo)} to go, {sum(r['size_kb'] for r in todo) // 1024} MB")
    failed = []
    for i, r in enumerate(todo, 1):
        key = f"{r['owner']}/{r['name']}"
        log(f"[{i}/{len(todo)}] {key} ({r['size_kb'] // 1024} MB{', fork' if r['fork'] else ''})")
        try:
            rec = process(r, toks[r["owner"]], zf_path, work)
        except Exception as e:  # keep going; failures are listed at the end
            log(f"  FAILED {key}: {e}")
            failed.append(key)
            rmtree(os.path.join(work, f"{r['name']}.git"))
            continue
        with open(done_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
        done[key] = rec
        log(f"  ok: {rec['commits']} commits, leaks {rec['leaks_found']}->{rec['leaks_after']}, "
            f"licenses -{rec['license_paths_removed']}, zipped {rec['zipped']}, "
            f"api {rec['api']}, {rec['seconds']}s, zip {os.path.getsize(zf_path) / 2**30:.1f} GB")

    if len(done) == len(repos) and not only:
        with open(os.path.join(work, "summary.json"), "w", encoding="utf-8") as f:
            json.dump(list(done.values()), f, indent=1)
        os.remove(os.path.join(work, "pseudonym.key"))
        os.path.exists(PARA_CACHE_PATH) and os.remove(PARA_CACHE_PATH)  # without it the imaginary names cannot be traced back
    log(f"finished: {len(done)}/{len(repos)} done, failed: {failed}")


if __name__ == "__main__":
    main()
