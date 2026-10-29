"""Full anonymisation on top of mirror.py (user, 2026-10-27: "do full anonymisation ... do your best").

Every commit of the history is rewritten (the code itself is not re-authored):
- the project gets an imaginary name that reflects its topic; every spelling of the real name (acmefolio,
  Acmefolio, ACMEFOLIO, open-ledger, open_ledger, OpenLedger, "Open Ledger" ...) is replaced in the same style in
  all text files, folder and file names, branch and tag names, commit messages and issues, so imports and package
  paths still line up;
- the owner's account name, contributors' logins (@login, github.com/login) and full names (e.g. copyright
  headers) are replaced by imaginary ones; every email address becomes redactedemail@gmail.com; the project's
  homepage and its sub-domains become example.com; in READMEs and other docs, links naming the project, owner or
  homepage become https://example.com;
- every other text file gets one extra newline at the end, so no file keeps the content hash it has in the
  original repo;
- logos, favicons, banners and screenshots are replaced by neutral placeholder images;
- the whole timeline moves back by a secret offset (30-180 days; order kept, rounded to 10 minutes in UTC).
"""
import functools
import hashlib
import hmac
import io
import os
import re
import struct
import subprocess
import time
import zipfile
import zlib
from urllib.parse import urlparse

EMAIL = "redactedemail@gmail.com"
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")
# EMAIL_RE.sub retries every start position of a long run of address characters (a 175k-character run without an
# "@" took 106 s; a 13 MB bundle, hours), so email_sub finds the same matches in one pass: a match always starts
# where a run of local-part characters starts (or where the last match ended) and ends at the domain after its "@".
_LOCAL_RUN = re.compile(r"[A-Za-z0-9._%+\-]+")
_DOMAIN = re.compile(r"[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")


def email_sub(repl, s):
    """Same result as EMAIL_RE.sub(repl, s) for a string repl, in linear time."""
    out, last, pos = [], 0, 0
    while True:
        run = _LOCAL_RUN.search(s, pos)
        if not run:
            break
        e = run.end()
        dom = _DOMAIN.match(s, e + 1) if s.startswith("@", e) else None
        if dom:
            out += (s[last:run.start()], repl)
            last = pos = dom.end()
        else:
            pos = e
    return "".join(out) + s[last:] if out else s
URL_RE = re.compile(r"(?:https?://|www\.)[^\s)\]}>\"'`]+")
WORD_RE = re.compile(r"\w+")
AT_RUN_RE = re.compile(r"@([A-Za-z0-9-]+)")
MERGE_PR_RE = re.compile(r"(Merge pull request #\d+ from )([A-Za-z0-9][A-Za-z0-9-]{0,38})/([^\s'\"]+)")
MERGE_BR_RE = re.compile(r"(Merge (?:remote-tracking )?branch '(?:[^'/\s]+/)?)([^'\s]+)(')")
TODO_RE = re.compile(r"\b(TODO|FIXME|XXX|HACK|NOTE)\(([A-Za-z0-9][A-Za-z0-9_.-]{1,38})\)")
GH_RUN_RE = re.compile(r"github\.com/([A-Za-z0-9-]+)", re.I)
SAFE_URL = "https://example.com"
# The imaginary name reflects the project's topic (user, 2026-10-27): the workflow's `name` input when given,
# otherwise a topic phrase picked from the repo's description and topics, with a qualifier from the key.
TOPICS = [
    (r"order book|matching engine", "Order Matching Engine"),
    (r"portfolio|wealth|net worth", "Portfolio Tracker"),
    (r"due diligence", "Due Diligence Agents"),
    (r"simulat", "Market Simulator"),
    (r"stock|trading|trader|exchange|forex|crypto", "Trading Platform"),
    (r"invoic|freelanc|time track", "Business Finance Hub"),
    (r"\berp\b|\bcrm\b|\bhrm\b|business management|project management", "Business Operations Suite"),
    (r"budget|personal finance|expense|money manag", "Budget Manager"),
    (r"account|bookkeep|ledger", "Accounting Ledger"),
    (r"database|\bsql\b|query engine|storage engine", "Distributed Database"),
    (r"agent|\bllm\b|claude|\bgpt\b|\bai\b", "Finance Agent Toolkit"),
    (r"financ|bank|payment", "Finance Platform"),
]
QUALIFIER = """Northwind Bluefield Clearwater Brightline Silverline Keystone Summit Meridian Harbor Granite Evergreen
Riverside Lakeside Highpoint Crestview Fairway Oakridge Redwood Stonebridge Westfield""".split()

IMAGE_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".icns", ".bmp", ".avif", ".tif", ".tiff")
LOGO_RE = re.compile(r"logo|brand|favicon|wordmark|banner|mascot|apple-touch|og-image|opengraph|social|splash|"
                     r"screenshot|screen-shot|preview|hero|cover|avatar|thumbnail|readme", re.I)
DOC_EXT = (".md", ".mdx", ".markdown", ".rst", ".adoc", ".txt", ".html", ".htm")
NO_TWEAK_EXT = (".snap", ".golden", ".patch", ".diff", ".pem", ".crt", ".key", ".der", ".sig", ".asc", ".sum")
MAX_TEXT = 20 * 2**20
# Metadata and translation files list people by login or one-word name ("login": "x", reviewers: - x, Last-Translator:
# x <...>, translator-credits): they get every known identity replaced, like docs, not only @login and full names.
STRUCT_RE = re.compile(r"(^|/)(\.all-contributorsrc|\.pullapprove\.ya?ml|codeowners|funding\.ya?ml|citation\.cff|"
                       r"\.zenodo\.json|\.mailmap|dependabot\.ya?ml|renovate\.json5?|(authors|contributors|maintainers|"
                       r"credits|owners)(\.[a-z]+)?)$|\.(po|pot|xlf|xliff|cff)$|(^|/)\.github/.*\.(json|ya?ml)$", re.I)
# A name that is also a common English word ("page", "ghost", "contributor") is replaced only where it stands for a
# person (@x, github.com/x, merge lines, TODO(x), ref names, metadata files), never on its own in prose or code.
COMMON_FALLBACK = set("""
able about above access account action active add address admin advanced after again agent all alpha also alter
amber angel answer anything apple april area army art artist autumn avatar back badge baker bank base basic bear
beta bird black blank block blue board body book boss bot box brain branch brand bridge bright brown build builder
bunny butter button cache call camp candy cap captain card care carpet case cash cat chain change chaos charlie
chart check cherry chief child city class clean clear client clock cloud coach code coder coffee cold color
comment common config contact content contrib contributor cook cool copper core corner cosmos count cover craft
crash cream creator crow crystal cube cyber daily dancer dark data dawn day deal debug deep delta demo design
designer desk dev developer devil diamond digital doc docs doctor dog dragon dream drive duck dust eagle earth east
echo edge editor eight element empty end energy engine engineer error event example expert eye face factory falcon
fan farm fast father feature field file final fire first fish fix flash flow flower fly focus forest fox frame free
friend frost fun game garden gate ghost giant gift glass global gold good grace green grey guest guide hacker hand
happy hawk heart hello help hero hill home honey hope host hunter ice idea image info iron island jack jade jazz
job joker joy judge jungle just king kit knight lab lady lake lamp last leader lemon level light lime line link lion
little local logic long lord love lucky lunar magic mail main maker man manager map maple mark market master matrix
max media mellow member mercury meta metal micro mind mint mirror mobile mode model money monkey moon morning
mother motion mountain mouse music native nature new news night ninja noble node north nova ocean office omega one
open orange order origin owner page paper park pass patch peace pearl pencil pepper phoenix pilot pink pixel plain
planet player plus point polar post power prime prince pro project proxy pulse pure purple quantum queen quick
rabbit rain random raven ready red release remote rich river robot rock rocket root rose ruby runner sage sailor
salt sand scout sea search season secret security seed server shadow shark sharp shell shine silver simple sky
smart smile smith snake snow solar solid sound south space spark spider spirit spring square star steel stone
storm story studio sugar summer sun super swift system tango team tech test thunder tiger time tiny titan token
tool top tower trade tree true trust twin ultra union unit unknown user valley vector velvet victor viper vision
voice void walker wall water wave west white wild wind winter wizard wolf wood work world writer yellow young zero
""".split())


def _common_words():
    words = set(COMMON_FALLBACK)
    for p in ("/usr/share/dict/words", "/usr/share/dict/american-english"):
        try:
            with open(p, encoding="utf-8", errors="ignore") as f:
                words |= {w for w in (x.strip() for x in f) if len(w) >= 3 and w.isalpha() and w.islower()}
            break
        except OSError:
            pass
    return words


COMMON = _common_words()


def plain_word(k):
    """An identity that is also an ordinary word: lower case or Capitalised, and in the word list."""
    return k.isascii() and k.isalpha() and k.lower() in COMMON and (k.islower() or k[1:].islower())


def project_name(key, name, about="", given=""):
    """Imaginary project name: (Title Words, slug, CamelCase). `given` wins; otherwise qualifier + topic phrase,
    the same every run with the same key."""
    if given.strip():
        title = " ".join(given.split())
    else:
        topic = next((t for pat, t in TOPICS if re.search(pat, about, re.I)), "Software Platform")
        h = hmac.new(key, ("project:" + name.lower()).encode(), hashlib.sha256).digest()
        title = f"{QUALIFIER[int.from_bytes(h[:4], 'big') % len(QUALIFIER)]} {topic}"
    words = re.findall(r"[A-Za-z0-9]+", title)
    return title, "-".join(w.lower() for w in words), "".join(w[:1].upper() + w[1:] for w in words)


def split_words(s):
    return re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+", s)


def spellings(words):
    """{style: spelling} for a list of words, identifier-safe styles first (they win when two styles collide)."""
    lw = [w.lower() for w in words]
    cap = [w[:1].upper() + w[1:] for w in words]
    cap_l = [w[:1].upper() + w[1:].lower() for w in words]
    return {
        "Camel": "".join(cap), "CamelL": "".join(cap_l), "lower": "".join(lw), "UPPER": "".join(lw).upper(),
        "camel": lw[0] + "".join(cap_l[1:]),
        "kebab": "-".join(lw), "snake": "_".join(lw), "SNAKE": "_".join(lw).upper(),
        "Kebab": "-".join(cap), "Title": " ".join(cap), "spaced": " ".join(lw),
    }


def png(size=256, rgb=(0xB8, 0xBE, 0xC6)):
    """A plain grey square PNG (neutral placeholder for raster logos and screenshots)."""
    raw = b"".join(b"\x00" + bytes(rgb) * size for _ in range(size))

    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0)) +
            chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def ico(p):
    return struct.pack("<HHH", 0, 1, 1) + struct.pack("<BBBBHHII", 0, 0, 0, 0, 1, 32, len(p), 22) + p


def placeholder(path, title):
    ext = os.path.splitext(path.lower())[1]
    if ext == ".svg":
        initials = "".join(w[0] for w in title.split()[:3]).upper()
        return (f'<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256" viewBox="0 0 256 256">'
                f'<rect width="256" height="256" rx="40" fill="#B8BEC6"/><text x="128" y="150" font-size="72" '
                f'font-family="sans-serif" text-anchor="middle" fill="#ffffff">{initials}</text></svg>\n').encode()
    p = png(64 if ext in (".ico", ".icns") else 256)
    return ico(p) if ext == ".ico" else p


SLOW_BLOB = 300  # seconds: a file that takes longer is replaced by STUCK_TEXT, so one file can never stall a run
STUCK_TEXT = b"This file was removed: it could not be anonymised automatically.\n"


class Slow(Exception):
    pass


def _alarm(_sig, _frame):
    raise Slow()


def timed(fn, *args):
    """fn(*args), or Slow after SLOW_BLOB seconds (the regex engine checks for signals while it runs). Needs SIGALRM
    and the main thread (Linux runners); elsewhere there is no limit."""
    import signal
    import threading
    if not hasattr(signal, "SIGALRM") or threading.current_thread() is not threading.main_thread():
        return fn(*args)
    old = signal.signal(signal.SIGALRM, _alarm)
    signal.alarm(SLOW_BLOB)
    try:
        return fn(*args)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


_PRE = None  # (repo, paths, process, cache) for the forked workers of precompute()


def _pre_work(oids):
    """Worker: the new content of some blobs, written compressed to the cache; returns the unchanged ones and the
    stats this worker added."""
    import subprocess
    repo, paths, process, stats, cache = _PRE
    before = {k: v for k, v in stats.items() if isinstance(v, int)}
    unchanged = []
    cat = subprocess.Popen(["git", "cat-file", "--batch"], cwd=repo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    for oid in oids:
        cat.stdin.write(oid + b"\n")
        cat.stdin.flush()
        size = int(cat.stdout.readline().split()[2])
        raw = cat.stdout.read(size)
        cat.stdout.read(1)
        new = process(paths[oid], raw)
        if new == raw:
            unchanged.append(oid)
        else:
            with open(os.path.join(cache, oid.decode()), "wb") as fh:
                fh.write(zlib.compress(new, 1))
    cat.stdin.close()
    cat.wait()
    return unchanged, {k: stats[k] - before.get(k, 0) for k in stats if isinstance(stats[k], int)}


def precompute(repo, paths, process, stats):
    """Anonymise every blob on all CPU cores before the history rewrite (which runs the blob callback on one core:
    big histories took more than the 6 h job limit). Returns (unchanged blob ids, cache dir of the new contents);
    the blob callback takes each result from there and does any blob without one itself. Needs fork (Linux);
    elsewhere, or with ANON_PARALLEL=0, the callback does all the work itself as before."""
    global _PRE
    import multiprocessing
    import subprocess
    import tempfile
    from concurrent.futures import ProcessPoolExecutor, as_completed
    from concurrent.futures.process import BrokenProcessPool
    n = os.cpu_count() or 1
    if n < 2 or os.environ.get("ANON_PARALLEL") == "0" or "fork" not in multiprocessing.get_all_start_methods():
        return set(), None
    out = subprocess.run(["git", "cat-file", "--batch-all-objects", "--batch-check=%(objectname) %(objecttype)"],
                         cwd=repo, capture_output=True, check=True).stdout
    oids = [line.split()[0] for line in out.splitlines() if line.endswith(b" blob") and line.split()[0] in paths]
    cache = tempfile.mkdtemp(prefix="anon-cache-", dir=os.path.dirname(os.path.abspath(repo)))
    _PRE = (repo, paths, process, stats, cache)
    chunks = [oids[i::n * 16] for i in range(n * 16)]
    unchanged = set()
    t0 = time.time()
    # Not multiprocessing.Pool: when a worker dies (out of memory) a Pool waits forever for its task, while this
    # pool raises, and the blob callback then does the blobs that are left.
    pool = ProcessPoolExecutor(n, mp_context=multiprocessing.get_context("fork"))
    try:
        for i, fut in enumerate(as_completed([pool.submit(_pre_work, c) for c in chunks]), 1):
            got, added = fut.result()
            unchanged.update(got)
            for k, v in added.items():
                stats[k] = stats.get(k, 0) + v
            if i % max(1, len(chunks) // 10) == 0:
                print(f"  blobs anonymised: {i * 100 // len(chunks)}% of {len(oids)} in {time.time() - t0:.0f}s", flush=True)
    except BrokenProcessPool:
        print(f"  a worker stopped (out of memory?) after {time.time() - t0:.0f}s; the rewrite does the rest", flush=True)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
        _PRE = None
    return unchanged, cache


def _git(repo, *args):
    return subprocess.run(["git", *args], cwd=repo, capture_output=True, check=True).stdout


def keep_published_refs(repo):
    """Only branches and tags are published, so only they are rewritten. A mirror clone also holds refs/pull/* (one
    per PR), refs/notes, refs/remotes ...: filter-repo leaves refs/remotes as they are (erpnext: 3 commits kept their
    real authors and dates, so verification failed every time), and the pull refs doubled the work (ghostfolio: 79k
    more files, among them a 13 MB bundle the email regex took hours on). Returns how many refs went."""
    refs = _git(repo, "for-each-ref", "--format=%(refname)").decode().split()
    drop = [r for r in refs if not r.startswith(("refs/heads/", "refs/tags/"))]
    if drop:
        subprocess.run(["git", "update-ref", "--stdin"], cwd=repo, check=True, capture_output=True,
                       input="".join(f"delete {r}\n" for r in drop).encode())
    return len(drop)


def shape(repo):
    """The shape of the history: every commit with its parents, branch tips, and what each tag points at."""
    parents = {}
    for line in _git(repo, "rev-list", "--all", "--parents").decode().splitlines():
        ids = line.split()
        parents[ids[0]] = ids[1:]
    heads = _git(repo, "for-each-ref", "--format=%(objectname)", "refs/heads").decode().split()
    tags = []
    for line in _git(repo, "for-each-ref", "--format=%(objecttype) %(objectname) %(*objecttype) %(*objectname)",
                     "refs/tags").decode().splitlines():
        kind, oid, pkind, poid = (line.split() + ["", ""])[:4]
        tags.append((pkind, poid) if kind == "tag" else (kind, oid))
    return {"parents": parents, "heads": sorted(heads), "tags": tags}


def shape_problems(before, repo, cmap):
    """The rewritten history must have exactly the source's shape: same number of commits, each one with the
    rewritten versions of its own parents in the same order, the same branches and tags on the same commits."""
    after = shape(repo)
    bp, ap = before["parents"], after["parents"]
    problems = []
    if len(ap) != len(bp):
        problems.append(f"commit count changed ({len(bp)} in the source, {len(ap)} rewritten)")
    moved = sum(1 for c, ps in bp.items() if ap.get(cmap.get(c)) != [cmap.get(x) for x in ps])
    if moved:
        problems.append(f"{moved} commits not in their place in the history")
    if sorted(cmap.get(h) or "" for h in before["heads"]) != after["heads"]:
        problems.append("branches differ from the source")
    old_tags = sorted(cmap.get(o) or "" if k == "commit" else k for k, o in before["tags"])
    if old_tags != sorted(o if k == "commit" else k for k, o in after["tags"]):
        problems.append("tags differ from the source")
    return problems


def proj_word(k):
    """An exact project spelling as a word: not inside a longer name (llm-d is not replaced in vllm-dev or llm-dx).
    A CamelCase spelling may still start a longer CamelCase name (AcmeDBConfig)."""
    camel = re.search(r"[a-z]", k) and re.search(r"[A-Z]", k)
    return r"(?<![A-Za-z0-9])" + re.escape(k) + (r"(?![a-z0-9])" if camel else r"(?![A-Za-z0-9])")


def install(m, owner, name, homepage="", aliases=(), about="", given="", names=(), keep_owner=False, owners=()):
    """Patch mirror.py (module m) for this repo. Returns (Anon class to use instead of m.Anon, project title, slug).

    names: the project names to replace, instead of the repo name (a generic repo name such as "components"
    must not be replaced everywhere). keep_owner: the owner is also a framework the code imports, so its
    name stays. owners: other account names of the owner (old or renamed orgs) to replace."""
    title, slug, camel = project_name(m.PSEUDO.key, name, about, given)
    new_words = re.findall(r"[A-Za-z0-9]+", title)
    m.Pseudo.email = lambda self, ident: EMAIL

    # Timeline: one secret shift for the whole repo (commits, tags, issues), whole 10-minute steps.
    h = hmac.new(m.PSEUDO.key, b"timeline", hashlib.sha256).digest()
    shift = 600 * (4320 + int.from_bytes(h[:4], "big") % 21600)
    _round = m.round_epoch
    m.round_epoch = lambda t: _round(t) - shift

    hosts = set()
    for x in [homepage or ""] + [a for a in aliases if "." in a]:
        host = urlparse(x if "//" in x else "//" + x).hostname or ""
        if host:
            hosts.add(host.removeprefix("www."))
    names = list(names or [name]) + [a for a in aliases if "." not in a]
    owner_logins = [] if keep_owner else [owner]
    owner_logins = [o for o in owner_logins + list(owners)  # an owner named like the project is renamed with it
                    if not any(o.lower() == n.lower() for n in names + [name])]
    proj = {}
    new = spellings(new_words)
    for n in names:
        old = spellings(split_words(n) or [n])
        old["as-is"], new["as-is"] = n, new["Camel"] if not re.search(r"[-_ ]", n) else new["Title"] if " " in n else new["kebab"]
        for style, sp in old.items():
            if len(sp) >= 4 and sp not in proj:
                proj[sp] = new[style]
    for sp in [k for k in proj if "_" in k]:  # Markdown escapes underscores: name\_part
        proj.setdefault(sp.replace("_", "\\_"), proj[sp].replace("_", "\\_"))
    # In prose (docs, messages, issues) a capitalised one-word name reads as the spaced title.
    prose = {}
    for n in names:
        if len(n) >= 4 and not re.search(r"[-_ ]", n):  # acmefolio, AcmeDB, OrderBookSimulator
            for sp in {n[:1].upper() + n[1:], n[:1].upper() + n[1:].lower(), spellings(split_words(n) or [n])["Camel"]}:
                prose[sp] = title
    prose_re = re.compile(r"(?<![A-Za-z0-9@/._-])(?:" + "|".join(map(re.escape, sorted(prose, key=len, reverse=True)))
                          + r")(?![A-Za-z0-9_/-]|\.[A-Za-z0-9])") if prose else None
    proj_re = re.compile("|".join(map(proj_word, sorted(proj, key=len, reverse=True))) or r"(?!)")  # (?!): never
    # Mixed spellings the styles above miss (AcmeFolio, OPEN-ledger): whole word, any case -> CamelCase.
    loose_words = sorted({tuple(w.lower() for w in (split_words(n) or [n])) for n in names if len(n) >= 3},
                         key=lambda ws: len("".join(ws)), reverse=True)
    loose = ["".join(ws) for ws in loose_words]
    loose_re = re.compile(r"(?<![A-Za-z0-9])(?:" + "|".join(
        r"(?:\\?[-_]| )?".join(map(re.escape, ws)) for ws in loose_words) + r")(?![A-Za-z0-9])", re.I)
    # CamelCase joins (AcmeDriver, FooAcmeError): a one-word name that is not an ordinary word, as a part of a name.
    camel_parts = sorted({ws[0][:1].upper() + ws[0][1:] for ws in loose_words
                          if len(ws) == 1 and len(ws[0]) >= 3 and not plain_word(ws[0])}, key=len, reverse=True)
    camel_alt = "|".join(map(re.escape, camel_parts))
    camel_re = re.compile(r"(?<![A-Za-z])(?:" + camel_alt + r")(?=[A-Z][a-z])|(?<=[a-z0-9])(?:" + camel_alt +
                          r")(?![a-z])") if camel_parts else None
    host_re = re.compile(r"\b(?:[A-Za-z0-9-]+\.)*(?:" + "|".join(re.escape(x) for x in sorted(hosts, key=len, reverse=True))
                         + r")\b", re.I) if hosts else None
    rev_hosts = sorted({".".join(reversed(x.split("."))) for x in hosts if "." in x}, key=len, reverse=True)
    # reverse-DNS ids: io.acme.app -> com.example.app
    rev_re = re.compile(r"(?<![\w.-])(?:" + "|".join(map(re.escape, rev_hosts)) + r")\b(?!-)", re.I) if rev_hosts else None
    # Owner logins joined with a hyphen (bot accounts acme-release[bot], forks f-acme) too, unless the owner is a word.
    owner_re = re.compile("|".join(
        (r"(?<![A-Za-z0-9-])" if plain_word(o) else r"(?<![A-Za-z0-9])") + re.escape(o) +
        (r"(?![A-Za-z0-9-])" if plain_word(o) else r"(?![A-Za-z0-9])") for o in owner_logins), re.I) if owner_logins else None
    owner_new = {o.lower(): m.PSEUDO.login(o) for o in owner_logins}
    needles = [x.lower() for x in [*owner_logins, *names, *hosts] if len(x) >= 3]

    def url_fix(mt):
        u = mt.group()
        return SAFE_URL if any(n in u.lower() for n in needles) else u

    # Quick checks before each regex: a file without the plain text a match must contain is skipped (most files).
    # Case-insensitive checks use str.lower() only on ASCII text, where it agrees with re.I.
    host_lows = [x.lower() for x in hosts]
    loose_firsts = [ws[0] for ws in loose_words]
    owner_lows = [o.lower() for o in owner_logins]
    rev_firsts = [x.lower() for x in rev_hosts]

    def may_have(s, lows):
        if not s.isascii():
            return True
        low = s.lower()
        return any(x in low for x in lows)

    def rename(s):
        """Project, homepage and owner names (code-safe: same style in, same style out)."""
        if host_re and may_have(s, host_lows):
            s = host_re.sub("example.com", s)
        if any(k in s for k in proj):
            s = proj_re.sub(lambda mt: proj[mt.group()], s)
        if may_have(s, loose_firsts):
            s = loose_re.sub(lambda mt: new["lower"] if mt.group().islower() else new["UPPER"] if mt.group().isupper() else camel, s)
        if owner_re and may_have(s, owner_lows):
            s = owner_re.sub(lambda mt: owner_new[mt.group().lower()], s)
        if rev_re and may_have(s, rev_firsts):
            s = rev_re.sub("com.example", s)
        if camel_re and any(p in s for p in camel_parts):
            s = camel_re.sub(camel, s)
        return s

    class ProjAnon(m.Anon):
        def __init__(self, identities):
            keep = {k: v for k, v in identities.items() if k.lower() not in {p.lower() for p in proj}}
            extra_people = getattr(m, "EXTRA_PEOPLE", ())
            # Ordinary words that are also someone's login or e-mail name stay as words in prose (no "at <person>
            # boundaries" for "at page boundaries"); they are still replaced where they stand for a person.
            self.plain = {k.lower(): v for k, v in keep.items() if plain_word(k) and k not in extra_people}
            super().__init__({k: v for k, v in keep.items() if k.lower() not in self.plain})
            people = sorted({k for k in keep if (" " in k.strip() and "@" not in k and len(k) >= 5)
                             or k in getattr(m, "EXTRA_PEOPLE", ())}, key=len, reverse=True)  # job option people
            # One regex over thousands of names is slow on big files (ghostfolio: 0.5 MB/s, too slow for 4 GB of
            # history), so each file only gets a regex of the names that can occur in it, same order as before.
            self.people_list = people
            self.people_first = {}  # first word -> indexes into people (None: not a plain word, always tried)
            for i, k in enumerate(people):
                w = k.split()[0]
                self.people_first.setdefault(w if re.fullmatch(r"\w+", w) else None, []).append(i)
            self.people = {re.sub(r"\s+", " ", k): v for k, v in keep.items() if k in people}
            logins = sorted({k for k in keep if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{2,38}", k)}, key=len, reverse=True)
            self.all_logins = {k.lower(): v for k, v in keep.items() if k in logins}  # plain words included
            self.login_list = logins
            self.login_index = {}
            for i, k in enumerate(logins):
                self.login_index.setdefault(k.lower(), []).append(i)
            self.logins = {k.lower(): v for k, v in keep.items() if k in logins}

        @staticmethod
        @functools.lru_cache(maxsize=4096)
        def _people_re(people):
            # Same as (?<![\w])(?:A|B), but each name starts with its literal first character, so the regex engine
            # can jump to the places where a name may start; the look-behind then checks the character before it.
            def one(k):
                p = r"\s+".join(map(re.escape, k.split()))
                c = re.escape(k.split()[0][0])
                return c + r"(?<![\w][\s\S])" + p[len(c):]
            return re.compile("(?:" + "|".join(map(one, people)) + r")(?![\w])")

        @staticmethod
        @functools.lru_cache(maxsize=4096)
        def _login_re(logins):
            alt = "|".join(map(re.escape, logins))
            return re.compile(r"(?<=@)(?:" + alt + r")\b|(?<=github\.com/)(?:" + alt + r")\b", re.I)

        def people_in(self, s):
            idx = list(self.people_first.get(None, ()))
            for w in set(WORD_RE.findall(s)) & self.people_first.keys():
                idx += self.people_first[w]
            return tuple(self.people_list[i] for i in sorted(idx))

        def logins_in(self, s):
            idx = set()
            runs = AT_RUN_RE.findall(s) if "@" in s else []
            if may_have(s, ["github.com/"]):
                runs += GH_RUN_RE.findall(s)
            for t in runs:  # a login is a prefix of the run of login characters after @ or github.com/
                t = t.lower()
                for n in range(3, min(len(t), 39) + 1):
                    idx.update(self.login_index.get(t[:n], ()))
            return tuple(self.login_list[i] for i in sorted(idx))

        def who(self, w):
            """The replacement of a login or one-word name, or None."""
            low = w.lower()
            return self.all_logins.get(low) or self.plain.get(low)

        def branch(self, b):
            """A branch name with the logins in it replaced (login/topic, login-patch-1, topic/login)."""
            out = []
            for seg in b.split("/"):
                r = self.who(seg)
                if r:
                    seg = r
                else:
                    for i in [j for j, ch in enumerate(seg) if ch in "-_"][::-1]:  # longest login prefix first
                        head = seg[:i]
                        r = None if plain_word(head) else self.all_logins.get(head.lower())
                        if r:
                            seg = r + seg[i:]
                            break
                out.append(seg)
            return rename("/".join(out))

        def ref(self, r):
            for pre in ("refs/heads/", "refs/tags/"):
                if r.startswith(pre):
                    return pre + self.branch(r[len(pre):])
            return rename(r)

        def contexts(self, s):
            """Places where a word stands for a person: merge lines (with their branch names) and TODO(x)."""
            if "Merge " in s:
                s = MERGE_PR_RE.sub(lambda mt: mt.group(1) + (self.who(mt.group(2)) or mt.group(2)) + "/" +
                                    self.branch(mt.group(3)), s)
                s = MERGE_BR_RE.sub(lambda mt: mt.group(1) + self.branch(mt.group(2)) + mt.group(3), s)
            if "(" in s:
                s = TODO_RE.sub(lambda mt: mt.group(1) + "(" + (self.who(mt.group(2)) or mt.group(2)) + ")", s)
            return s

        def code(self, s):
            """Code-safe replacements for any text file."""
            if "@" in s:
                s = email_sub(EMAIL, s)
            s = self.contexts(rename(s))
            logins = self.logins_in(s)
            if logins:
                s = self._login_re(logins).sub(lambda mt: self.who(mt.group()) or mt.group(), s)
            people = self.people_in(s)
            if people:
                s = self._people_re(people).sub(lambda mt: self.people.get(re.sub(r"\s+", " ", mt.group()), mt.group()), s)
            return s

        def meta(self, s):
            """Metadata and translation files: code-safe, plus every known identity (logins, one-word names)."""
            return m.Anon.text(self, self.code(s))

        def text(self, s):
            """Docs, messages and issues: also links naming the project and every known identity."""
            if "://" in s or "www." in s:
                s = URL_RE.sub(url_fix, s)
            if host_re and may_have(s, host_lows):
                s = host_re.sub("example.com", s)
            if prose_re and any(k in s for k in prose):
                s = prose_re.sub(title, s)
            return super().text(self.code(s))

    m.readme_blobs = lambda repo: {"full"}  # tells rewrite() below to run the full pass (the second pass is secrets-only)

    def rewrite(repo, secrets, anon, full):
        full = bool(full)
        stats = {"licenses_removed": set(), "logos": 0, "renamed_paths": 0, "tweaked": 0}
        paths = {}
        siblings, twins = {}, {}  # commit -> its parents; parents -> the commits written on them so far
        for line in m.run(["git", "rev-list", "--all", "--parents"], cwd=repo).splitlines():
            ids = line.split(b" ", 1)
            siblings[ids[0]] = ids[1] if len(ids) == 2 else b""
        if full:  # blob id -> one path it appears at (blob callbacks get no path)
            for line in m.run(["git", "rev-list", "--all", "--objects"], cwd=repo).splitlines():
                parts = line.split(b" ", 1)
                if len(parts) == 2:
                    paths.setdefault(parts[0], parts[1].decode("utf-8", "surrogateescape"))

        def scrub(b):
            for sec in secrets:
                if sec in b:
                    b = b.replace(sec, m.SECRET_MARK)
            return b

        def clean_file(path, data, depth=0):
            """One file's anonymised content (also used for the files inside zip archives)."""
            low = path.lower()
            if low.endswith(IMAGE_EXT) and (LOGO_RE.search(low) or loose_re.search(low) or proj_re.search(path)):
                stats["logos"] += 1
                return placeholder(path, title)
            if low.endswith(".zip") and data[:2] == b"PK" and depth < 3:
                return clean_zip(data, depth + 1)
            if len(data) <= MAX_TEXT and b"\x00" not in data[:8000]:
                s = data.decode("utf-8", "surrogateescape")
                base = low.rsplit("/", 1)[-1]
                if low.endswith(DOC_EXT) or base.startswith("readme"):
                    s = anon.text(s)
                elif STRUCT_RE.search(low) and hasattr(anon, "meta"):
                    s = anon.meta(s)
                else:
                    s = anon.code(s)
                return s.encode("utf-8", "surrogateescape")
            return data

        def clean_zip(data, depth):
            """Zip archives committed to the repo: every member renamed and anonymised like a repo file, then packed
            again (fixed timestamps, so the same archive always gives the same result)."""
            try:
                src = zipfile.ZipFile(io.BytesIO(data))
                out_buf = io.BytesIO()
                with zipfile.ZipFile(out_buf, "w", zipfile.ZIP_DEFLATED) as dst:
                    for info in src.infolist():
                        name = rename(info.filename)
                        if info.is_dir():
                            dst.writestr(zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0)), b"")
                            continue
                        member = scrub(src.read(info))
                        dst.writestr(zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0)), clean_file(name, member, depth))
                stats["zips"] = stats.get("zips", 0) + 1
                return out_buf.getvalue()
            except (zipfile.BadZipFile, RuntimeError, NotImplementedError, ValueError, OSError):
                return data  # encrypted or damaged archive: left as it is

        def process(path, data):
            """A blob's new content (path: one path it appears at, None when not known)."""
            try:
                return timed(process_one, path, data)
            except Slow:
                stats["stuck"] = stats.get("stuck", 0) + 1
                print(f"  a file took over {SLOW_BLOB}s ({len(data)} bytes, type {os.path.splitext(path or '')[1] or '-'})"
                      "; replaced by a short note", flush=True)
                return STUCK_TEXT

        def process_one(path, data):
            data = scrub(data)
            if path is not None:
                low = path.lower()
                logo = low.endswith(IMAGE_EXT) and (LOGO_RE.search(low) or loose_re.search(low) or proj_re.search(path))
                text = (not logo and len(data) <= MAX_TEXT and b"\x00" not in data[:8000]
                        and not (low.endswith(".zip") and data[:2] == b"PK"))
                data = clean_file(path, data)
                if text and not low.endswith(NO_TWEAK_EXT):
                    data += b"\n"
                    stats["tweaked"] += 1
            return data

        same, cache = precompute(repo, paths, process, stats) if full else (set(), None)

        def blob_cb(blob, _meta):
            oid = blob.original_id
            if oid in same:
                return
            if cache:
                f = os.path.join(cache, oid.decode())
                if os.path.exists(f):
                    with open(f, "rb") as fh:
                        blob.data = zlib.decompress(fh.read())
                    os.remove(f)
                    return
            blob.data = process(paths.get(oid) if full else None, blob.data)

        def filename_cb(fn):
            parts = fn.split(b"/")
            if m.LICENSE_RE.match(parts[-1]) or any(p.lower() == b"licenses" for p in parts[:-1]):
                stats["licenses_removed"].add(fn)
                return None
            if full:
                new_fn = rename(fn.decode("utf-8", "surrogateescape")).encode("utf-8", "surrogateescape")
                if new_fn != fn:
                    stats["renamed_paths"] += 1
                fn = new_fn
            return m.win_path(fn)

        def refname_cb(ref):
            if not full:
                return ref
            r = ref.decode("utf-8", "surrogateescape")
            return (anon.ref(r) if hasattr(anon, "ref") else rename(r)).encode("utf-8", "surrogateescape")

        def commit_cb(c, _meta):
            an, cn = c.author_name.decode("utf-8", "replace"), c.committer_name.decode("utf-8", "replace")
            c.author_name, c.author_email = m.PSEUDO.name(an).encode(), EMAIL.encode()
            c.committer_name, c.committer_email = m.PSEUDO.name(cn).encode(), EMAIL.encode()
            if full:
                c.author_date, c.committer_date = m.git_date(c.author_date), m.git_date(c.committer_date)
                c.message = anon.bytes(scrub(c.message))
            else:
                c.message = scrub(c.message)
            # Commits on the same parents that differed only in their exact time or e-mail would become one and the
            # same commit (llm-d: two commits 1 s apart): the later one moves on by 10 minutes, so none is lost.
            group = twins.setdefault(siblings.get(c.original_id), set())
            while (key := hashlib.sha1(b"\0".join((c.author_name, c.author_date, c.committer_name, c.committer_date,
                                                   c.message))).digest()) in group:
                secs, tz = c.committer_date.split()
                c.committer_date = b"%d %s" % (int(secs) + 600, tz)
            group.add(key)

        def tag_cb(t, _meta):
            if t.tagger_name is not None:
                tn = t.tagger_name.decode("utf-8", "replace")
                t.tagger_name, t.tagger_email = m.PSEUDO.name(tn).encode(), EMAIL.encode()
                if full:
                    t.tagger_date = m.git_date(t.tagger_date)
            t.message = anon.bytes(scrub(t.message)) if full else scrub(t.message)

        args = m.fr.FilteringOptions.parse_args(["--force", "--quiet", "--replace-refs", "delete-no-add",
                                                 "--prune-empty", "never", "--prune-degenerate", "never"])
        cwd = os.getcwd()
        os.chdir(repo)
        try:
            m.fr.RepoFilter(args, blob_callback=blob_cb, filename_callback=filename_cb, refname_callback=refname_cb,
                            commit_callback=commit_cb, tag_callback=tag_cb).run()
        finally:
            os.chdir(cwd)
        cmap = {}
        with open(os.path.join(repo, "filter-repo", "commit-map"), encoding="ascii") as f:
            next(f)
            for line in f:
                old, new_id = line.split()
                cmap[old] = new_id
        m.rmtree(os.path.join(repo, "filter-repo"))
        if cache:
            m.rmtree(cache)
        m.subprocess.run(["git", "config", "--remove-section", "remote.origin"], cwd=repo, capture_output=True)
        for junk in ("FETCH_HEAD", "ORIG_HEAD", "logs"):
            p = os.path.join(repo, junk)
            m.rmtree(p) if os.path.isdir(p) else (os.path.exists(p) and os.remove(p))
        m.run(["git", "reflog", "expire", "--expire=now", "--all"], cwd=repo)
        m.run(["git", "-c", "pack.threads=1", "gc", "--prune=now", "--quiet"], cwd=repo)
        if full:
            m.log(f"full pass: {stats['tweaked']} text files changed, {stats['logos']} logos/screenshots replaced, "
                  f"{stats['renamed_paths']} paths renamed, {stats.get('zips', 0)} zip archives cleaned, "
                  f"{stats.get('stuck', 0)} files too slow to anonymise (replaced)")
        return cmap, len(stats["licenses_removed"])

    m.rewrite = rewrite

    _verify = m.verify_clean

    def verify_clean(repo, cmap):
        problems = [p for p in _verify(repo, cmap) if not p.startswith("real identities left")]
        raw = m.run(["git", "log", "--all", "--format=%an%x00%ae%x00%cn%x00%ce"], cwd=repo)
        raw += m.run(["git", "for-each-ref", "--format=%(taggername)%00%(taggeremail)", "refs/tags"], cwd=repo)
        bad = set()
        for line in raw.decode("utf-8", "replace").splitlines():
            parts = line.split("\x00")
            for nm, mail in zip(parts[0::2], parts[1::2]):
                if (nm or mail) and (nm not in m.PSEUDO.made or mail.strip("<>") != EMAIL):
                    bad.add(nm)
        if bad:
            problems.append(f"real identities left: {len(bad)}")
        # Leftover project names in the latest version (counted, not shown).
        head = m.run(["git", "symbolic-ref", "HEAD"], cwd=repo).decode().strip()
        left = m.subprocess.run(["git", "grep", "-I", "-i", "-c", "-E", "|".join(re.escape(w) for w in loose), head],
                                cwd=repo, capture_output=True, text=True).stdout.splitlines()
        m.log(f"files in the latest version still containing the old project name: {len(left)}")
        return problems

    m.verify_clean = verify_clean
    return ProjAnon, title, slug
