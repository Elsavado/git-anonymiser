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
import hashlib
import hmac
import io
import os
import re
import struct
import zipfile
import zlib
from urllib.parse import urlparse

EMAIL = "redactedemail@gmail.com"
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")
URL_RE = re.compile(r"(?:https?://|www\.)[^\s)\]}>\"'`]+")
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
    # In prose (docs, messages, issues) a capitalised one-word name reads as the spaced title.
    prose = {}
    for n in names:
        if len(n) >= 4 and not re.search(r"[-_ ]", n):  # acmefolio, AcmeDB, OrderBookSimulator
            for sp in {n[:1].upper() + n[1:], n[:1].upper() + n[1:].lower(), spellings(split_words(n) or [n])["Camel"]}:
                prose[sp] = title
    prose_re = re.compile(r"(?<![A-Za-z0-9@/._-])(?:" + "|".join(map(re.escape, sorted(prose, key=len, reverse=True)))
                          + r")(?![A-Za-z0-9_/-]|\.[A-Za-z0-9])") if prose else None
    proj_re = re.compile("|".join(re.escape(k) for k in sorted(proj, key=len, reverse=True)) or r"(?!)")  # (?!): never
    # Mixed spellings the styles above miss (AcmeFolio, OPEN-ledger): whole word, any case -> CamelCase.
    loose_words = sorted({tuple(w.lower() for w in (split_words(n) or [n])) for n in names if len(n) >= 3},
                         key=lambda ws: len("".join(ws)), reverse=True)
    loose = ["".join(ws) for ws in loose_words]
    loose_re = re.compile(r"(?<![A-Za-z0-9])(?:" + "|".join(
        r"[-_ ]?".join(map(re.escape, ws)) for ws in loose_words) + r")(?![A-Za-z0-9])", re.I)
    host_re = re.compile(r"\b(?:[A-Za-z0-9-]+\.)*(?:" + "|".join(re.escape(x) for x in sorted(hosts, key=len, reverse=True))
                         + r")\b", re.I) if hosts else None
    owner_re = re.compile(r"(?<![A-Za-z0-9-])(?:" + "|".join(map(re.escape, owner_logins)) + r")(?![A-Za-z0-9-])",
                          re.I) if owner_logins else None
    owner_new = {o.lower(): m.PSEUDO.login(o) for o in owner_logins}
    needles = [x.lower() for x in [*owner_logins, *names, *hosts] if len(x) >= 3]

    def url_fix(mt):
        u = mt.group()
        return SAFE_URL if any(n in u.lower() for n in needles) else u

    def rename(s):
        """Project, homepage and owner names (code-safe: same style in, same style out)."""
        if host_re:
            s = host_re.sub("example.com", s)
        s = proj_re.sub(lambda mt: proj[mt.group()], s)
        s = loose_re.sub(lambda mt: new["lower"] if mt.group().islower() else new["UPPER"] if mt.group().isupper() else camel, s)
        if owner_re:
            s = owner_re.sub(lambda mt: owner_new[mt.group().lower()], s)
        return s

    class ProjAnon(m.Anon):
        def __init__(self, identities):
            keep = {k: v for k, v in identities.items() if k.lower() not in {p.lower() for p in proj}}
            super().__init__(keep)
            people = sorted({k for k in keep if (" " in k.strip() and "@" not in k and len(k) >= 5)
                             or k in getattr(m, "EXTRA_PEOPLE", ())}, key=len, reverse=True)  # job option people
            self.people_re = re.compile(r"(?<![\w])(?:" + "|".join(r"\s+".join(map(re.escape, k.split())) for k in people)
                                        + r")(?![\w])") if people else None
            self.people = {re.sub(r"\s+", " ", k): v for k, v in keep.items() if k in people}
            logins = sorted({k for k in keep if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{2,38}", k)}, key=len, reverse=True)
            self.login_re = re.compile(r"(?<=@)(?:" + "|".join(map(re.escape, logins)) + r")\b|(?<=github\.com/)(?:"
                                       + "|".join(map(re.escape, logins)) + r")\b", re.I) if logins else None
            self.logins = {k.lower(): v for k, v in keep.items() if k in logins}

        def code(self, s):
            """Code-safe replacements for any text file."""
            s = EMAIL_RE.sub(EMAIL, s)
            s = rename(s)
            if self.login_re:
                s = self.login_re.sub(lambda mt: self.logins.get(mt.group().lower(), mt.group()), s)
            if self.people_re:
                s = self.people_re.sub(lambda mt: self.people.get(re.sub(r"\s+", " ", mt.group()), mt.group()), s)
            return s

        def text(self, s):
            """Docs, messages and issues: also links naming the project and every known identity."""
            s = URL_RE.sub(url_fix, s)
            if host_re:
                s = host_re.sub("example.com", s)
            if prose_re:
                s = prose_re.sub(title, s)
            return super().text(self.code(s))

    m.readme_blobs = lambda repo: {"full"}  # tells rewrite() below to run the full pass (the second pass is secrets-only)

    def rewrite(repo, secrets, anon, full):
        full = bool(full)
        stats = {"licenses_removed": set(), "logos": 0, "renamed_paths": 0, "tweaked": 0}
        paths = {}
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
                s = anon.text(s) if (low.endswith(DOC_EXT) or base.startswith("readme")) else anon.code(s)
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

        def blob_cb(blob, _meta):
            data = scrub(blob.data)
            path = paths.get(blob.original_id) if full else None
            if path is not None:
                low = path.lower()
                logo = low.endswith(IMAGE_EXT) and (LOGO_RE.search(low) or loose_re.search(low) or proj_re.search(path))
                text = (not logo and len(data) <= MAX_TEXT and b"\x00" not in data[:8000]
                        and not (low.endswith(".zip") and data[:2] == b"PK"))
                data = clean_file(path, data)
                if text and not low.endswith(NO_TWEAK_EXT):
                    data += b"\n"
                    stats["tweaked"] += 1
            blob.data = data

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
            return rename(ref.decode("utf-8", "surrogateescape")).encode("utf-8", "surrogateescape") if full else ref

        def commit_cb(c, _meta):
            an, cn = c.author_name.decode("utf-8", "replace"), c.committer_name.decode("utf-8", "replace")
            c.author_name, c.author_email = m.PSEUDO.name(an).encode(), EMAIL.encode()
            c.committer_name, c.committer_email = m.PSEUDO.name(cn).encode(), EMAIL.encode()
            if full:
                c.author_date, c.committer_date = m.git_date(c.author_date), m.git_date(c.committer_date)
                c.message = anon.bytes(scrub(c.message))
            else:
                c.message = scrub(c.message)

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
        m.subprocess.run(["git", "config", "--remove-section", "remote.origin"], cwd=repo, capture_output=True)
        for junk in ("FETCH_HEAD", "ORIG_HEAD", "logs"):
            p = os.path.join(repo, junk)
            m.rmtree(p) if os.path.isdir(p) else (os.path.exists(p) and os.remove(p))
        m.run(["git", "reflog", "expire", "--expire=now", "--all"], cwd=repo)
        m.run(["git", "-c", "pack.threads=1", "gc", "--prune=now", "--quiet"], cwd=repo)
        if full:
            m.log(f"full pass: {stats['tweaked']} text files changed, {stats['logos']} logos/screenshots replaced, "
                  f"{stats['renamed_paths']} paths renamed, {stats.get('zips', 0)} zip archives cleaned")
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
