"""README trimming (user rule 2026-11-04): a README keeps only practical, informative content -- what the code does,
how to install, configure, run, build, test and use it (every technical section stays). These go: badges, logos and banners, licence,
contributing, sponsors, donations, community and social links, acknowledgements, star history, contributor walls,
citations, contact. Any sentence calling the project open source (or free software / MIT-licensed etc.) is removed
from every documentation file. Deterministic: the same input always gives the same output."""
import re

# sections whose heading names one of these are dropped (with their sub-sections); every other section stays.
# Whole words only, so "authorization", "credit risk", "compression", "contacts" or "reporting" are never hit.
DROP = re.compile(r"^\W*why\b|\bwhat'?s next\b|^\W*(resources|links|useful links|more|see also|support|help|"
                  r"feedback|faq and support|get help|getting help|community|team|authors?|credits?|thanks|"
                  r"maintainers?|contact|contact us|news|press|blog|showcase|users|used by|who uses.*|"
                  r"related projects|similar projects|alternatives|roadmap|changelog|release notes|history|"
                  r"disclaimer|legal|trademarks?|copyright|governance|translations?|stats|statistics|"
                  r"star history|stargazers|contributors|backers|sponsors|partners|pricing|testimonials)\W*$|"
                  r"\blicen[cs](e|es|ing|ed)\b|\bcontribut(e|ing|ions?|ors?)\b|\bsponsor(s|ship|ing)?\b|"
                  r"\bdonat(e|ion|ions)\b|\bsupport (us|the project|this project|the development|development)\b|"
                  r"\bbuy me\b|\bpatreon\b|\bopen ?collective\b|\bbackers?\b|\bfunding\b|\bjoin (us|our|the)\b|"
                  r"\bdiscord\b|\bslack\b|\btelegram\b|\btwitter\b|\bsocial\b|\bfollow us\b|\backnowledg(e)?ments?\b|"
                  r"\bspecial thanks\b|\bthank you\b|\bstar history\b|\bcode of conduct\b|\bcitations?\b|\bcite\b|"
                  r"\bciting\b|\bbibtex\b|\bwho (is )?using\b|\bopen ?source\b|\bawesome\b|\bwe'?re hiring\b|"
                  r"\bstar (us|this)\b|\bgive (us|a) star\b|\bsecurity polic(y|ies)\b|\breporting (bugs|issues|"
                  r"security|a vulnerability)\b|\bcommercial (support|license|licence|use)\b|\benterprise edition\b|"
                  r"\bhosted version\b|\bcloud version\b|\bcommunity\b", re.I)

OPEN_SOURCE = re.compile(r"open[ -]?sourc|free (and|&) open|free software|libre software|foss\b|\bfloss\b|"
                         r"(mit|apache|gpl|agpl|lgpl|bsd|mpl)[- ]?(2\.0|v?\d)?[- ]licen[cs]ed|"
                         r"licen[cs]ed under|under the [a-z0-9 .-]+ licen[cs]e|released under|"
                         r"star (us|this repo|the repo)|give (us|it|this) a star|⭐|contributions? (are )?welcome|"
                         r"pull requests? (are )?welcome|community[- ]driven|community[- ]built|"
                         r"sponsor|donat|buy me a coffee|patreon|open ?collective|join (our|the) (discord|slack|community)",
                         re.I)

BADGE_LINE = re.compile(r"^\s*(\[!\[|!\[|<a [^>]*>\s*<img|<img|<p[^>]*>\s*(<a|<img)|<picture|<source|<br\s*/?>|"
                        r"</?(p|div|picture|h[1-6]|center|a|sub|sup|kbd|details|summary)\b[^>]*>\s*$)", re.I)
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
SETEXT = re.compile(r"^(=+|-+)\s*$")
FENCE = re.compile(r"^\s*(```|~~~)")
SENTENCE = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9*_\[`(])")
TAG = re.compile(r"<[^>]+>")


def _sentences_clean(line):
    """Drop the sentences of one prose line that call the project open source (or similar); '' if none is left."""
    if not OPEN_SOURCE.search(line):
        return line
    lead = re.match(r"^(\s*(?:[-*+]|\d+[.)])?\s*)", line).group(1)
    body = line[len(lead):]
    kept = [s for s in SENTENCE.split(body) if not OPEN_SOURCE.search(s)]
    return (lead + " ".join(kept)).rstrip() if kept else ""


def strip_open_source(text):
    """Every documentation file: prose sentences calling the project open source go; code blocks stay as they are."""
    out, fence = [], False
    for line in text.split("\n"):
        if FENCE.match(line):
            fence = not fence
            out.append(line)
            continue
        if fence:
            if OPEN_SOURCE.search(line):   # a code comment calling it open source loses the comment
                cut = re.sub(r"\s*(#|//|--|;)\s.*$", "", line)
                if cut.strip() and not OPEN_SOURCE.search(cut):
                    out.append(cut)
                elif OPEN_SOURCE.search(cut):
                    out.append(line)
                continue
            out.append(line)
            continue
        new = _sentences_clean(line)
        if new or not line.strip():
            out.append(new)
    return _squeeze("\n".join(out))


def _squeeze(text):
    text = re.sub(r"(?m)^[ 	]+$", "", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip("\n") + "\n" if text.strip() else ""


def _sections(lines):
    """[(level, heading text, [lines])]; level 0 = text before the first heading."""
    secs, cur, fence = [], [0, "", []], False
    i = 0
    while i < len(lines):
        line = lines[i]
        if FENCE.match(line):
            fence = not fence
        if not fence:
            m = HEADING.match(line)
            nxt = lines[i + 1] if i + 1 < len(lines) else ""
            if m:
                secs.append(cur)
                cur = [len(m.group(1)), TAG.sub("", m.group(2)), [line]]
                i += 1
                continue
            if line.strip() and not line.lstrip().startswith(("-", "*", "|", ">", "<", "!", "[")) and SETEXT.match(nxt) \
                    and len(nxt.strip()) >= 3:
                secs.append(cur)
                cur = [1 if nxt.strip()[0] == "=" else 2, line.strip(), [line, nxt]]
                i += 2
                continue
        cur[2].append(line)
        i += 1
    secs.append(cur)
    return [s for s in secs if s[0] or any(x.strip() for x in s[2])]


def _decorations_gone(lines):
    out, fence = [], False
    for line in lines:
        if FENCE.match(line):
            fence = not fence
        if not fence and BADGE_LINE.match(line):
            rest = TAG.sub("", _unlink_line(line)).strip()
            if len(re.findall(r"[A-Za-z]{2,}", rest)) >= 4:   # prose after the badges: keep the prose
                out.append(rest)
            continue
        out.append(line)
    return out


def trim_readme(text, path=""):
    """A README reduced to its informative sections (Markdown); other formats only lose open-source wording."""
    low = path.lower()
    if not (low.endswith((".md", ".mdx", ".markdown")) or "." not in low.rsplit("/", 1)[-1]):
        return strip_open_source(text)
    secs = _sections(text.replace("\r\n", "\n").split("\n"))
    out, title_done, drop_level = [], False, None
    for level, head, lines in secs:
        if level == 0:
            out += _decorations_gone(lines)
            continue
        if drop_level is not None:
            if level > drop_level:
                continue          # sub-section of a dropped section
            drop_level = None
        if DROP.search(head.strip(" *_`:#")):
            drop_level = level
            continue
        out += _decorations_gone(lines)
    result = strip_open_source("\n".join(out))
    return result if result.strip() else strip_open_source(text)  # never leave an empty README


# ---- links (user rule 2026-11-04: "remove any links") ----
LOCAL = r"(?:https?://)?(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(?::\d+)?[^\s)\]>\"'`]*"
URL = re.compile(r"(?:https?://|ftp://|www\.)[^\s<>()\[\]\"'`]+(?:\([^\s()]*\)[^\s<>()\[\]\"'`]*)*", re.I)
IMG_MD = re.compile(r"!\[[^\]]*\]\([^)]*\)|!\[[^\]]*\]\[[^\]]*\]")
LINK_MD = re.compile(r"\[([^\]]*)\]\((?:[^()]|\([^()]*\))*\)")
LINK_REF = re.compile(r"\[([^\]]+)\]\[[^\]]*\]")
REF_DEF = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*\S+.*$")
A_TAG = re.compile(r"<a\b[^>]*>(.*?)</a>", re.I | re.S)
IMG_TAG = re.compile(r"<img\b[^>]*>", re.I)
AUTO = re.compile(r"<(?:https?|ftp|mailto):[^>]+>", re.I)
MAILTO = re.compile(r"mailto:\S+", re.I)
CODE_SPAN = re.compile(r"`+[^`]+`+")
HAS_LINK = re.compile(r"`_|\.\. _|image::|figure::|\]\(|\]\[|https?://|ftp://|www\.|mailto:|<a\b|<img\b", re.I)
LINK_ONLY_ITEM = re.compile(r"^\s*([-*+]|\d+[.)])\s*(\*\*|__)?\[[^\]]*\]\((?:[^()]|\([^()]*\))*\)(\*\*|__)?\s*$")


def _is_local(u):
    return re.match(LOCAL, u, re.I) is not None and re.match(LOCAL, u, re.I).group() == u


RST_LINK = re.compile(r"`([^`<]+?)\s*<[^>`]+>`_{1,2}")
RST_DEF = re.compile(r"^\s*\.\. (_[^:]+:|\|[^|]+\|\s*(image|replace)::|image::|figure::)\s*\S*")


def _unlink_line(line):
    line = RST_LINK.sub(lambda mt: mt.group(1), line)
    line = IMG_TAG.sub("", IMG_MD.sub("", line))
    line = A_TAG.sub(lambda mt: TAG.sub("", mt.group(1)), line)
    line = LINK_MD.sub(lambda mt: mt.group(1), line)
    line = LINK_REF.sub(lambda mt: mt.group(1), line)
    line = AUTO.sub("", line)
    line = MAILTO.sub("", line)
    line = URL.sub(lambda mt: mt.group() if _is_local(mt.group()) else "", line)
    line = re.sub(r"\(\s*\)|<\s*>", "", line)
    line = re.sub(r"[ \t]{2,}", " ", line).rstrip()
    line = re.sub(r"\s+([,.;:])", r"\1", line) if line.strip() else line
    return line


def strip_links(text):
    """Every link goes: Markdown/HTML links keep their text, images, link definitions and bare URLs disappear.
    localhost addresses stay as plain text (they are instructions, not links). Inside code blocks a line that
    carries a non-local URL is left out."""
    out, fence, block, skip_opts = [], False, [], False
    for line in text.split("\n"):
        if FENCE.match(line):
            if not fence:
                fence, block = True, [line]
            else:
                fence = False
                body = block[1:]
                if any(b.strip() for b in body):
                    out += block + [line]
            continue
        if fence:
            if not any(not _is_local(u) for u in URL.findall(line)):
                block.append(line)
            continue
        if REF_DEF.match(line) or LINK_ONLY_ITEM.match(line):
            continue
        if RST_DEF.match(line):
            skip_opts = True      # an rst image / link target and its indented options go
            continue
        if skip_opts and re.match(r"^\s+:\w[\w-]*:", line):
            continue
        skip_opts = False
        if not HAS_LINK.search(line):
            out.append(line)
            continue
        if any(not _is_local(u) for span in CODE_SPAN.findall(line) for u in URL.findall(span)):
            continue              # an inline command that needs a link (e.g. a clone URL): the line goes
        new = _unlink_line(line)
        if not line.strip():
            out.append("")
        elif new.strip() and not re.fullmatch(r"\s*([-*+]|\d+[.)]|>|\|[\s|:-]*)\s*", new):
            out.append(new)
    if fence:
        out += block
    return _squeeze("\n".join(out))


HTML_MEDIA = re.compile(r"<(picture|source|img|video|svg)\b[^>]*?>|</(picture|video|svg)\s*>", re.I | re.S)
HTML_A = re.compile(r"<a\b[^>]*?>|</a\s*>", re.I | re.S)
HTML_ALIGN = re.compile(r"<(p|div|h[1-6])\b[^>]*?\balign=[^>]*?>", re.I | re.S)


def _html_gone(text):
    """Multi-line HTML image / picture / anchor tags (common at the top of READMEs) go before line work."""
    parts = re.split(r"(?m)(^\s*(?:```|~~~).*$)", text)
    fence, out = False, []
    for part in parts:
        if re.match(r"^\s*(```|~~~)", part):
            fence = not fence
            out.append(part)
        elif fence:
            out.append(part)
        else:
            out.append(HTML_ALIGN.sub("", HTML_A.sub("", HTML_MEDIA.sub("", part))))
    return "".join(out)


def clean_doc(text, path):
    """README: informative sections only, no open-source wording, no links. Other docs: no open-source wording,
    no links. Returns the original text when cleaning would leave nothing."""
    base = path.lower().rsplit("/", 1)[-1]
    if not base.startswith("readme") and not base.endswith((".md", ".mdx", ".markdown", ".rst", ".adoc")):
        return text   # code, requirements.txt, CMakeLists.txt etc. are never touched
    if base.startswith("readme"):
        new = strip_links(trim_readme(_html_gone(text), base))
    else:
        new = strip_links(strip_open_source(_html_gone(text)))
    if not new.strip() or re.sub(r"\s+", "", new) == re.sub(r"\s+", "", text):
        return text   # nothing left, or only spacing changed: leave the file alone
    return new
