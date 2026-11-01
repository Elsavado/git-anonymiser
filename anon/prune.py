"""Deletes the plain issues (not the imported pull requests) from finished anonymised repos.

Env: GH_TOKEN (owner's token), JOB (encrypted JSON list of "owner/repo"), JOB_KEY, BUDGET_MIN.
A repo whose issues changed in the last IDLE_H hours is still importing and is skipped (its import would
re-create deleted issues as "missing"); it is tried again by the next run. Logs show counts only: every repo
name is masked. Writes "more=true" to GITHUB_OUTPUT while repos are left."""
import calendar
import json
import os
import subprocess
import sys
import time

TOK = os.environ["GH_TOKEN"]
BUDGET = float(os.environ.get("BUDGET_MIN", "330")) * 60
IDLE_H = 3
PR_LABEL = "pull request"
T0 = time.time()


def mask(v):
    for x in {v, v.lower()}:
        print(f"::add-mask::{x}", flush=True)


def job():
    p = subprocess.run(["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-a", "-A", "-pass", "env:JOB_KEY"],
                       input=os.environ["JOB"].strip().encode(), capture_output=True)
    if p.returncode != 0:
        sys.exit("the job could not be decrypted")
    return json.loads(p.stdout)


def gql(query, variables=None):
    """GraphQL call through gh; waits on rate limits. Returns (data, error)."""
    body = json.dumps({"query": query, "variables": variables or {}})
    for attempt in range(1, 31):
        p = subprocess.run(["gh", "api", "graphql", "--input", "-"], input=body.encode(), capture_output=True,
                           env={**os.environ, "GH_TOKEN": TOK})
        out = json.loads(p.stdout or b"{}") if p.stdout.strip().startswith(b"{") else {}
        err = (p.stderr.decode() + json.dumps(out.get("errors") or "")).lower()
        if p.returncode == 0 and not out.get("errors"):
            return out.get("data"), None
        if "rate limit" in err or "abuse" in err or "secondary" in err or "502" in err or "timeout" in err:
            time.sleep(min(60 * attempt, 600))
            continue
        return None, err[-200:]
    return None, "gave up after repeated rate limits"


LIST = """query($o: String!, $n: String!, $c: String) { repository(owner: $o, name: $n) { updatedAt
  issues(first: 100, after: $c, orderBy: {field: CREATED_AT, direction: DESC}) {
    pageInfo { hasNextPage endCursor } nodes { id labels(first: 20) { nodes { name } } } } } }"""
DELETE = "mutation($id: ID!) { deleteIssue(input: {issueId: $id}) { clientMutationId } }"


def prune(repo):
    """'done', 'busy' (still importing) or 'time' (budget reached). Prints counts only."""
    owner, name = repo.split("/")
    ids, cur, updated = [], None, None
    while True:
        d, err = gql(LIST, {"o": owner, "n": name, "c": cur})
        if not d or not d.get("repository"):
            print(f"  could not list ({err or 'not found'})")
            return "done"
        r = d["repository"]
        updated = updated or r["updatedAt"]
        iss = r["issues"]
        ids += [x["id"] for x in iss["nodes"] if PR_LABEL not in {lb["name"] for lb in x["labels"]["nodes"]}]
        if not iss["pageInfo"]["hasNextPage"]:
            break
        cur = iss["pageInfo"]["endCursor"]
    age = time.time() - calendar.timegm(time.strptime(updated, "%Y-%m-%dT%H:%M:%SZ"))
    if ids and age < IDLE_H * 3600:
        print(f"  {len(ids)} issues, but the repo changed {age / 60:.0f} min ago (import running?): later")
        return "busy"
    print(f"  {len(ids)} plain issues to delete")
    if os.environ.get("DRY") == "1":
        return "done"
    gone = 0
    for i, iid in enumerate(ids):
        if time.time() - T0 > BUDGET:
            print(f"  {gone} deleted; time budget reached")
            return "time"
        _, err = gql(DELETE, {"id": iid})
        if err is None:
            gone += 1
        time.sleep(1.0)  # pace the mutations (secondary limits)
        if (i + 1) % 500 == 0:
            print(f"  {gone}/{len(ids)} deleted")
    print(f"  {gone}/{len(ids)} deleted")
    return "done"


def main():
    repos = job()
    for r in repos:
        mask(r)
        mask(r.split("/")[1])
    left = []
    for i, r in enumerate(repos, 1):
        if time.time() - T0 > BUDGET:
            left += repos[i - 1:]
            break
        print(f"repo {i}/{len(repos)}", flush=True)
        res = prune(r)
        if res != "done":
            left.append(r)
        if res == "time":
            left += repos[i:]
            break
    print(f"{len(repos) - len(left)} repos finished, {len(left)} left")
    with open(os.environ.get("GITHUB_OUTPUT", os.devnull), "a") as f:
        f.write(f"more={'true' if left else 'false'}\n")
    if left:  # the next run gets only what is left
        enc = subprocess.run(["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-a", "-A", "-pass", "env:JOB_KEY"],
                             input=json.dumps(left).encode(), capture_output=True, check=True).stdout.decode()
        with open("next-job.txt", "w") as f:
            f.write(enc.strip())


if __name__ == "__main__":
    main()
