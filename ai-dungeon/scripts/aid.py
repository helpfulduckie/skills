#!/usr/bin/env python3
"""
aid — AI Dungeon GraphQL CLI with auto-refreshing tokens

Scenarios, search, details, resources — and seamless token refresh via
Firebase's REST API so you never have to paste a token again.

Usage:
  export AID_TOKEN='firebase <jwt>'     # quick one-off
  aid token import '<jwt>' '<refresh>'  # store for auto-refresh
  aid token status                      # check expiry
  aid token extract                     # how to get tokens from browser
  aid resources                         # your credit/scale balances

  aid trending                            # trending this week
  aid trending --sfw --days 1             # hot today, Everyone+Teen only
  aid search "vampire romance" --nsfw     # keyword search, Mature+Unrated only
  aid mine                                # your scenarios (published + drafts)
  aid mine --drafts                       # just your unpublished drafts
  aid creator LewdLeah                    # another creator's published scenarios
  aid popular --no-official               # popular, minus platform-promoted accounts
  aid --json trending                     # raw JSON

  aid popular --limit 10                       # all-time popular
  aid popular --sfw --days 30                  # top SFW of last month
  aid popular --tag romance fantasy            # popular scenarios tagged BOTH
  aid analyze popular --deep                   # aggregate analysis w/ card counts

  aid details <shortId>     # scenario details + plot components
  aid cards <shortId>       # list a scenario's story cards
  aid cards <shortId> --md  # export cards as skill markdown
  aid tree <shortId>        # Multiple Choice branch tree
  aid export <shortId>      # dump setup + cards to JSON (handles MC/CC)

  aid create --title "My Scenario" --prompt @opening.txt         # create a new scenario
  aid duplicate <shortId>                                        # copy a scenario into your library
  aid update <shortId> --description @desc.txt                   # edit a scenario you own
  aid update <shortId> --type multipleChoice                     # convert scenario type
  aid scripts <shortId> --shared-library @lib.js                 # edit scripts (only sends what changes)
  aid options <shortId> --count 2                                # add child option branches
  aid card <shortId> --title "Orc" --type race --value @orc.txt  # create a story card
  aid card <shortId> --id 12345 --cc                             # edit one story card (mark for char creation)
  aid add-cards <shortId> cards.json                             # add cards from a file (keeps existing)
  aid import-cards <shortId> cards.json --yes                    # REPLACE all cards from a file
  aid delete <shortId> --yes                                     # delete a scenario/branch you own
  aid restore <shortId>                                          # undo a delete

  aid mc build worlds.json                                       # compile a layered MC tree (offline)
  aid mc sync worlds.json --yes                                  # build/update that tree on your account

  aid keys "elf"                      # generate trigger keys for a word
  aid convert cards.json              # convert cards JSON <-> markdown
  aid tags fantasy romance darkhumor  # lint tags against AID rules
"""

import argparse
import base64
import json
import os
import random
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

try:
    import requests
except ImportError:
    requests = None


def _invocation():
    """How this CLI was invoked, for help/usage text: `aid` if installed on PATH,
    otherwise `python <path-as-run>` so examples are copy-pasteable as-is."""
    arg0 = sys.argv[0] or "aid.py"
    if os.path.basename(arg0) in ("aid", "aid.exe"):
        return "aid"
    return f"python {arg0}"


PROG = _invocation()


# ─── Firebase Config ─────────────────────────────────────────────────────────
# Extracted from play.aidungeon.com env
FIREBASE_API_KEY = "AIzaSyCnvo_XFPmAabrDkOKBRpbivp5UH8r_3mg"
FIREBASE_PROJECT = "aidungeon-2c6cc"
# A valid AI Dungeon id token carries this issuer. Checking it on import catches a
# token that's been truncated or mangled (e.g. markdown formatting applied to the
# pasted text) even when the payload still happens to base64-decode.
EXPECTED_ISSUER = f"https://securetoken.google.com/{FIREBASE_PROJECT}"
FIREBASE_TOKEN_URL = f"https://securetoken.googleapis.com/v1/token?key={FIREBASE_API_KEY}"
# The Firebase API key is HTTP-referer restricted; refreshes without a matching
# Referer header are rejected ("Requests from referer <empty> are blocked").
FIREBASE_REFERER = "https://play.aidungeon.com/"
GRAPHQL_API = "https://api.aidungeon.com/graphql"
TOKEN_REFRESH_BUFFER = 5 * 60  # refresh if <5 min from expiry
TOKEN_STORE = Path.home() / ".config" / "aid-cli" / "tokens.json"


def require_requests():
    """Return requests, or exit with setup guidance for networked commands."""
    if requests is None:
        print("Networked commands need 'requests'. Install with: pip install requests", file=sys.stderr)
        sys.exit(1)
    return requests


# ─── Token Store ─────────────────────────────────────────────────────────────

def token_store_path():
    return TOKEN_STORE


def load_token_store():
    """Load stored tokens. Returns dict or None."""
    p = token_store_path()
    if p.exists():
        try:
            return json.loads(p.read_text())
        except (json.JSONDecodeError, OSError):
            return None
    return None


def save_token_store(data):
    """Write tokens to store file."""
    p = token_store_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2))


def clear_token_store():
    """Delete the token store file."""
    p = token_store_path()
    if p.exists():
        p.unlink()


def decode_jwt_payload(token):
    """Decode the payload portion of a JWT without verification."""
    try:
        # Strip 'firebase ' prefix if present
        t = token
        if t.startswith("firebase "):
            t = t[9:]
        # JWT has 3 dot-separated parts
        payload = t.split(".")[1]
        # Add padding
        payload += "=" * (4 - len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return None


def token_expiry_from_jwt(token):
    """Extract 'exp' claim from a JWT. Returns epoch seconds or None."""
    payload = decode_jwt_payload(token)
    if payload and "exp" in payload:
        return payload["exp"]
    return None


def format_time_left(epoch_secs):
    """Format remaining time in a human-readable way."""
    remaining = epoch_secs - time.time()
    if remaining < 0:
        return "EXPIRED"
    mins = int(remaining // 60)
    secs = int(remaining % 60)
    if mins >= 60:
        hours = mins // 60
        mins = mins % 60
        return f"{hours}h {mins}m"
    return f"{mins}m {secs}s"


# ─── Token Refresh ───────────────────────────────────────────────────────────

def refresh_id_token(refresh_token):
    """
    Exchange a Firebase refresh token for a new ID token via the REST API.
    Returns { id_token, refresh_token, expires_in, user_id } or raises.
    """
    req = require_requests()
    resp = req.post(
        FIREBASE_TOKEN_URL,
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        },
        headers={"Referer": FIREBASE_REFERER},
        timeout=15,
    )
    if not resp.ok:
        detail = resp.json().get("error", {}).get("message", resp.text)
        raise RuntimeError(f"Token refresh failed: {detail}")
    data = resp.json()
    # The API returns a new refresh token too — use it for next refresh
    return {
        "id_token": data["id_token"],
        "refresh_token": data.get("refresh_token", refresh_token),
        "expires_in": int(data.get("expires_in", 3600)),
        "user_id": data.get("user_id"),
    }


def resolve_token(args):
    """
    Resolve a usable Firebase JWT (with 'firebase ' prefix) from:
    1. --token flag (highest priority, no store update)
    2. AID_TOKEN env var
    3. Token store (auto-refreshes if needed)
    """
    # Explicit token overrides store entirely
    explicit = args.token or os.environ.get("AID_TOKEN", "")
    if explicit:
        t = explicit.strip()
        if not t.startswith("firebase "):
            t = f"firebase {t}"
        return t

    # Try stored token with auto-refresh
    store = load_token_store()
    if not store or "id_token" not in store:
        print("  ✗ No token available.", file=sys.stderr)
        print("    Pass one with --token or AID_TOKEN env.", file=sys.stderr)
        print(f"    Or import one for auto-refresh: {PROG} token import '<jwt>' [refresh_token]", file=sys.stderr)
        sys.exit(1)

    id_token = store["id_token"]
    refresh_tok = store.get("refresh_token")
    exp = store.get("expires_at") or token_expiry_from_jwt(id_token)

    # Auto-refresh if close to expiry and we have a refresh token
    if exp and exp - time.time() < TOKEN_REFRESH_BUFFER and refresh_tok:
        print("  ↻ Token expiring soon, refreshing...", file=sys.stderr)
        try:
            result = refresh_id_token(refresh_tok)
            new_exp = time.time() + result["expires_in"]
            store["id_token"] = result["id_token"]
            store["refresh_token"] = result["refresh_token"]
            store["expires_at"] = new_exp
            store["last_refreshed"] = time.time()
            save_token_store(store)
            id_token = result["id_token"]
            print(f"  ✓ Refreshed — valid for {result['expires_in'] // 60} min", file=sys.stderr)
        except RuntimeError as e:
            print(f"  ✗ {e}", file=sys.stderr)
            print("  ⚠ Falling back to stored token (may be expired)", file=sys.stderr)

    return f"firebase {id_token}"


# ─── GraphQL ─────────────────────────────────────────────────────────────────

GRAPHQL_HEADERS = {
    "Content-Type": "application/json",
    "x-client-version": "1.0.0",
}


def gql(token, query, variables=None, op_name="OpenSearch"):
    """Execute a GraphQL query and return parsed data."""
    req = require_requests()
    headers = {
        **GRAPHQL_HEADERS,
        "Authorization": token,
        "x-gql-operation-name": op_name,
    }
    payload = {"query": query, "variables": variables or {}}
    r = req.post(GRAPHQL_API, json=payload, headers=headers, timeout=15)
    data = r.json()
    if "errors" in data:
        for e in data["errors"]:
            print(f"  ✗ {e['message']}", file=sys.stderr)
        sys.exit(1)
    return data["data"]


# ─── Queries ─────────────────────────────────────────────────────────────────

SEARCH_QUERY = """\
query OpenSearch($input: SearchInput!) {
  search(input: $input) {
    items {
      id contentType publicId shortId title description image tags
      voteCount published publishedAt createdAt saveCount commentCount
      contentRating adventuresPlayed
      user { id username isMember profile { title thumbImageUrl } }
    }
    total hasMore took
  }
}"""

SCENARIO_QUERY = """\
query GetScenarioDetails($shortId: String, $viewPublished: Boolean) {
  scenario(shortId: $shortId, viewPublished: $viewPublished) {
    id shortId title description advancedDescription image
    isOwner published tags adventuresPlayed thirdPerson
    nsfw contentRating voteCount saveCount storyCardCount commentCount
    state(viewPublished: $viewPublished) {
      prompt plotEssentials authorsNote instructions storySummary
    }
    user { id username isMember profile { title thumbImageUrl } }
  }
}"""

STORY_CARDS_QUERY = """\
query GetScenarioStoryCards($shortId: String, $viewPublished: Boolean) {
  scenario(shortId: $shortId, viewPublished: $viewPublished) {
    id shortId title storyCardCount isOwner
    state(viewPublished: $viewPublished) {
      storyCards {
        id title type keys value description useForCharacterCreation
      }
    }
  }
}"""

# MC scenarios nest child scenarios under `options` (recursive). Each option is a
# full Scenario, so we walk a few levels deep to reveal the branch tree.
OPTIONS_QUERY = """\
query GetScenarioOptions($shortId: String, $viewPublished: Boolean) {
  scenario(shortId: $shortId, viewPublished: $viewPublished) {
    id shortId title type storyCardCount
    state(viewPublished: $viewPublished) { prompt }
    options {
      id shortId title type storyCardCount deletedAt
      state { prompt }
      options {
        id shortId title type storyCardCount deletedAt
        state { prompt }
        options {
          id shortId title type storyCardCount deletedAt
          state { prompt }
        }
      }
    }
  }
}"""

RESOURCES_QUERY = """\
query GetResources {
  user { id resources {
    creditsBalance { currentBalance }
    scalesBalance { currentBalance }
    promoActionsBalance { currentBalance }
  }}
}"""

# The authenticated user. The JWT carries a Google name/email, not the AID handle,
# so resolve the username here to default `mine` to the current user.
ME_QUERY = """\
query Me { user { id username } }"""

# Everything needed to dump a single scenario: setup (plot components + meta) and
# its attached story cards, in one query.
EXPORT_QUERY = """\
query GetScenarioExport($shortId: String, $viewPublished: Boolean) {
  scenario(shortId: $shortId, viewPublished: $viewPublished) {
    id shortId title description tags thirdPerson nsfw contentRating type storyCardCount
    state(viewPublished: $viewPublished) {
      prompt plotEssentials authorsNote instructions storySummary
      storyCards {
        id title type keys value description useForCharacterCreation
      }
    }
  }
}"""

# Read side of the read-modify-write update flow. Returns every field the
# UpdateScenario mutation expects, so an edit changes one field and sends the rest
# back unchanged (the API replaces the whole object — omitting a field clears it).
SCENARIO_EDIT_QUERY = """\
query GetScenarioForEdit($shortId: String, $viewPublished: Boolean) {
  scenario(shortId: $shortId, viewPublished: $viewPublished) {
    id shortId isOwner title description tags contentRating
    thirdPerson allowComments image type scriptsEnabled
    state(viewPublished: $viewPublished) {
      scenarioId type prompt plotEssentials authorsNote instructions
      storySummary storyCardInstructions storyCardStoryInformation scenarioStateVersion
      storyCards { id updatedAt title type keys value description useForCharacterCreation }
      scripts { onInput onOutput onModelContext sharedLibrary }
    }
  }
}"""

UPDATE_SCENARIO_MUTATION = """\
mutation UpdateScenario($input: ScenarioInput) {
  updateScenario(input: $input) {
    scenario { id shortId title editedAt }
    message
    success
  }
}"""

# Creates `count` child option scenarios under a parent. The UI uses this both to
# turn a scenario into a Multiple Choice / Character Creator branch and to add
# sub-options deeper in the tree. Children are full scenarios (own shortId) edited
# via UpdateScenario.
CREATE_OPTIONS_MUTATION = """\
mutation CreateScenarioOptions($title: String, $shortId: String, $count: Int) {
  createScenarioOptions(title: $title, shortId: $shortId, count: $count) {
    scenarios { id shortId title parentScenarioId }
    success
    message
  }
}"""

UPDATE_STORY_CARD_MUTATION = """\
mutation UseUpdateStoryCard($input: UpdateStoryCardInput!) {
  updateStoryCard(input: $input) {
    success
    message
    storyCard { id type title description keys value useForCharacterCreation updatedAt }
  }
}"""

DELETE_STORY_CARD_MUTATION = """\
mutation UseDeleteStoryCard($input: DeleteStoryCardInput!) {
  deleteStoryCard(input: $input) {
    success
    message
    storyCard { id deletedAt }
  }
}"""

DELETE_SCENARIO_MUTATION = """\
mutation MainMenuViewDeleteScenario($shortId: String) {
  deleteScenario(shortId: $shortId) {
    scenario { id shortId title parentScenarioId deletedAt }
    success
    message
  }
}"""

# Creates a brand-new scenario. Takes the same ScenarioInput as UpdateScenario;
# the minimal shape the web client sends is { title, details: { prompt } }.
CREATE_SCENARIO_MUTATION = """\
mutation NewMenuCreateScenario($input: ScenarioInput) {
  createScenario(input: $input) {
    success
    message
    scenario { id shortId title }
  }
}"""

# Copies an existing scenario into the caller's library — works on scenarios you
# don't own (how the "Copy of …" scenarios get made), so no ownership guard.
DUPLICATE_SCENARIO_MUTATION = """\
mutation UseDuplicateScenario($shortId: String) {
  duplicateScenario(shortId: $shortId) {
    success
    message
    scenario { id shortId title }
  }
}"""

# Restores a soft-deleted scenario (undoes `deleteScenario`, which only sets deletedAt).
RESTORE_SCENARIO_MUTATION = """\
mutation UseRestoreScenario($shortId: String) {
  restoreScenario(shortId: $shortId) {
    success
    message
    scenario { id shortId title deletedAt }
  }
}"""

# Scripts-only update. gameCode merges — send just the scripts you're changing and
# the rest are preserved (verified), so no need to round-trip the whole scenario or
# the (often huge) sharedLibrary you aren't touching.
UPDATE_SCRIPTS_MUTATION = """\
mutation UpdateScenarioScripts($shortId: String, $gameCode: JSONObject) {
  updateScenarioScripts(shortId: $shortId, gameCode: $gameCode) {
    success
    message
    scenario { id state { scripts { onInput onOutput onModelContext sharedLibrary } } }
  }
}"""

# Bulk story-card import. DESTRUCTIVE: replaces the scenario's entire card set with
# the provided list (verified — not an append). Cards take no id; the server mints them.
IMPORT_STORY_CARDS_MUTATION = """\
mutation ImportStoryCards($input: ImportStoryCardsInput!) {
  importStoryCards(input: $input) {
    success
    message
    storyCards { title type }
  }
}"""

SCENARIO_TYPES = ["simple", "multipleChoice", "characterCreator"]


# ─── Story Card Utilities ────────────────────────────────────────────────────

# Default field values for a story card. Fields matching these are omitted from
# the markdown json block (and re-supplied when parsing markdown back to JSON).
CARD_DEFAULTS = {
    "type": "character",
    "description": "",
    "useForCharacterCreation": False,
}


def build_keys(keys, key):
    """
    Port of AI Dungeon's buildKeys(). Given an existing comma-separated `keys`
    string and a new `key`, returns a keys string with space/punctuation variants
    that trigger reliably without bleeding into longer words. Caps at <101 chars.

    - Short keys (<6 chars) get leading+trailing space/punct guards on both sides.
    - Medium keys (6-8) get one-sided guards.
    - Long keys (9+) are used bare (unique enough to not collide).
    """
    key = re.sub(r"\s+", " ", key.strip())
    keyset = []
    if key == "":
        return keys
    elif keys.strip() != "":
        keyset.extend(keys.split(","))
        lower_key = key.lower()
        for i in range(len(keyset) - 1, -1, -1):
            pre_key = re.sub(r"\s+", " ", keyset[i].strip()).lower()
            if pre_key == "" or lower_key in pre_key:
                keyset.pop(i)
    if len(key) < 6:
        keyset.extend([
            " " + key + " ", " " + key + "'", '"' + key + " ", " " + key + ".",
            " " + key + "?", " " + key + "!", " " + key + ";", "'" + key + " ",
            "(" + key + " ", " " + key + ")", " " + key + ":", " " + key + '"',
            "[" + key + " ", " " + key + "]", "—" + key + " ", " " + key + "—",
            "{" + key + " ", " " + key + "}",
        ])
    elif len(key) < 9:
        keyset.extend([
            key + " ", " " + key, key + "'", '"' + key, key + ".", key + "?",
            key + "!", key + ";", "'" + key, "(" + key, key + ")", key + ":",
            key + '"', "[" + key, key + "]", "—" + key, key + "—", "{" + key, key + "}",
        ])
    else:
        keyset.append(key)
    result = keyset[0] if keyset else key
    i = 1
    while i < len(keyset) and (len(result) + 1 + len(keyset[i])) < 101:
        result += "," + keyset[i]
        i += 1
    return result


def cards_to_markdown(cards):
    """
    Convert a list of story-card dicts to the skill's markdown format:

        ### Title
        ```json
        { "keys": "...", "type": "..." }
        ```

        <value text>

        ---

    The json block holds only non-default metadata (keys that differ from the
    auto-generated set, plus type/description/useForCharacterCreation when not
    default). Title becomes the header; value becomes the body. Empty blocks are
    omitted entirely.
    """
    blocks = []
    for card in cards:
        title = (card.get("title") or "").strip()
        value = card.get("value") or card.get("entry") or ""
        keys = card.get("keys") or ""

        # Determine which metadata to surface in the json block.
        meta = {}
        auto_keys = build_keys("", title) if title else ""
        if keys.strip() and keys.strip() != auto_keys.strip():
            meta["keys"] = keys
        for field in ("type", "description", "useForCharacterCreation"):
            if field in card and card[field] != CARD_DEFAULTS[field]:
                meta[field] = card[field]

        header = f"### {title}" if title else "### (untitled)"
        parts = [header]
        if meta:
            parts.append("```json")
            parts.append(json.dumps(meta, indent=2, ensure_ascii=False))
            parts.append("```")
        if value:
            parts.append("")
            parts.append(value.strip())
        blocks.append("\n".join(parts))
    return "\n\n---\n\n".join(blocks) + "\n"


def markdown_to_cards(md):
    """
    Parse the skill's markdown card format back into a list of story-card dicts.
    The json block is optional; when absent, keys auto-generate from the title and
    type defaults to 'character'. Sections are split on '### ' headers (the '---'
    separators are cosmetic and ignored).
    """
    cards = []
    # Split on headers; keep the title with each section.
    sections = re.split(r"(?m)^###\s+", md)
    for section in sections:
        section = section.strip()
        if not section:
            continue
        lines = section.split("\n")
        title = lines[0].strip()
        rest = "\n".join(lines[1:])

        # Extract an optional ```json ... ``` block.
        meta = {}
        json_match = re.search(r"```json\s*(.*?)```", rest, re.DOTALL)
        if json_match:
            try:
                meta = json.loads(json_match.group(1))
            except json.JSONDecodeError:
                print(f"  ⚠ Bad json block in card '{title}', ignoring it", file=sys.stderr)
            rest = rest[:json_match.start()] + rest[json_match.end():]

        # Whatever remains (minus stray '---') is the value/body.
        body = re.sub(r"(?m)^---\s*$", "", rest).strip()

        card = {
            "keys": meta.get("keys") or build_keys("", title),
            "value": body,
            "type": meta.get("type", CARD_DEFAULTS["type"]),
            "title": title,
            "description": meta.get("description", CARD_DEFAULTS["description"]),
            "useForCharacterCreation": meta.get(
                "useForCharacterCreation", CARD_DEFAULTS["useForCharacterCreation"]
            ),
        }
        cards.append(card)
    return cards


# ─── Tag Validation ──────────────────────────────────────────────────────────

# Curated examples from Yuki's tagging guide, by category. Spaces are fine in modern tags,
# so these read as natural phrases. Don't spend a tag on the default second-person POV.
TAG_SUGGESTIONS = {
    "genre (max 2)": ["fantasy", "sci fi", "romance", "horror", "isekai", "mystery",
                       "comedy", "historical", "slice of life", "superhero", "thriller"],
    "themes (as needed)": ["redemption", "betrayal", "coming of age", "found family",
                            "identity", "revenge", "power fantasy", "forbidden love",
                            "tragedy", "dark humor"],
    "setting (max 3)": ["medieval", "modern", "futuristic", "urban", "dystopia",
                        "space", "dreamworld", "virtual reality", "academy",
                        "underworld", "forest realm"],
    "tone (1-3)": ["comedic", "dramatic", "romantic", "dark", "serious", "silly",
                   "sad", "mysterious", "wholesome", "edgy"],
    "style": ["first person", "third person", "journal format",
              "quest based", "sandbox", "multiple povs", "nonlinear", "scripted"],
    "custom features": ["custom stats", "dice rolls", "inventory", "companion",
                        "quest log", "skill checks", "player choice", "event triggers",
                        "system messages"],
}


def lint_tags(tags):
    """
    Validate tags against AI Dungeon's rules. Returns (cleaned, issues) where `issues`
    is a list of human-readable warnings. Modern tags allow spaces and ordinary
    punctuation ("slice of life" is one tag), so the only hard rule is the 10-tag limit.
    Tags are case-insensitive, so they're normalized to lowercase; internal whitespace is
    collapsed and ends trimmed.
    """
    issues = []
    cleaned = []
    if len(tags) > 10:
        issues.append(f"✗ {len(tags)} tags — the limit is 10. Drop {len(tags) - 10}.")
    for tag in tags:
        fixed = re.sub(r"\s+", " ", tag).strip()
        if not fixed:
            continue
        if fixed != fixed.lower():
            issues.append(f"⚠ '{tag}' has uppercase — tags are case-insensitive; using '{fixed.lower()}'.")
            fixed = fixed.lower()
        cleaned.append(fixed)
    return cleaned, issues



# ─── Plot Component Profiling ────────────────────────────────────────────────

def profile_scenario(s):
    """
    Classify a scenario's plot-component strategy from its state. Returns a short
    label describing the dominant design pattern, mirroring the skill's analysis.
    """
    state = s.get("state") or {}
    prompt = (state.get("prompt") or "").strip()
    pe = (state.get("plotEssentials") or "").strip()
    an = (state.get("authorsNote") or "").strip()
    instr = state.get("instructions") or {}
    if isinstance(instr, dict):
        instr_text = (instr.get("scenario") or "").strip()
    else:
        instr_text = str(instr or "").strip()
    cards = s.get("storyCardCount", 0)
    has_placeholders = "${" in prompt or "${" in pe

    if s.get("type") == "options" or (not pe and not an and not instr_text and not prompt):
        return "MC-navigation (content on leaves)"
    if has_placeholders and cards == 0:
        if pe and "${" in pe:
            return "placeholder-template (player defines world via PE)"
        return "placeholder-driven (customization wizard)"
    if cards >= 100 and not pe:
        return "card-bible (world lives in cards)"
    if cards > 0 and not pe and len(an) < 60:
        return "sandbox (cards + minimal steering)"
    if instr_text and not cards:
        return "instruction-driven (rules-heavy, no cards)"
    return "mixed"


# ─── Search Filter Helpers ───────────────────────────────────────────────────

RATING_MAP = {
    "everyone": "Everyone", "teen": "Teen", "mature": "Mature", "unrated": "Unrated",
}
ALL_RATINGS = ["Mature", "Unrated", "Teen", "Everyone"]

# Platform-promoted accounts. The official `aidungeon` account authors the default
# starter scenarios (Original Quickstart has 56M+ plays) and a stable of example
# scenarios that dominate the top of the popular list; --no-official drops them so
# you can see genuine community standings.
OFFICIAL_CREATORS = {"aidungeon"}


def filter_creators(items, args):
    """
    Filter search items by author username (case-insensitive). --by keeps only the
    named creators; --exclude / --no-official drop them. Returns (kept, removed_count).
    """
    by = {u.lower() for u in (getattr(args, "by", None) or [])}
    exclude = {u.lower() for u in (getattr(args, "exclude_user", None) or [])}
    if getattr(args, "no_official", False):
        exclude |= OFFICIAL_CREATORS
    if not by and not exclude:
        return items, 0
    kept = []
    for it in items:
        uname = ((it.get("user") or {}).get("username") or "").lower()
        if by and uname not in by:
            continue
        if uname in exclude:
            continue
        kept.append(it)
    return kept, len(items) - len(kept)


def creator_filter_note(removed):
    """Header suffix noting how many items a creator filter dropped from the page."""
    return f"  |  {removed} filtered by creator" if removed else ""


def resolve_ratings(args, default_all=True):
    """Map --rating / --sfw / --nsfw flags to the API's contentRatingFilters list."""
    if getattr(args, "sfw", False):
        return ["Teen", "Everyone"]
    if getattr(args, "nsfw", False):
        return ["Mature", "Unrated"]
    rating = getattr(args, "rating", None)
    if not rating or "all" in rating:
        return ALL_RATINGS if default_all else ["Teen", "Everyone"]
    return [RATING_MAP[r] for r in rating]


def apply_search_filters(fields, args, default_time=None):
    """
    Apply shared --rating and --days flags onto a search `fields` dict.
    default_time is the timeRange to use when --days isn't given (None = all-time).
    Then apply any raw --filters overrides last.
    """
    fields["contentRatingFilters"] = resolve_ratings(args)
    days = getattr(args, "days", None)
    time_range = days if days is not None else default_time
    if time_range is not None:
        fields["timeRange"] = str(time_range)
    elif "timeRange" in fields:
        del fields["timeRange"]
    if getattr(args, "tag", None):
        fields["tags"] = [t.strip().lower() for t in args.tag]
    if getattr(args, "filters", None):
        for f in args.filters:
            k, _, v = f.partition("=")
            fields[k.strip()] = json.loads(v.strip())
    return fields


def add_search_filter_args(p, with_days=True):
    """Attach shared rating/days and creator-filter flags to a subparser."""
    rating_group = p.add_mutually_exclusive_group()
    rating_group.add_argument("--rating", nargs="+",
                   choices=["everyone", "teen", "mature", "unrated", "all"],
                   help="Content ratings to include (default: all)")
    rating_group.add_argument("--sfw", action="store_true",
                   help="Everyone+Teen only (alias for --rating everyone teen)")
    rating_group.add_argument("--nsfw", action="store_true",
                   help="Mature+Unrated only (alias for --rating mature unrated)")
    if with_days:
        p.add_argument("--days",
                       help="Time range in days (e.g. 7, 30; omit for all-time / default window)")
    p.add_argument("--by", nargs="+", metavar="USER",
                   help="Keep only scenarios by these creators (case-insensitive)")
    p.add_argument("--exclude", nargs="+", metavar="USER", dest="exclude_user",
                   help="Drop scenarios by these creators (case-insensitive)")
    p.add_argument("--no-official", action="store_true", dest="no_official",
                   help=f"Drop platform-official accounts ({', '.join(sorted(OFFICIAL_CREATORS))})")
    p.add_argument("--tag", nargs="+", metavar="TAG",
                   help="Only scenarios carrying ALL these tags (lowercased; server-side filter)")


def add_view_flag(p):
    """
    Attach the --published view toggle. Inspection commands default to the working
    draft (viewPublished=False) — what the editor shows and what edits operate on;
    --published opts into the live snapshot. (No effect for scenarios you don't own;
    those only ever return the published version.)
    """
    p.add_argument("--published", action="store_true",
                   help="Show the published snapshot instead of your working draft")


# ─── Branch Tree Helpers ─────────────────────────────────────────────────────

def child_nodes(node, seen_ids):
    """
    Return a node's real child branches. `seen_ids` is the set of IDs from root down
    to and including this node.

    `options` is not a child list: it is a flattened list of the node's entire
    subtree, plus the node itself. Three things therefore have to come out of it —
    self-references, ancestors already on the path, and *descendants of siblings*,
    which are grandchildren or deeper rather than children.

    Missing that third case double-counts a layered tree. World Time Generator
    (`CsVRzE8kMGUh`) is three menus of five leaves; its root lists all eighteen
    descendants, so walking them yields the fifteen leaves under the menus plus the
    same fifteen again at root level, and `aid tree` reports thirty.

    A candidate is a grandchild exactly when some other candidate's own subtree
    contains it, which is what the second pass below tests. One level of lookup is
    enough precisely because `options` is already flattened.
    """
    nid = node.get("id")
    kids = []
    for child in (node.get("options") or []):
        cid = child.get("id")
        if child.get("deletedAt"):
            continue
        if cid and cid != nid and cid not in seen_ids:
            kids.append(child)

    subtrees = set()
    for kid in kids:
        kid_id = kid.get("id")
        for descendant in (kid.get("options") or []):
            did = descendant.get("id")
            if did and did != kid_id:
                subtrees.add(did)

    return [k for k in kids if k.get("id") not in subtrees]


def count_leaves(node, seen_ids=None):
    """Count playable leaf branches, with path-based dedup against self/cycles."""
    if seen_ids is None:
        seen_ids = set()
    nid = node.get("id")
    path = seen_ids | ({nid} if nid else set())
    kids = child_nodes(node, path)
    if not kids:
        return 1
    return sum(count_leaves(k, path) for k in kids)


def collect_leaves(node, seen_ids=None, path=None):
    """
    Return a list of (path_titles, leaf_node) for every playable leaf, with the
    same self/cycle dedup as count_leaves. For a plain scenario (no options) this
    returns a single entry: the node itself.
    """
    if seen_ids is None:
        seen_ids = set()
    if path is None:
        path = []
    nid = node.get("id")
    seen = seen_ids | ({nid} if nid else set())
    here = path + [node.get("title") or node.get("shortId") or "?"]
    kids = child_nodes(node, seen)
    if not kids:
        return [(here, node)]
    out = []
    for k in kids:
        out.extend(collect_leaves(k, seen, here))
    return out


# ─── Export Helpers ──────────────────────────────────────────────────────────

def slugify(text, maxlen=60):
    """Filesystem-safe slug from a title."""
    s = re.sub(r"[^\w\s-]", "", (text or "").lower()).strip()
    s = re.sub(r"[\s_]+", "-", s)
    s = re.sub(r"-{2,}", "-", s).strip("-")
    return s[:maxlen] or "untitled"


def extract_setup(s):
    """Pull a scenario's setup (plot components + metadata) into a flat dict."""
    state = s.get("state") or {}
    instr = state.get("instructions") or {}
    instr_text = instr.get("scenario") if isinstance(instr, dict) else instr
    return {
        "title": s.get("title") or "",
        "description": s.get("description") or "",
        "type": s.get("type"),
        "tags": s.get("tags") or [],
        "thirdPerson": s.get("thirdPerson", False),
        "nsfw": s.get("nsfw", False),
        "contentRating": s.get("contentRating") or "",
        "prompt": state.get("prompt") or "",
        "plotEssentials": state.get("plotEssentials") or "",
        "authorsNote": state.get("authorsNote") or "",
        "aiInstructions": instr_text or "",
        "storySummary": state.get("storySummary") or "",
    }


def extract_cards(s):
    """Pull a scenario's story cards into the import-compatible JSON shape."""
    state = s.get("state") or {}
    cards = state.get("storyCards") or []
    out = []
    for c in cards:
        out.append({
            "keys": c.get("keys") or "",
            "value": c.get("value") or "",
            "type": c.get("type") or "character",
            "title": c.get("title") or "",
            "description": c.get("description") or "",
            "useForCharacterCreation": c.get("useForCharacterCreation", False),
        })
    return out


# ─── Update Helpers ──────────────────────────────────────────────────────────

def read_value(v):
    """
    Resolve a flag value. A leading '@' means "read from this file" so long text
    (scripts, plot essentials) can be passed without shell-escaping. Returns None
    unchanged so callers can treat None as "flag not given".
    """
    if v is None:
        return None
    if v.startswith("@"):
        return Path(v[1:]).read_text(encoding="utf-8")
    return v


# Conventional filenames for `update --scripts-dir`, mapping a file in the
# directory to its scripts.* input field. Matches the four AID script tabs.
SCRIPT_FILES = {
    "onInput": "input.js",
    "onOutput": "output.js",
    "onModelContext": "context.js",
    "sharedLibrary": "library.js",
}


def new_card_id(existing_ids):
    """
    Mint a story-card id for creation, mirroring the web client exactly. There's no
    separate createStoryCard — the editor generates the id itself and upserts via
    updateStoryCard. From the bundle: `id: Math.floor(1e9*Math.random()).toString()`,
    i.e. a uniform integer in [0, 1e9). We add a per-scenario collision check the
    client skips (the upsert is scoped by shortId, so this only needs local uniqueness).
    """
    while True:
        cid = str(random.randrange(10**9))
        if cid not in existing_ids:
            return cid


def script_value(flag_val, scripts_dir, field):
    """
    Resolve one script's new value. An explicit flag (with @file support) wins;
    otherwise fall back to the conventionally-named file in scripts_dir if present.
    Returns None when neither is given, so the script is left unchanged.
    """
    v = read_value(flag_val)
    if v is not None:
        return v
    if scripts_dir:
        f = Path(scripts_dir) / SCRIPT_FILES[field]
        if f.exists():
            return f.read_text(encoding="utf-8")
    return None


def build_scenario_update_input(s):
    """
    Build a full ScenarioInput from a scenario fetched via SCENARIO_EDIT_QUERY,
    round-tripping every field UpdateScenario replaces. Callers mutate the result
    to apply edits; anything left untouched is sent back as-is. The field set
    mirrors what the web client sends — no more, no less.
    """
    state = s.get("state") or {}

    cards = []
    for c in (state.get("storyCards") or []):
        cards.append({
            "id": c.get("id"),
            "updatedAt": c.get("updatedAt"),
            "keys": c.get("keys") or "",
            "value": c.get("value") or "",
            "type": c.get("type") or "character",
            "title": c.get("title") or "",
            "description": c.get("description") or "",
            "useForCharacterCreation": c.get("useForCharacterCreation", False),
        })

    scripts_src = state.get("scripts") or {}
    scripts = {
        "onInput": scripts_src.get("onInput") or "",
        "onOutput": scripts_src.get("onOutput") or "",
        "onModelContext": scripts_src.get("onModelContext") or "",
        "sharedLibrary": scripts_src.get("sharedLibrary") or "",
    }

    details = {
        "scenarioId": state.get("scenarioId"),
        "type": state.get("type"),
        "prompt": state.get("prompt") or "",
        "authorsNote": state.get("authorsNote") or "",
        "plotEssentials": state.get("plotEssentials") or "",
        "storyCards": cards,
        "instructions": state.get("instructions") if state.get("instructions") is not None else {},
        "storySummary": state.get("storySummary") or "",
        "storyCardInstructions": state.get("storyCardInstructions") or "",
        "storyCardStoryInformation": state.get("storyCardStoryInformation") or "",
        "scenarioStateVersion": state.get("scenarioStateVersion"),
        "scripts": scripts,
    }

    return {
        "shortId": s.get("shortId"),
        "title": s.get("title") or "",
        "description": s.get("description") or "",
        "tags": s.get("tags") or [],
        "contentRating": s.get("contentRating") or "Unrated",
        "thirdPerson": s.get("thirdPerson", False),
        "allowComments": s.get("allowComments", True),
        "image": s.get("image") or "",
        "type": s.get("type"),
        "scriptsEnabled": s.get("scriptsEnabled", True),
        "details": details,
    }


def _diff_preview(val, width=70):
    """One-line, length-aware preview of a field value for the change summary."""
    if isinstance(val, list):
        return "[" + ", ".join(str(x) for x in val) + "]"
    s = str(val).replace("\n", "⏎")
    if len(s) > width:
        return f"{s[:width]}… ({len(val)} chars)"
    return s


# ─── Multiple Choice Layer Builder ───────────────────────────────────────────
# Build a Multiple Choice tree from a single layered spec. AID's MC tree gives
# non-leaf nodes zero effect on play and zero inheritance to children, so a
# "each layer adds cards + plot essentials" model only works if every accumulated
# choice is baked into each leaf. These helpers compile the layers into the full
# per-leaf content; `mc sync` then writes that tree to AID.

def normalize_card(c):
    """One story card in import shape, with keys auto-built from the title if absent. A
    compile-time `when` condition is preserved (stripped later, before the card is sent)."""
    title = c.get("title") or ""
    out = {
        "keys": c.get("keys") or build_keys("", title),
        "value": c.get("value") or c.get("entry") or "",
        "type": c.get("type") or "character",
        "title": title,
        "description": c.get("description") or "",
        "useForCharacterCreation": bool(c.get("useForCharacterCreation")),
    }
    if c.get("when"):
        out["when"] = c["when"]
    return out


def merge_text(parts):
    """Join non-empty text fragments with blank lines, in order (broad → specific)."""
    return "\n\n".join(p.strip() for p in parts if p and p.strip())


def merge_cards(card_lists):
    """Union story cards across layers, deduped by title (later layers win); order kept."""
    out = []
    index = {}
    for cards in card_lists:
        for c in cards:
            key = (c.get("title") or "").strip().lower()
            if key and key in index:
                out[index[key]] = c
            else:
                if key:
                    index[key] = len(out)
                out.append(c)
    return out


# ─── Flags and conditions (the layered-spec macro system) ────────────────────
# Options can set `flags` that accumulate down the root→leaf path; cards and text
# fragments can carry a `when` condition tested against those accumulated flags. This
# lets early layers set state (context size, race) that later layers consume to decide
# which lore cards / plot-essentials fragments a leaf gets, and at what detail.

def accumulate_flags(chosen):
    """Merge each chosen option's `flags` dict in path order; later layers win on collision."""
    flags = {}
    for o in chosen:
        f = o.get("flags")
        if isinstance(f, dict):
            flags.update(f)
    return flags


def when_matches(when, flags):
    """True when every key in `when` matches the accumulated flags. A value is a scalar
    (equality) or a list (membership); keys AND together. Absent/empty `when` always matches.
    No negation by design — gate content by inclusion, not exclusion."""
    if not isinstance(when, dict) or not when:
        return True
    for key, allowed in when.items():
        actual = flags.get(key)
        choices = allowed if isinstance(allowed, list) else [allowed]
        if actual not in choices:
            return False
    return True


def resolve_text_parts(value, flags):
    """Expand a text field into its included fragments. A field is either a plain string
    (always included) or a list whose items are strings or `{text, when}` objects gated by
    flags. Returns a list of strings for merge_text."""
    if not value:
        return []
    if isinstance(value, str):
        return [value]
    parts = []
    for item in value:
        if isinstance(item, str):
            parts.append(item)
        elif isinstance(item, dict) and when_matches(item.get("when"), flags):
            parts.append(item.get("text", ""))
    return parts


def strip_when(card):
    """A copy of the card without its compile-time `when` key, so it never reaches the API."""
    if "when" in card:
        return {k: v for k, v in card.items() if k != "when"}
    return card


def collect_flag_keys(layers):
    """All flag keys any option declares — the set a `when` may legitimately reference."""
    keys = set()
    for layer in layers:
        for opt in (layer.get("options") or []):
            f = opt.get("flags")
            if isinstance(f, dict):
                keys.update(f.keys())
    return keys


def collect_when_keys(value):
    """Every flag key referenced by a `when` block anywhere in a spec value (structural walk)."""
    found = set()

    def visit(v):
        if isinstance(v, dict):
            if isinstance(v.get("when"), dict):
                found.update(v["when"].keys())
            for vv in v.values():
                visit(vv)
        elif isinstance(v, list):
            for vv in v:
                visit(vv)

    visit(value)
    return found


def spec_cards(node, spec_dir):
    """Resolve a spec node's cards: inline `cards` plus an optional `cardsFile` (relative
    to the spec file). Both preserve a `when` condition for compile-time gating."""
    cards = [normalize_card(c) for c in (node.get("cards") or [])]
    cf = node.get("cardsFile")
    if cf:
        cards += load_cards_file(str(spec_dir / cf), keep_when=True)
    return cards


def load_spec(path):
    """Load and lightly validate a layer spec. Returns (spec, spec_dir)."""
    p = Path(path)
    if not p.exists():
        print(f"  ✗ Spec not found: {path}", file=sys.stderr)
        sys.exit(1)
    try:
        spec = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"  ✗ Spec isn't valid JSON: {e}", file=sys.stderr)
        sys.exit(1)
    layers = spec.get("layers")
    if not layers or not isinstance(layers, list):
        print("  ✗ Spec needs a non-empty 'layers' array.", file=sys.stderr)
        sys.exit(1)
    for i, layer in enumerate(layers):
        if not layer.get("options"):
            print(f"  ✗ Layer {i} ('{layer.get('name', i)}') has no options.", file=sys.stderr)
            sys.exit(1)

    # Catch the silent failure mode: a `when` that names a flag no option ever sets will
    # never match, so its card/fragment vanishes from every leaf. Warn rather than fail.
    declared = collect_flag_keys(layers)
    referenced = collect_when_keys(spec.get("leaf")) | collect_when_keys(layers)
    nodes = [spec.get("leaf")] + [o for layer in layers for o in (layer.get("options") or [])]
    for node in nodes:
        cf = (node or {}).get("cardsFile")
        if not cf:
            continue
        cfp = p.parent / cf
        try:
            data = json.loads(cfp.read_text(encoding="utf-8"))
            referenced |= collect_when_keys(data)
        except (OSError, json.JSONDecodeError):
            pass
    unknown = referenced - declared
    if unknown:
        print(f"  ⚠ when-conditions reference flag(s) no option sets: "
              f"{', '.join(sorted(unknown))}. Those conditions never match — check for typos.",
              file=sys.stderr)
    return spec, p.parent


def compile_leaf(spec, chosen, spec_dir):
    """Compile one accumulated root→leaf path of chosen options into a leaf's setup + cards.

    Flags from every chosen option accumulate first; then text fragments and cards carrying a
    `when` are kept only if they match those flags. Text fields concatenate (base, then each
    option in path order); cards union (later layers win on title). Returns (setup, cards, flags).
    """
    flags = accumulate_flags(chosen)
    leaf = spec.get("leaf") or {}
    sources = [leaf] + list(chosen)

    def field(name):
        parts = []
        for src in sources:
            parts.extend(resolve_text_parts(src.get(name, ""), flags))
        return merge_text(parts)

    setup = {
        "type": leaf.get("type") or "simple",
        "prompt": field("prompt"),
        "plotEssentials": field("plotEssentials"),
        "authorsNote": field("authorsNote"),
        "aiInstructions": field("aiInstructions"),
    }

    raw = []
    for src in sources:
        raw.extend(spec_cards(src, spec_dir))
    kept = [strip_when(c) for c in raw if when_matches(c.get("when"), flags)]
    cards = merge_cards([kept])
    return setup, cards, flags


def build_tree_plan(spec, spec_dir):
    """Expand the layered spec into a full branch-tree plan (root node returned).

    Every root→leaf path is a distinct combination of one option per layer; the leaf
    carries the union of all chosen options' cards and the concatenation of their text.
    Internal nodes are navigation menus framed by their layer's prompt.
    """
    layers = spec["layers"]

    def rec(depth, chosen):
        if depth == len(layers):
            setup, cards, flags = compile_leaf(spec, chosen, spec_dir)
            return {"leaf": True, "setup": setup, "cards": cards, "flags": flags}
        layer = layers[depth]
        node = {"leaf": False, "prompt": layer.get("prompt", ""),
                "layer": layer.get("name") or f"layer{depth}", "children": []}
        for opt in layer["options"]:
            child = rec(depth + 1, chosen + [opt])
            child["title"] = opt.get("title") or "(untitled)"
            node["children"].append(child)
        return node

    root = rec(0, [])
    root["title"] = spec.get("title") or "Untitled"
    return root


def plan_stats(node):
    """(menu_nodes, leaves, total_cards) over a compiled plan."""
    if node.get("leaf"):
        return 0, 1, len(node.get("cards") or [])
    ni, nl, nc = 1, 0, 0
    for child in node["children"]:
        a, b, c = plan_stats(child)
        ni += a
        nl += b
        nc += c
    return ni, nl, nc


def print_plan(node, prefix="", is_last=True, depth=0):
    """Render the compiled plan as a tree, with per-leaf card/PE sizes."""
    if depth == 0:
        ni, nl, nc = plan_stats(node)
        print(f"\n  {node['title']}  (root menu)")
        print(f"      {nl} leaves  |  {ni} menu nodes  |  {nc} cards across leaves")
        kids = node["children"]
        for i, child in enumerate(kids):
            print_plan(child, "  ", i == len(kids) - 1, depth + 1)
        return
    connector = "└─ " if is_last else "├─ "
    if node.get("leaf"):
        pe = len(node["setup"]["plotEssentials"])
        nc = len(node.get("cards") or [])
        flags = node.get("flags") or {}
        flag_str = ("  {" + " ".join(f"{k}={v}" for k, v in flags.items()) + "}") if flags else ""
        print(f"  {prefix}{connector}{node['title']}  ◆ leaf  [{nc} cards, {pe} PE chars]{flag_str}")
    else:
        print(f"  {prefix}{connector}{node['title']}  (menu)")
        child_prefix = prefix + ("   " if is_last else "│  ")
        kids = node["children"]
        for i, child in enumerate(kids):
            print_plan(child, child_prefix, i == len(kids) - 1, depth + 1)


def write_plan_export(node, out_dir):
    """Write the compiled plan as an export-style directory (one setup+cards per leaf)."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    used = set()

    def unique(name):
        base = name or "leaf"
        n = base
        i = 2
        while n in used:
            n = f"{base}-{i}"
            i += 1
        used.add(n)
        return n

    written = []

    def walk(n, path):
        if n.get("leaf"):
            name = unique(slugify("__".join(path) or n.get("title") or "leaf"))
            (out / f"{name}.setup.json").write_text(
                json.dumps(n["setup"], indent=2, ensure_ascii=False), encoding="utf-8")
            written.append(f"{name}.setup.json")
            if n.get("cards"):
                (out / f"{name}.cards.json").write_text(
                    json.dumps(n["cards"], indent=2, ensure_ascii=False), encoding="utf-8")
                written.append(f"{name}.cards.json")
            return
        for child in n["children"]:
            walk(child, path + [child["title"]])

    walk(node, [])
    return out, written


def print_items(items, show_tags=True, show_status=False):
    if not items:
        print("  (no results)")
        return
    for i, item in enumerate(items, 1):
        title = item["title"] or "(untitled)"
        user = item["user"]["username"] if item.get("user") else "?"
        plays = item.get("adventuresPlayed", 0)
        votes = item.get("voteCount", 0)
        saves = item.get("saveCount", 0)
        rating = item.get("contentRating") or "?"
        desc = (item.get("description") or "")[:140]
        short_id = item.get("shortId") or "?"
        status = (("published" if item.get("published") else "draft") + "  |  ") if show_status else ""

        print(f"\n  {'─' * 50}")
        print(f"  {i:>2}. {title}")
        print(f"      {short_id}  |  {status}by {user}  |  {rating}  |  {plays} plays  |  {votes} votes  |  {saves} saves")
        if desc:
            print(f"      {desc}")
        tags = item.get("tags") or []
        if show_tags and tags:
            print(f"      tags: {'  '.join(tags[:6])}")
    print()


# ─── Commands ────────────────────────────────────────────────────────────────

def cmd_trending(args):
    token = resolve_token(args)
    fields = apply_search_filters({
        "contentType": ["scenario"],
        "sortOrder": "trending",
        "contentFilters": ["published"],
        "screen": "discover",
        "limit": args.limit,
        "offset": args.offset,
    }, args, default_time="7")

    data = gql(token, SEARCH_QUERY, {"input": fields})
    result = data["search"]
    items, removed = filter_creators(result["items"], args)

    if args.json:
        print(json.dumps({**result, "items": items}, indent=2))
        return

    window = fields.get("timeRange", "7")
    print(f"\n  ╔═══ Trending Scenarios ({window}-day window) ═══╗")
    print(f"  ║  {result['total']} total  |  {'more pages' if result['hasMore'] else 'all shown'}  |  {result['took']}ms")
    print(f"  ║  ratings: {', '.join(fields['contentRatingFilters'])}{creator_filter_note(removed)}")
    print(f"  ╚{'═' * 44}")
    print_items(items)


def cmd_popular(args):
    token = resolve_token(args)
    fields = apply_search_filters({
        "contentType": ["scenario"],
        "sortOrder": "popular",
        "contentFilters": ["published"],
        "screen": "discover",
        "limit": args.limit,
        "offset": args.offset,
    }, args, default_time=None)

    data = gql(token, SEARCH_QUERY, {"input": fields})
    result = data["search"]
    items, removed = filter_creators(result["items"], args)

    if args.json:
        print(json.dumps({**result, "items": items}, indent=2))
        return

    window = fields.get("timeRange")
    window_str = f"{window}-day window" if window else "all-time"
    print(f"\n  ╔═══ Popular Scenarios ({window_str}) ═══╗")
    print(f"  ║  {result['total']} total  |  {'more pages' if result['hasMore'] else 'all shown'}  |  {result['took']}ms")
    print(f"  ║  ratings: {', '.join(fields['contentRatingFilters'])}{creator_filter_note(removed)}")
    print(f"  ╚{'═' * 44}")
    print_items(items)


def cmd_search(args):
    token = resolve_token(args)
    query = " ".join(args.query)
    fields = apply_search_filters({
        "contentType": ["scenario"],
        "sortOrder": "trending",
        "contentFilters": ["published"],
        "screen": "discover",
        "searchTerm": query,
        "limit": args.limit,
        "offset": args.offset,
    }, args, default_time=None)

    data = gql(token, SEARCH_QUERY, {"input": fields})
    result = data["search"]
    items, removed = filter_creators(result["items"], args)

    if args.json:
        print(json.dumps({**result, "items": items}, indent=2))
        return

    print(f"\n  ╔═══ Search: \"{query}\" ═══╗")
    print(f"  ║  {result['total']} total  |  {result['took']}ms  |  ratings: {', '.join(fields['contentRatingFilters'])}{creator_filter_note(removed)}")
    print(f"  ╚{'═' * (len(query) + 20)}")
    print_items(items)


def current_username(token):
    """Resolve the authenticated user's AID handle (not in the JWT)."""
    u = (gql(token, ME_QUERY, op_name="Me").get("user") or {}).get("username")
    if not u:
        print("  ✗ Couldn't resolve your username from the token.", file=sys.stderr)
        sys.exit(1)
    return u


def profile_fields(username, limit, offset):
    """Base SearchInput for a creator's profile listing (newest first)."""
    return {
        "contentType": ["scenario"],
        "sortOrder": "updated",
        "thirdPerson": False,
        "safe": False,
        "contentRatingFilters": ALL_RATINGS,
        "username": username,
        "screen": "profile",
        "limit": limit,
        "offset": offset,
    }


def print_profile(result, username, scope, show_status):
    items = result["items"]
    more = "  |  more (use --offset)" if result.get("hasMore") else ""
    print(f"\n  ╔═══ {username}'s scenarios ({scope}) ═══╗")
    print(f"  ║  {len(items)} shown{more}  |  sorted by last updated")
    print(f"  ╚{'═' * 44}")
    print_items(items, show_status=show_status)


def cmd_mine(args):
    token = resolve_token(args)
    username = current_username(token)
    fields = profile_fields(username, args.limit, args.offset)
    # Omitting `published` returns both; setting it filters to one side.
    scope = "all"
    if args.published:
        fields["published"] = True
        scope = "published"
    elif args.drafts:
        fields["published"] = False
        scope = "drafts"

    result = gql(token, SEARCH_QUERY, {"input": fields})["search"]
    if args.json:
        print(json.dumps(result, indent=2))
        return
    print_profile(result, username, scope, show_status=(scope == "all"))


def cmd_creator(args):
    token = resolve_token(args)
    # Only a creator's published scenarios are visible to others.
    fields = profile_fields(args.username, args.limit, args.offset)
    fields["contentFilters"] = ["published"]

    result = gql(token, SEARCH_QUERY, {"input": fields})["search"]
    if args.json:
        print(json.dumps(result, indent=2))
        return
    print_profile(result, args.username, "published", show_status=False)


def cmd_details(args):
    token = resolve_token(args)
    data = gql(
        token,
        SCENARIO_QUERY,
        {"shortId": args.short_id, "viewPublished": args.published},
        op_name="GetScenarioDetails",
    )
    s = data["scenario"]
    if not s:
        print(f"  ✗ Scenario '{args.short_id}' not found")
        sys.exit(1)

    if args.json:
        print(json.dumps(s, indent=2))
        return

    state = s.get("state") or {}
    prompt = (state.get("prompt") or "")[:400]

    print(f"\n  ╔═══ Scenario: {s['title']} ═══╗")
    print(f"  ║  by {s['user']['username']}")
    print(f"  ║  shortId: {s['shortId']}  |  id: {s['id']}")
    print(f"  ║  {s.get('adventuresPlayed', 0)} plays  |  {s.get('voteCount', 0)} votes  |  {s.get('saveCount', 0)} saves")
    print(f"  ║  {s.get('storyCardCount', 0)} story cards  |  rating: {s.get('contentRating', '?')}")
    print(f"  ║  NSFW: {s.get('nsfw', False)}  |  3rd person: {s.get('thirdPerson', False)}")
    print(f"  ║  Published: {s.get('published', False)}")
    print(f"  ╚{'═' * 40}")

    desc = s.get("description", "")
    if desc:
        print(f"\n  Description:\n    {desc}")

    adv = s.get("advancedDescription", "")
    if adv:
        print(f"\n  Advanced Description:\n    {adv[:500]}")

    if prompt:
        print(f"\n  Opening Prompt (first 400 chars):\n    {prompt}…")

    # Plot components, when present
    pe = (state.get("plotEssentials") or "").strip()
    if pe:
        print(f"\n  Plot Essentials:\n    {pe[:400]}")
    an = (state.get("authorsNote") or "").strip()
    if an:
        print(f"\n  Author's Note:\n    {an[:300]}")
    instr = state.get("instructions") or {}
    instr_text = instr.get("scenario") if isinstance(instr, dict) else instr
    if instr_text:
        print(f"\n  AI Instructions:\n    {instr_text[:400]}")

    print(f"\n  Design pattern: {profile_scenario(s)}")

    tags = s.get("tags") or []
    if tags:
        print(f"\n  Tags: {'  '.join(tags[:10])}")
    print()


def cmd_cards(args):
    token = resolve_token(args)
    data = gql(
        token,
        STORY_CARDS_QUERY,
        {"shortId": args.short_id, "viewPublished": args.published},
        op_name="GetScenarioStoryCards",
    )
    s = data["scenario"]
    if not s:
        print(f"  ✗ Scenario '{args.short_id}' not found")
        sys.exit(1)

    state = s.get("state") or {}
    cards = state.get("storyCards") or []
    count = s.get("storyCardCount", 0)

    # Markdown export mode
    if args.md:
        print(cards_to_markdown(cards))
        return
    if args.json:
        print(json.dumps(cards, indent=2, ensure_ascii=False))
        return

    print(f"\n  ╔═══ Story Cards: {s['title']} ═══╗")
    print(f"  ║  {len(cards)} returned  |  {count} total (storyCardCount)")
    print(f"  ╚{'═' * 40}")

    if not cards and count > 0:
        print(f"\n  ⚠ This scenario reports {count} cards but returned none on the root.")
        print(f"    It's almost certainly a Multiple Choice scenario — cards live on the")
        print(f"    leaf branches, not the root. Use:  {PROG} tree {args.short_id}")
        print(f"    then query cards on a specific leaf's shortId.\n")
        return

    # Group by type for readability
    by_type = {}
    for c in cards:
        by_type.setdefault(c.get("type") or "Custom", []).append(c)
    for ctype, group in sorted(by_type.items()):
        print(f"\n  ── {ctype} ({len(group)}) ──")
        for c in group:
            title = c.get("title") or "(no name)"
            keys = c.get("keys") or ""
            value = (c.get("value") or "")[:100]
            cc = " [CC]" if c.get("useForCharacterCreation") else ""
            print(f"    • {title}{cc}")
            print(f"        triggers: {keys}")
            if value:
                print(f"        {value}")
    print()


def _print_tree(node, depth=0, is_last=True, prefix="", seen_ids=None):
    """Recursively print an MC scenario branch tree, with shortIds and self/cycle dedup."""
    if seen_ids is None:
        seen_ids = set()
    nid = node.get("id")
    path = seen_ids | ({nid} if nid else set())

    title = node.get("title") or "(untitled)"
    sid = node.get("shortId") or "?"
    ntype = node.get("type") or "?"
    cards = node.get("storyCardCount", 0)
    kids = child_nodes(node, path)
    is_leaf = not kids

    connector = "└─ " if is_last else "├─ "
    leaf_marker = "  ◆ leaf" if is_leaf else ""
    card_info = f"  [{cards} cards]" if cards else ""
    label = f"{title}  ({ntype})  {sid}{card_info}{leaf_marker}"
    if depth == 0:
        print(f"\n  {title}  ({ntype})  {sid}{card_info}")
    else:
        print(f"  {prefix}{connector}{label}")

    child_prefix = prefix + ("   " if is_last else "│  ") if depth > 0 else "  "
    for i, child in enumerate(kids):
        _print_tree(child, depth + 1, i == len(kids) - 1, child_prefix, path)


def cmd_tree(args):
    token = resolve_token(args)
    data = gql(
        token,
        OPTIONS_QUERY,
        {"shortId": args.short_id, "viewPublished": args.published},
        op_name="GetScenarioOptions",
    )
    s = data["scenario"]
    if not s:
        print(f"  ✗ Scenario '{args.short_id}' not found")
        sys.exit(1)
    if args.json:
        print(json.dumps(s, indent=2, ensure_ascii=False))
        return

    root_kids = child_nodes(s, {s.get("id")})
    if not root_kids:
        print(f"\n  '{s['title']}' has no child options — it's a single scenario,")
        print(f"  not a Multiple Choice tree. Use:  {PROG} details {args.short_id}\n")
        return

    print(f"\n  ╔═══ Branch Tree: {s['title']} ═══╗")
    leaves = count_leaves(s)
    print(f"  ║  {leaves} playable leaf branches  |  shortId: {s.get('shortId', '?')}")
    print(f"  ╚{'═' * 44}")
    _print_tree(s)
    print(f"\n  ◆ = playable leaf (full plot components active)")
    print(f"  Non-leaf nodes are navigation only — their plot components are ignored.")
    print(f"  Query any leaf's cards with:  {PROG} cards <shortId>\n")


def _export_one(token, short_id, view_published=False):
    """Fetch a single scenario's setup + cards. Returns (scenario, setup, cards)."""
    data = gql(token, EXPORT_QUERY,
               {"shortId": short_id, "viewPublished": view_published},
               op_name="GetScenarioExport")
    s = data["scenario"]
    if not s:
        return None, None, None
    return s, extract_setup(s), extract_cards(s)


def cmd_export(args):
    token = resolve_token(args)

    # Walk the tree first to detect MC/Character-Creator structure and find leaves.
    tdata = gql(token, OPTIONS_QUERY,
                {"shortId": args.short_id, "viewPublished": args.published},
                op_name="GetScenarioOptions")
    root = tdata["scenario"]
    if not root:
        print(f"  ✗ Scenario '{args.short_id}' not found")
        sys.exit(1)

    is_mc = bool(child_nodes(root, {root.get("id")}))
    leaves = collect_leaves(root)
    root_slug = slugify(root.get("title") or root.get("shortId"))

    out_dir = Path(args.out) if args.out else Path(f"{root_slug}-export")
    out_dir.mkdir(parents=True, exist_ok=True)

    # Build the list of (name, shortId) targets. For MC, include the root so its
    # framing prompt is preserved, then one entry per leaf (named by branch path).
    targets = []
    used_names = set()

    def unique(name):
        base = name
        i = 2
        while name in used_names:
            name = f"{base}-{i}"
            i += 1
        used_names.add(name)
        return name

    if is_mc:
        targets.append((unique("_root"), root.get("shortId")))
        for path_titles, leaf in leaves:
            # Name from the branch path below the root (e.g. warrior__knight).
            branch = path_titles[1:] if len(path_titles) > 1 else [leaf.get("title") or leaf.get("shortId")]
            targets.append((unique(slugify("__".join(branch))), leaf.get("shortId")))
    else:
        # Plain scenario (incl. Character Creator): just the one.
        targets.append((unique(root_slug), root.get("shortId")))

    written = []
    for name, sid in targets:
        s, setup, cards = _export_one(token, sid, args.published)
        if s is None:
            print(f"  ⚠ couldn't fetch '{sid}', skipping", file=sys.stderr)
            continue

        if not args.cards_only:
            p = out_dir / f"{name}.setup.json"
            p.write_text(json.dumps(setup, indent=2, ensure_ascii=False), encoding="utf-8")
            written.append(p)

        # Only emit a cards file when there actually are cards.
        if not args.setup_only and cards:
            if args.md:
                p = out_dir / f"{name}.cards.md"
                p.write_text(cards_to_markdown(cards), encoding="utf-8")
            else:
                p = out_dir / f"{name}.cards.json"
                p.write_text(json.dumps(cards, indent=2, ensure_ascii=False), encoding="utf-8")
            written.append(p)

        cc = sum(1 for c in cards if c["useForCharacterCreation"])
        cc_note = f", {cc} for character creator" if cc else ""
        label = root.get("title") if name == "_root" else name
        print(f"  ✓ {label}: {len(cards)} cards{cc_note}", file=sys.stderr)

    kind = "Multiple Choice / Character Creator" if is_mc else "single scenario"
    print(f"\n  Exported {kind}: {len(written)} file(s) → {out_dir}/")
    if is_mc:
        print(f"  {len(leaves)} leaf branch(es). Each leaf has its own setup + cards;")
        print(f"  '_root.setup.json' holds the navigation/framing prompt.")
    print()


def cmd_update(args):
    token = resolve_token(args)
    data = gql(token, SCENARIO_EDIT_QUERY,
               {"shortId": args.short_id, "viewPublished": False},
               op_name="GetScenarioForEdit")
    s = data["scenario"]
    if not s:
        print(f"  ✗ Scenario '{args.short_id}' not found", file=sys.stderr)
        sys.exit(1)
    if not s.get("isOwner"):
        print(f"  ✗ You don't own '{s.get('title') or args.short_id}' — can't update it.", file=sys.stderr)
        sys.exit(1)

    inp = build_scenario_update_input(s)
    diffs = []

    def apply(container, key, value, label):
        if value is None:
            return
        old = container.get(key)
        if value != old:
            diffs.append((label, old, value))
            container[key] = value

    det = inp["details"]

    apply(inp, "title", read_value(args.title), "title")
    apply(inp, "description", read_value(args.description), "description")
    apply(inp, "image", read_value(args.image), "image")
    apply(inp, "type", args.scenario_type, "type")
    if args.tags is not None:
        cleaned, issues = lint_tags(args.tags)
        for issue in issues:
            print(f"  {issue}", file=sys.stderr)
        apply(inp, "tags", cleaned, "tags")
    if args.rating is not None:
        apply(inp, "contentRating", RATING_MAP[args.rating], "contentRating")
    if args.third_person is not None:
        apply(inp, "thirdPerson", args.third_person, "thirdPerson")
    if args.allow_comments is not None:
        apply(inp, "allowComments", args.allow_comments, "allowComments")
    if args.scripts_enabled is not None:
        apply(inp, "scriptsEnabled", args.scripts_enabled, "scriptsEnabled")

    apply(det, "prompt", read_value(args.prompt), "prompt")
    apply(det, "plotEssentials", read_value(args.plot_essentials), "plotEssentials")
    apply(det, "authorsNote", read_value(args.authors_note), "authorsNote")
    apply(det, "storySummary", read_value(args.story_summary), "storySummary")

    if not diffs:
        print(f"\n  No changes — every field already matches. Nothing sent.\n")
        return

    print(f"\n  ╔═══ Update: {s.get('title')} ═══╗")
    print(f"  ║  shortId: {s.get('shortId')}  |  {len(diffs)} field(s) changing")
    print(f"  ╚{'═' * 44}")
    for label, old, new in diffs:
        print(f"\n  {label}")
        print(f"    - {_diff_preview(old)}")
        print(f"    + {_diff_preview(new)}")

    payload_bytes = len(json.dumps({"input": inp}).encode("utf-8"))
    print(f"\n  Payload: {payload_bytes / 1024:.0f} KB")

    if args.dry_run:
        print(f"  ⓘ Dry run — nothing sent. Drop --dry-run to apply.\n")
        if args.json:
            print(json.dumps(inp, indent=2, ensure_ascii=False))
        return

    result = gql(token, UPDATE_SCENARIO_MUTATION, {"input": inp},
                 op_name="UpdateScenario")["updateScenario"]
    if result.get("success"):
        print(f"\n  ✓ Updated. {result.get('message') or ''}".rstrip())
        print(f"    editedAt: {(result.get('scenario') or {}).get('editedAt')}\n")
    else:
        print(f"\n  ✗ Update failed: {result.get('message')}\n", file=sys.stderr)
        sys.exit(1)


OWNER_QUERY = """\
query GetScenarioOwner($shortId: String) {
  scenario(shortId: $shortId) { shortId title isOwner type }
}"""


def require_owned(token, short_id):
    """Fetch a scenario and exit unless the caller owns it. Returns the scenario."""
    s = gql(token, OWNER_QUERY, {"shortId": short_id}, op_name="GetScenarioOwner")["scenario"]
    if not s:
        print(f"  ✗ Scenario '{short_id}' not found", file=sys.stderr)
        sys.exit(1)
    if not s.get("isOwner"):
        print(f"  ✗ You don't own '{s.get('title') or short_id}'.", file=sys.stderr)
        sys.exit(1)
    return s


def cmd_options(args):
    token = resolve_token(args)
    parent = require_owned(token, args.short_id)
    result = gql(token, CREATE_OPTIONS_MUTATION,
                 {"shortId": args.short_id, "count": args.count, "title": args.title},
                 op_name="CreateScenarioOptions")["createScenarioOptions"]
    if not result.get("success"):
        print(f"\n  ✗ {result.get('message') or 'createScenarioOptions failed'}\n", file=sys.stderr)
        sys.exit(1)
    made = result.get("scenarios") or []
    print(f"\n  ✓ Created {len(made)} option(s) under '{parent.get('title')}' ({args.short_id})")
    for c in made:
        print(f"    • {c.get('title')}  {c.get('shortId')}")
    print(f"\n  Edit a branch:  {PROG} update <shortId> --prompt ...")
    if parent.get("type") == "simple":
        print(f"  Parent is still 'simple' — set its type with: "
              f"{PROG} update {args.short_id} --type multipleChoice\n")
    else:
        print()


def cmd_mc_build(args):
    spec, spec_dir = load_spec(args.spec)
    plan = build_tree_plan(spec, spec_dir)
    ni, nl, nc = plan_stats(plan)
    print_plan(plan)
    if args.out:
        out, written = write_plan_export(plan, args.out)
        print(f"\n  ✓ Wrote {len(written)} file(s) → {out}/")
    print(f"\n  {nl} playable leaves, each self-contained (layers baked in — AID branches")
    print(f"  don't inherit, so every choice on the path lives on the leaf).")
    print(f"  Push it with:  {PROG} mc sync {args.spec} [--scenario <shortId>] --yes\n")


# Direct child branches of a scenario, for matching the plan against the live tree.
MC_CHILDREN_QUERY = """\
query GetScenarioChildren($shortId: String) {
  scenario(shortId: $shortId, viewPublished: false) {
    id shortId title type
    options { id shortId title type deletedAt }
  }
}"""


def fetch_children(token, short_id):
    """Live (non-deleted) direct child branches of a scenario."""
    s = gql(token, MC_CHILDREN_QUERY, {"shortId": short_id},
            op_name="GetScenarioChildren")["scenario"]
    return [c for c in (s.get("options") or []) if not c.get("deletedAt")]


def build_leaf_cards(compiled, existing):
    """Story-card list for a leaf's full update: reuse id/updatedAt for title-matches,
    mint ids for new cards. Replaces the leaf's whole set so repeated syncs converge."""
    by_title = {}
    for c in existing:
        t = (c.get("title") or "").strip().lower()
        if t:
            by_title.setdefault(t, c)
    seen_ids = {c["id"] for c in existing if c.get("id")}
    out = []
    for c in compiled:
        card = {
            "keys": c["keys"], "value": c["value"], "type": c["type"],
            "title": c["title"], "description": c["description"],
            "useForCharacterCreation": c["useForCharacterCreation"],
        }
        prev = by_title.get((c["title"] or "").strip().lower())
        if prev and prev.get("id"):
            card["id"] = prev["id"]
            if prev.get("updatedAt") is not None:
                card["updatedAt"] = prev["updatedAt"]
        else:
            cid = new_card_id(seen_ids)
            seen_ids.add(cid)
            card["id"] = cid
        out.append(card)
    return out


def push_node(token, short_id, node):
    """Write one plan node to its scenario via a full updateScenario (read-modify-write,
    fork-safe). Internal nodes become multipleChoice menus; leaves get the compiled
    setup + baked-in card set."""
    s = gql(token, SCENARIO_EDIT_QUERY, {"shortId": short_id, "viewPublished": False},
            op_name="GetScenarioForEdit")["scenario"]
    inp = build_scenario_update_input(s)
    det = inp["details"]
    inp["title"] = node["title"]

    if node.get("leaf"):
        setup = node["setup"]
        inp["type"] = det["type"] = setup.get("type") or "simple"
        det["prompt"] = setup["prompt"]
        det["plotEssentials"] = setup["plotEssentials"]
        det["authorsNote"] = setup["authorsNote"]
        if setup.get("aiInstructions"):
            instr = dict(det.get("instructions") or {})
            instr["scenario"] = setup["aiInstructions"]
            det["instructions"] = instr
        det["storyCards"] = build_leaf_cards(node.get("cards") or [], det.get("storyCards") or [])
    else:
        inp["type"] = det["type"] = "multipleChoice"
        det["prompt"] = node["prompt"]

    result = gql(token, UPDATE_SCENARIO_MUTATION, {"input": inp},
                 op_name="UpdateScenario")["updateScenario"]
    if not result.get("success"):
        print(f"  ⚠ update '{node['title']}' ({short_id}) failed: {result.get('message')}",
              file=sys.stderr)
    return result.get("success")


def sync_walk(token, short_id, node, prune, counts):
    """Recursively write the plan to AID, matching existing branches by title (idempotent)."""
    push_node(token, short_id, node)
    counts["updated"] += 1
    if node.get("leaf"):
        counts["leaves"] += 1
        return

    existing = fetch_children(token, short_id)
    by_title = {c["title"]: c for c in existing}

    missing = [child for child in node["children"] if child["title"] not in by_title]
    new_sids = []
    if missing:
        result = gql(token, CREATE_OPTIONS_MUTATION,
                     {"shortId": short_id, "count": len(missing), "title": None},
                     op_name="CreateScenarioOptions")["createScenarioOptions"]
        if not result.get("success"):
            print(f"  ✗ Couldn't create {len(missing)} option(s) under {short_id}: "
                  f"{result.get('message')}", file=sys.stderr)
            sys.exit(1)
        new_sids = [sc["shortId"] for sc in (result.get("scenarios") or [])]
        counts["created"] += len(new_sids)

    mi = 0
    for child in node["children"]:
        if child["title"] in by_title:
            csid = by_title[child["title"]]["shortId"]
        else:
            csid = new_sids[mi]
            mi += 1
        sync_walk(token, csid, child, prune, counts)

    if prune:
        keep = {child["title"] for child in node["children"]}
        for c in existing:
            if c["title"] not in keep:
                gql(token, DELETE_SCENARIO_MUTATION, {"shortId": c["shortId"]},
                    op_name="MainMenuViewDeleteScenario")
                counts["pruned"] += 1


def cmd_mc_sync(args):
    spec, spec_dir = load_spec(args.spec)
    plan = build_tree_plan(spec, spec_dir)
    ni, nl, nc = plan_stats(plan)

    target = args.scenario or "(new scenario)"
    print(f"\n  ╔═══ MC sync: {plan['title']} ═══╗")
    print(f"  ║  target: {target}")
    print(f"  ║  {nl} leaves  |  {ni} menu nodes  |  {nc} cards across leaves")
    if args.prune:
        print(f"  ║  --prune: existing branches not in the spec will be deleted")
    print(f"  ╚{'═' * 44}")
    print_plan(plan)

    if not args.yes:
        verb = "update" if args.scenario else "create a new scenario, then build"
        print(f"\n  This will {verb} {ni} menu node(s) and {nl} leaf branch(es) on your account.")
        print(f"  Re-run with --yes to apply.\n")
        return

    token = resolve_token(args)
    if args.scenario:
        require_owned(token, args.scenario)
        root_sid = args.scenario
    else:
        inp = {"title": plan["title"], "details": {"prompt": plan.get("prompt") or ""}}
        if spec.get("description") is not None:
            inp["description"] = spec["description"]
        if spec.get("tags"):
            cleaned, issues = lint_tags(spec["tags"])
            for issue in issues:
                print(f"  {issue}", file=sys.stderr)
            inp["tags"] = cleaned
        if spec.get("rating"):
            inp["contentRating"] = RATING_MAP[spec["rating"]]
        created = gql(token, CREATE_SCENARIO_MUTATION, {"input": inp},
                      op_name="NewMenuCreateScenario")["createScenario"]
        if not created.get("success"):
            print(f"\n  ✗ {created.get('message') or 'createScenario failed'}\n", file=sys.stderr)
            sys.exit(1)
        root_sid = (created.get("scenario") or {}).get("shortId")
        print(f"  ✓ Created root scenario {root_sid}")

    counts = {"updated": 0, "created": 0, "pruned": 0, "leaves": 0}
    sync_walk(token, root_sid, plan, args.prune, counts)

    print(f"\n  ✓ Synced '{plan['title']}' → {root_sid}")
    pruned = f", {counts['pruned']} pruned" if args.prune else ""
    print(f"    {counts['updated']} node(s) written, {counts['created']} branch(es) created, "
          f"{counts['leaves']} leaf(s){pruned}")
    print(f"    Inspect:  {PROG} tree {root_sid}\n")


def cmd_card(args):
    token = resolve_token(args)

    # Create path: must NOT read scenario state first. On a never-published scenario,
    # querying state(viewPublished:false) right before a single-card upsert makes the
    # new card land only in the published view, not the draft (reproduced 5/5; cause
    # unconfirmed). Verify ownership state-free instead.
    if args.id is None:
        if args.delete:
            print(f"  ✗ --delete needs --id (the card to remove).", file=sys.stderr)
            sys.exit(1)
        if args.title is None and args.value is None:
            print(f"  ✗ Creating a card needs at least --title or --value.", file=sys.stderr)
            sys.exit(1)
        require_owned(token, args.short_id)
        title = read_value(args.title) or ""
        inp = {
            "id": new_card_id(set()),
            "shortId": args.short_id,
            "contentType": "scenario",
            "type": args.card_type or "character",
            "title": title,
            "description": read_value(args.description) or "",
            "keys": read_value(args.keys) if args.keys is not None else build_keys("", title),
            "value": read_value(args.value) or "",
            "useForCharacterCreation": bool(args.cc),
        }
        result = gql(token, UPDATE_STORY_CARD_MUTATION, {"input": inp},
                     op_name="UseUpdateStoryCard")["updateStoryCard"]
        if result.get("success"):
            c = result.get("storyCard") or {}
            cc = " [CC]" if c.get("useForCharacterCreation") else ""
            print(f"\n  ✓ Created card '{c.get('title')}'{cc}  ({c.get('type')})  id {c.get('id')}")
            print(f"    triggers: {c.get('keys')}\n")
        else:
            print(f"\n  ✗ {result.get('message') or 'createStoryCard failed'}\n", file=sys.stderr)
            sys.exit(1)
        return

    # Edit/delete: locate the card by id, which needs the card list.
    data = gql(token, STORY_CARDS_QUERY,
               {"shortId": args.short_id, "viewPublished": False},
               op_name="GetScenarioStoryCards")
    s = data["scenario"]
    if not s:
        print(f"  ✗ Scenario '{args.short_id}' not found", file=sys.stderr)
        sys.exit(1)
    if not s.get("isOwner"):
        print(f"  ✗ You don't own '{s.get('title') or args.short_id}'.", file=sys.stderr)
        sys.exit(1)
    cards = (s.get("state") or {}).get("storyCards") or []

    card = next((c for c in cards if str(c.get("id")) == str(args.id)), None)
    if not card:
        print(f"  ✗ No story card with id '{args.id}' on this scenario.", file=sys.stderr)
        print(f"    List ids with:  {PROG} cards {args.short_id} --json", file=sys.stderr)
        sys.exit(1)

    if args.delete:
        label = f"'{card.get('title') or '(untitled)'}'  ({card.get('type')})  id {args.id}"
        if not args.yes:
            print(f"\n  Would delete card: {label}")
            print(f"  Re-run with --yes to confirm.\n")
            return
        result = gql(token, DELETE_STORY_CARD_MUTATION,
                     {"input": {"id": args.id, "shortId": args.short_id, "contentType": "scenario"}},
                     op_name="UseDeleteStoryCard")["deleteStoryCard"]
        if result.get("success"):
            print(f"\n  ✓ Deleted card {label}. {result.get('message') or ''}".rstrip() + "\n")
        else:
            print(f"\n  ✗ {result.get('message') or 'deleteStoryCard failed'}\n", file=sys.stderr)
            sys.exit(1)
        return

    inp = {
        "id": card["id"],
        "shortId": args.short_id,
        "contentType": "scenario",
        "type": args.card_type if args.card_type is not None else (card.get("type") or "class"),
        "title": read_value(args.title) if args.title is not None else (card.get("title") or ""),
        "description": read_value(args.description) if args.description is not None else (card.get("description") or ""),
        "keys": read_value(args.keys) if args.keys is not None else (card.get("keys") or ""),
        "value": read_value(args.value) if args.value is not None else (card.get("value") or ""),
        "useForCharacterCreation": args.cc if args.cc is not None else card.get("useForCharacterCreation", False),
    }

    result = gql(token, UPDATE_STORY_CARD_MUTATION, {"input": inp},
                 op_name="UseUpdateStoryCard")["updateStoryCard"]
    if result.get("success"):
        c = result.get("storyCard") or {}
        cc = " [CC]" if c.get("useForCharacterCreation") else ""
        print(f"\n  ✓ Updated card '{c.get('title')}'{cc}  ({c.get('type')})")
        print(f"    triggers: {c.get('keys')}\n")
    else:
        print(f"\n  ✗ {result.get('message') or 'updateStoryCard failed'}\n", file=sys.stderr)
        sys.exit(1)


def cmd_create(args):
    token = resolve_token(args)

    details = {"prompt": read_value(args.prompt) or ""}
    if args.plot_essentials is not None:
        details["plotEssentials"] = read_value(args.plot_essentials)
    if args.authors_note is not None:
        details["authorsNote"] = read_value(args.authors_note)

    inp = {"title": read_value(args.title) or "", "details": details}
    if args.description is not None:
        inp["description"] = read_value(args.description)
    if args.tags is not None:
        cleaned, issues = lint_tags(args.tags)
        for issue in issues:
            print(f"  {issue}", file=sys.stderr)
        inp["tags"] = cleaned
    if args.rating is not None:
        inp["contentRating"] = RATING_MAP[args.rating]
    if args.scenario_type is not None:
        inp["type"] = args.scenario_type

    result = gql(token, CREATE_SCENARIO_MUTATION, {"input": inp},
                 op_name="NewMenuCreateScenario")["createScenario"]
    if not result.get("success"):
        print(f"\n  ✗ {result.get('message') or 'createScenario failed'}\n", file=sys.stderr)
        sys.exit(1)
    sc = result.get("scenario") or {}
    print(f"\n  ✓ Created '{sc.get('title') or '(untitled)'}'  ({sc.get('shortId')})")
    print(f"    Flesh it out:  {PROG} update {sc.get('shortId')} --plot-essentials @pe.md ...\n")


def cmd_scripts(args):
    token = resolve_token(args)
    sd = args.scripts_dir
    game = {}
    for flag, field in (("on_input", "onInput"), ("on_output", "onOutput"),
                        ("on_context", "onModelContext"), ("shared_library", "sharedLibrary")):
        v = script_value(getattr(args, flag), sd, field)
        if v is not None:
            game[field] = v
    if not game:
        print("  ✗ Nothing to set — pass --on-input/--on-output/--on-context/"
              "--shared-library (or --scripts-dir).", file=sys.stderr)
        sys.exit(1)

    require_owned(token, args.short_id)
    payload_kb = len(json.dumps(game).encode("utf-8")) / 1024
    fields = ", ".join(game)
    if args.dry_run:
        print(f"\n  Would set scripts: {fields}  ({payload_kb:.0f} KB)")
        print(f"  ⓘ Dry run — nothing sent. (Other scripts are preserved; gameCode merges.)\n")
        return

    result = gql(token, UPDATE_SCRIPTS_MUTATION,
                 {"shortId": args.short_id, "gameCode": game},
                 op_name="UpdateScenarioScripts")["updateScenarioScripts"]
    if result.get("success"):
        print(f"\n  ✓ Updated scripts: {fields}  ({payload_kb:.0f} KB). {result.get('message') or ''}".rstrip() + "\n")
    else:
        print(f"\n  ✗ {result.get('message') or 'updateScenarioScripts failed'}\n", file=sys.stderr)
        sys.exit(1)


def load_cards_file(path, keep_when=False):
    """Read a .json or .md cards file (autodetected) into normalized card dicts. With
    keep_when, a card's `when` condition is preserved for the mc compiler (it strips it
    before the card is sent); the destructive bulk commands leave keep_when off."""
    src = Path(path)
    if not src.exists():
        print(f"  ✗ File not found: {path}", file=sys.stderr)
        sys.exit(1)
    content = src.read_text(encoding="utf-8")
    stripped = content.lstrip()
    if stripped.startswith("[") or stripped.startswith("{"):
        parsed = json.loads(content)
        raw = parsed if isinstance(parsed, list) else [parsed]
    else:
        raw = markdown_to_cards(content)

    cards = []
    for c in raw:
        title = c.get("title") or ""
        card = {
            "keys": c.get("keys") or build_keys("", title),
            "value": c.get("value") or "",
            "type": c.get("type") or "character",
            "title": title,
            "description": c.get("description") or "",
            "useForCharacterCreation": bool(c.get("useForCharacterCreation")),
        }
        if keep_when and c.get("when"):
            card["when"] = c["when"]
        cards.append(card)
    if not cards:
        print(f"  ✗ No story cards found in {path}", file=sys.stderr)
        sys.exit(1)
    return cards


def cmd_import_cards(args):
    token = resolve_token(args)
    # Ownership only — do NOT read scenario state first (a state read before this
    # write forks a never-published scenario's draft; see the card-create note).
    s = require_owned(token, args.short_id)
    cards = load_cards_file(args.file)

    if not args.yes:
        print(f"\n  ⚠ This REPLACES every story card on '{s.get('title')}' ({args.short_id})")
        print(f"    with the {len(cards)} card(s) from {args.file}. The current set is discarded.")
        print(f"    (To add without discarding, use '{PROG} add-cards'.)")
        print(f"    Re-run with --yes to confirm.\n")
        return

    result = gql(token, IMPORT_STORY_CARDS_MUTATION,
                 {"input": {"shortId": args.short_id, "contentType": "scenario", "storyCards": cards}},
                 op_name="ImportStoryCards")["importStoryCards"]
    if result.get("success"):
        print(f"\n  ✓ Imported {len(cards)} card(s), replacing the previous set. {result.get('message') or ''}".rstrip() + "\n")
    else:
        print(f"\n  ✗ {result.get('message') or 'importStoryCards failed'}\n", file=sys.stderr)
        sys.exit(1)


def cmd_add_cards(args):
    token = resolve_token(args)
    # Additive: upsert each card with a fresh id. No state pre-read (which would fork
    # the draft) and no destructive replace — existing cards are left in place.
    require_owned(token, args.short_id)
    cards = load_cards_file(args.file)

    added = 0
    for c in cards:
        inp = {
            "id": new_card_id(set()),
            "shortId": args.short_id,
            "contentType": "scenario",
            "type": c["type"],
            "title": c["title"],
            "description": c["description"],
            "keys": c["keys"],
            "value": c["value"],
            "useForCharacterCreation": c["useForCharacterCreation"],
        }
        result = gql(token, UPDATE_STORY_CARD_MUTATION, {"input": inp},
                     op_name="UseUpdateStoryCard")["updateStoryCard"]
        if result.get("success"):
            added += 1
        else:
            print(f"  ⚠ '{c['title']}' failed: {result.get('message')}", file=sys.stderr)
    print(f"\n  ✓ Added {added}/{len(cards)} card(s) to {args.short_id} (existing cards kept).\n")


def cmd_restore(args):
    token = resolve_token(args)
    result = gql(token, RESTORE_SCENARIO_MUTATION, {"shortId": args.short_id},
                 op_name="UseRestoreScenario")["restoreScenario"]
    if result.get("success"):
        sc = result.get("scenario") or {}
        print(f"\n  ✓ Restored '{sc.get('title') or args.short_id}' ({args.short_id}).\n")
    else:
        print(f"\n  ✗ {result.get('message') or 'restoreScenario failed'}\n", file=sys.stderr)
        sys.exit(1)


def cmd_duplicate(args):
    token = resolve_token(args)
    result = gql(token, DUPLICATE_SCENARIO_MUTATION, {"shortId": args.short_id},
                 op_name="UseDuplicateScenario")["duplicateScenario"]
    if not result.get("success"):
        print(f"\n  ✗ {result.get('message') or 'duplicateScenario failed'}\n", file=sys.stderr)
        sys.exit(1)
    sc = result.get("scenario") or {}
    print(f"\n  ✓ Duplicated → '{sc.get('title') or '(untitled)'}'  ({sc.get('shortId')})\n")


def cmd_delete(args):
    token = resolve_token(args)
    s = require_owned(token, args.short_id)
    title = s.get("title") or args.short_id
    stype = s.get("type")

    if not args.yes:
        print(f"\n  Would delete: '{title}'  ({stype})  {args.short_id}")
        if stype in ("multipleChoice", "characterCreator"):
            print(f"  ⚠ Parent scenario — deleting it affects its option branches.")
        print(f"  Re-run with --yes to confirm.\n")
        return

    result = gql(token, DELETE_SCENARIO_MUTATION, {"shortId": args.short_id},
                 op_name="MainMenuViewDeleteScenario")["deleteScenario"]
    if result.get("success"):
        print(f"\n  ✓ Deleted '{title}' ({args.short_id}). {result.get('message') or ''}".rstrip() + "\n")
    else:
        print(f"\n  ✗ {result.get('message') or 'deleteScenario failed'}\n", file=sys.stderr)
        sys.exit(1)


def cmd_analyze(args):
    token = resolve_token(args)
    sort_order = args.sort
    default_time = "7" if sort_order == "trending" else None
    fields = apply_search_filters({
        "contentType": ["scenario"],
        "sortOrder": sort_order,
        "contentFilters": ["published"],
        "screen": "discover",
        "limit": args.limit,
        "offset": args.offset,
    }, args, default_time=default_time)

    data = gql(token, SEARCH_QUERY, {"input": fields})
    items, removed = filter_creators(data["search"]["items"], args)
    if removed:
        print(f"  ↪ {removed} scenario(s) dropped by creator filter", file=sys.stderr)
    if not items:
        print("  (no results to analyze)")
        return

    if args.json and not args.deep:
        print(json.dumps(items, indent=2, ensure_ascii=False))
        return

    # Optionally deepen: fetch per-scenario details for card counts + patterns
    deep_data = {}
    if args.deep:
        print(f"  ↻ Fetching details for {len(items)} scenarios...", file=sys.stderr)
        for it in items:
            try:
                d = gql(token, SCENARIO_QUERY,
                        {"shortId": it["shortId"], "viewPublished": True},
                        op_name="GetScenarioDetails")
                deep_data[it["shortId"]] = d["scenario"]
            except SystemExit:
                pass  # skip failures, keep going

    # Aggregate stats
    plays = [it.get("adventuresPlayed", 0) for it in items]
    votes = [it.get("voteCount", 0) for it in items]
    saves = [it.get("saveCount", 0) for it in items]
    total_plays = sum(plays)

    # Tag frequency
    tag_freq = {}
    for it in items:
        for t in (it.get("tags") or []):
            tag_freq[t] = tag_freq.get(t, 0) + 1
    top_tags = sorted(tag_freq.items(), key=lambda x: -x[1])[:15]

    label = "Trending (week)" if sort_order == "trending" else "Popular (all-time)"
    print(f"\n  ╔═══ Analysis: {label} — top {len(items)} ═══╗")
    print(f"  ║  Total plays across set: {total_plays:,}")
    print(f"  ║  Avg plays: {total_plays // len(items):,}  |  median: {sorted(plays)[len(plays)//2]:,}")
    print(f"  ║  Avg save ratio: {(sum(saves) / total_plays * 100):.1f}%" if total_plays else "")
    print(f"  ╚{'═' * 44}")

    print(f"\n  Top tags in this set:")
    for tag, freq in top_tags:
        bar = "█" * freq
        print(f"    {freq:>2} {bar}  {tag}")

    if args.deep and deep_data:
        # Card count distribution + pattern classification
        card_counts = []
        patterns = {}
        print(f"\n  Card counts & design patterns:")
        for it in items:
            s = deep_data.get(it["shortId"])
            if not s:
                continue
            cc = s.get("storyCardCount", 0)
            card_counts.append(cc)
            pat = profile_scenario(s)
            patterns[pat] = patterns.get(pat, 0) + 1
            title = (s.get("title") or "")[:34]
            print(f"    {cc:>4} cards  {title:<35}  {pat}")

        if card_counts:
            zero = sum(1 for c in card_counts if c == 0)
            heavy = sum(1 for c in card_counts if c >= 100)
            print(f"\n  Card distribution: {zero} with zero, {heavy} with 100+, "
                  f"{len(card_counts) - zero - heavy} in between")
            print(f"  (bimodal = creators either build card-bibles or go card-free)")

        print(f"\n  Design pattern breakdown:")
        for pat, n in sorted(patterns.items(), key=lambda x: -x[1]):
            print(f"    {n:>2}  {pat}")
    print()


def cmd_keys(args):
    text = " ".join(args.text)
    existing = args.existing or ""
    result = build_keys(existing, text)
    if args.json:
        print(json.dumps({"input": text, "keys": result,
                          "triggers": result.split(",")}, ensure_ascii=False))
        return
    triggers = result.split(",")
    print(f"\n  Keys for \"{text}\" ({len(result)} chars, {len(triggers)} triggers):")
    print(f"\n  {result}\n")
    if len(text.strip()) < 6:
        print("  (short word: guarded on both sides to avoid bleeding into other words)")
    elif len(text.strip()) < 9:
        print("  (medium word: one-sided guards)")
    else:
        print("  (long word: used bare — unique enough to not collide)")
    print()


def cmd_convert(args):
    """Convert story cards between JSON and the skill's markdown format. Autodetects."""
    src = Path(args.file)
    if not src.exists():
        print(f"  ✗ File not found: {args.file}", file=sys.stderr)
        sys.exit(1)
    content = src.read_text(encoding="utf-8")

    # Detect direction: try JSON first, fall back to markdown
    direction = args.to
    if not direction:
        stripped = content.lstrip()
        if stripped.startswith("[") or stripped.startswith("{"):
            direction = "md"
        else:
            direction = "json"

    if direction == "md":
        try:
            cards = json.loads(content)
        except json.JSONDecodeError as e:
            print(f"  ✗ Couldn't parse JSON: {e}", file=sys.stderr)
            sys.exit(1)
        if isinstance(cards, dict):
            cards = [cards]
        out = cards_to_markdown(cards)
    else:  # to json
        cards = markdown_to_cards(content)
        out = json.dumps(cards, indent=2, ensure_ascii=False)

    if args.out:
        Path(args.out).write_text(out, encoding="utf-8")
        print(f"  ✓ Wrote {args.out}", file=sys.stderr)
    else:
        print(out)


def cmd_tags(args):
    tags = args.tags
    cleaned, issues = lint_tags(tags)
    if args.json:
        print(json.dumps({"input": tags, "cleaned": cleaned, "issues": issues},
                         ensure_ascii=False))
        return
    print(f"\n  Tag check ({len(tags)} input):")
    if issues:
        for issue in issues:
            print(f"    {issue}")
    else:
        print(f"    ✓ All tags well-formed.")
    print(f"\n  Cleaned ({len(cleaned)}): {' '.join(cleaned)}")
    if not tags:
        print(f"\n  Suggestions by category:")
        for cat, examples in TAG_SUGGESTIONS.items():
            print(f"    {cat}: {', '.join(examples[:8])}")
    print()


def cmd_resources(args):
    token = resolve_token(args)
    data = gql(token, RESOURCES_QUERY, op_name="GetResources")
    r = data["user"]["resources"]
    if args.json:
        print(json.dumps(data, indent=2))
        return

    credits = r.get("creditsBalance", {}).get("currentBalance", 0)
    scales = r.get("scalesBalance", {}).get("currentBalance", 0)
    promo = r.get("promoActionsBalance", {}).get("currentBalance", 0)
    print(f"\n  ┌───── Account Resources ─────┐")
    print(f"  │  Credits:          {credits:>6}")
    print(f"  │  Scales:           {scales:>6}")
    print(f"  │  Promo Actions:    {promo:>6}")
    print(f"  └{'─' * 32}")
    print()


# ─── Token Commands ──────────────────────────────────────────────────────────

def cmd_token_import(args):
    """Import a Firebase JWT and optional refresh token for auto-refresh."""
    raw = args.id_token.strip()
    if raw.startswith("firebase "):
        raw = raw[9:]

    payload = decode_jwt_payload(raw)
    if not payload or "exp" not in payload:
        print("  ✗ Invalid JWT — couldn't decode payload.", file=sys.stderr)
        print("    The token may be truncated or mangled (e.g. markdown formatting applied "
              "to the text). Re-copy the raw token.", file=sys.stderr)
        sys.exit(1)

    issuer = payload.get("iss")
    if issuer != EXPECTED_ISSUER:
        print(f"  ✗ Token issuer doesn't match AI Dungeon.", file=sys.stderr)
        print(f"    expected: {EXPECTED_ISSUER}", file=sys.stderr)
        print(f"    got:      {issuer or '(none)'}", file=sys.stderr)
        print(f"    The token is likely mangled (markdown/whitespace) or from another "
              f"project — re-copy the raw token.", file=sys.stderr)
        sys.exit(1)

    exp_epoch = payload["exp"]
    now = time.time()
    remaining = exp_epoch - now

    store = load_token_store() or {}
    store["id_token"] = raw
    store["expires_at"] = exp_epoch

    if args.refresh_token:
        store["refresh_token"] = args.refresh_token.strip()
    elif "refresh_token" not in store:
        store["refresh_token"] = None

    store["last_imported"] = now
    save_token_store(store)

    email = payload.get("email", "?")
    uid = payload.get("user_id", payload.get("sub", "?"))
    expires_at_str = datetime.fromtimestamp(exp_epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    print(f"\n  ✓ Token imported!")
    print(f"    User:  {email}  ({uid[:12]}...)")
    print(f"    Expires:  {expires_at_str}  ({format_time_left(exp_epoch)} remaining)")
    if store.get("refresh_token"):
        print(f"    Auto-refresh:  enabled (refreshes when <5 min from expiry)")
    else:
        print(f"    Auto-refresh:  DISABLED — pass a refresh token to enable it")
    print()


def cmd_token_status(args):
    """Show current token status."""
    # Check env/--token first
    explicit = args.token or os.environ.get("AID_TOKEN", "")
    if explicit:
        raw = explicit.strip()
        if raw.startswith("firebase "):
            raw = raw[9:]
        payload = decode_jwt_payload(raw)
        if payload and "exp" in payload:
            exp = payload["exp"]
            status = "✓ VALID" if exp > time.time() else "✗ EXPIRED"
            print(f"\n  ┌───── Token (from {'--token' if args.token else 'AID_TOKEN env'}) ─────┐")
            print(f"  │  Status:  {status}")
            print(f"  │  Expires: {datetime.fromtimestamp(exp, tz=timezone.utc)}")
            print(f"  │  Remaining: {format_time_left(exp)}")
            email = payload.get("email", "?")
            print(f"  │  User:    {email}")
            print(f"  └{'─' * 48}")
            print()
            return
        print("  ✗ Could not decode the provided token", file=sys.stderr)
        sys.exit(1)

    # Check stored token
    store = load_token_store()
    if not store or "id_token" not in store:
        print(f"  No stored token. Use --token, AID_TOKEN env, or '{PROG} token import'.", file=sys.stderr)
        sys.exit(1)

    id_token = store["id_token"]
    payload = decode_jwt_payload(id_token)
    exp = store.get("expires_at") or (payload.get("exp") if payload else None)
    now = time.time()

    expiry_str = datetime.fromtimestamp(exp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if exp else "?"
    remaining_str = format_time_left(exp) if exp else "?"
    can_refresh = bool(store.get("refresh_token"))
    needs_refresh = exp and exp - now < TOKEN_REFRESH_BUFFER and can_refresh

    if exp and exp < now:
        status = "✗ EXPIRED"
    elif needs_refresh:
        status = "⚠ EXPIRING (will auto-refresh on next query)"
    else:
        status = "✓ VALID"

    print(f"\n  ┌───── Stored Token ─────┐")
    print(f"  │  Status:       {status}")
    print(f"  │  Expires:      {expiry_str}")
    print(f"  │  Remaining:    {remaining_str}")
    if payload:
        print(f"  │  User:         {payload.get('email', '?')}")
        print(f"  │  User ID:      {payload.get('user_id', payload.get('sub', '?'))}")
    print(f"  │  Refresh:      {'✓ enabled' if can_refresh else '✗ disabled'}")
    if store.get("last_refreshed"):
        lr = datetime.fromtimestamp(store["last_refreshed"], tz=timezone.utc).strftime("%H:%M:%S UTC")
        print(f"  │  Last refresh: {lr}")
    print(f"  │  Store:        {token_store_path()}")
    print(f"  └{'─' * 40}")
    print()


def cmd_token_clear(args):
    """Clear stored tokens."""
    clear_token_store()
    print("  ✓ Token store cleared")


EXTRACT_HELP = """\
  ┌───── Get tokens from AI Dungeon ─────────────────────────────┐

  AI Dungeon uses the Firebase v9 modular SDK, so there's no global
  `firebase` object to call. Instead, read the token straight out of
  browser storage. Log in at play.aidungeon.com, open the DevTools
  console, and paste this:

      (async () => {
        const show = (a, r) => {
          console.log('AID_TOKEN=' + a);
          if (r) console.log('REFRESH_TOKEN=' + r);
          console.log('\\nImport with:\\n  aid token import "' + a + '" "' + (r || '') + '"');
        };
        // 1. localStorage (some configs)
        for (let i = 0; i < localStorage.length; i++) {
          const k = localStorage.key(i);
          if (k && k.startsWith('firebase:authUser:')) {
            const u = JSON.parse(localStorage.getItem(k));
            if (u?.stsTokenManager?.accessToken)
              return show(u.stsTokenManager.accessToken, u.stsTokenManager.refreshToken);
          }
        }
        // 2. IndexedDB (default persistence). Records are { fbase_key, value }.
        const db = await new Promise((res, rej) => {
          const req = indexedDB.open('firebaseLocalStorageDb');
          req.onsuccess = () => res(req.result);
          req.onerror = () => rej(req.error);
        });
        const all = await new Promise((res) => {
          const req = db.transaction('firebaseLocalStorage')
                        .objectStore('firebaseLocalStorage').getAll();
          req.onsuccess = () => res(req.result);
          req.onerror = () => res([]);
        });
        for (const rec of all) {
          const u = rec?.value || rec;   // unwrap the keyPath wrapper
          if (u?.stsTokenManager?.accessToken)
            return show(u.stsTokenManager.accessToken, u.stsTokenManager.refreshToken);
        }
        console.log('No Firebase auth token found — are you logged in?');
      })();

    Then copy the printed line:
      aid token import '<AID_TOKEN>' '<REFRESH_TOKEN>'

  Quick one-off (no auto-refresh):
    DevTools → Network → filter 'graphql' → click any request →
    copy the 'authorization' request header (it's 'firebase <jwt>').
    Then:  export AID_TOKEN='firebase <jwt>'

  └───────────────────────────────────────────────────────────────┘
"""


def cmd_token_extract(args):
    """Print instructions for extracting tokens from browser."""
    print(EXTRACT_HELP.replace("aid token import", f"{PROG} token import"))


def cmd_token_force_refresh(args):
    """Force a token refresh now."""
    store = load_token_store()
    if not store or not store.get("refresh_token"):
        print(f"  ✗ No refresh token stored. Use '{PROG} token import' with a refresh token.", file=sys.stderr)
        sys.exit(1)

    print("  ↻ Forcing token refresh...", file=sys.stderr)
    try:
        result = refresh_id_token(store["refresh_token"])
        new_exp = time.time() + result["expires_in"]
        store["id_token"] = result["id_token"]
        store["refresh_token"] = result["refresh_token"]
        store["expires_at"] = new_exp
        store["last_refreshed"] = time.time()
        save_token_store(store)
        expiry_str = datetime.fromtimestamp(new_exp, tz=timezone.utc).strftime("%H:%M:%S UTC")
        print(f"  ✓ Refreshed! Valid until {expiry_str} ({result['expires_in'] // 60} min)", file=sys.stderr)
    except RuntimeError as e:
        print(f"  ✗ {e}", file=sys.stderr)
        sys.exit(1)


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="AI Dungeon GraphQL CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.replace("aid ", f"{PROG} "),
    )
    parser.add_argument("--token", help="Firebase JWT (overrides stored token)")
    parser.add_argument("--json", action="store_true", help="Raw JSON output")
    parser.add_argument("--limit", type=int, default=30, help="Results per page (default: 30)")
    parser.add_argument("--offset", type=int, default=0, help="Page offset (default: 0)")
    parser.add_argument("--filters", action="append",
                        help="Extra filter as JSON, e.g. --filters 'thirdPerson=true'")

    sub = parser.add_subparsers(dest="command", required=True)

    # Query commands
    p_trend = sub.add_parser("trending", help="Trending scenarios (default 7-day window)")
    add_search_filter_args(p_trend)
    p_trend.set_defaults(func=cmd_trending)

    p_pop = sub.add_parser("popular", help="Popular scenarios (default all-time)")
    add_search_filter_args(p_pop)
    p_pop.set_defaults(func=cmd_popular)

    p_search = sub.add_parser("search", help="Search scenarios by keyword")
    p_search.add_argument("query", nargs="+", help="Search terms")
    add_search_filter_args(p_search)
    p_search.set_defaults(func=cmd_search)

    p_mine = sub.add_parser("mine", help="List your own scenarios (published + drafts), newest first")
    mine_scope = p_mine.add_mutually_exclusive_group()
    mine_scope.add_argument("--published", action="store_true", help="Only published scenarios")
    mine_scope.add_argument("--drafts", action="store_true", help="Only unpublished drafts")
    p_mine.set_defaults(func=cmd_mine)

    p_creator = sub.add_parser("creator", help="List another creator's published scenarios, newest first")
    p_creator.add_argument("username", help="Creator's username")
    p_creator.set_defaults(func=cmd_creator)

    p_detail = sub.add_parser("details", help="Get scenario details by shortId")
    p_detail.add_argument("short_id", help="Scenario shortId (e.g. 'abc123')")
    add_view_flag(p_detail)
    p_detail.set_defaults(func=cmd_details)

    p_cards = sub.add_parser("cards", help="List a scenario's story cards")
    p_cards.add_argument("short_id", help="Scenario shortId")
    p_cards.add_argument("--md", action="store_true", help="Output as skill markdown format")
    add_view_flag(p_cards)
    p_cards.set_defaults(func=cmd_cards)

    p_tree = sub.add_parser("tree", help="Show a Multiple Choice scenario's branch tree")
    p_tree.add_argument("short_id", help="Scenario shortId")
    add_view_flag(p_tree)
    p_tree.set_defaults(func=cmd_tree)

    p_export = sub.add_parser("export",
                              help="Dump a scenario's setup + cards to JSON (handles MC/Character Creator)")
    p_export.add_argument("short_id", help="Scenario shortId")
    p_export.add_argument("--out", help="Output directory (default: <slug>-export/)")
    p_export.add_argument("--md", action="store_true", help="Write cards as markdown instead of JSON")
    p_export.add_argument("--setup-only", action="store_true", dest="setup_only",
                          help="Only export setup (plot components), skip cards")
    p_export.add_argument("--cards-only", action="store_true", dest="cards_only",
                          help="Only export story cards, skip setup")
    add_view_flag(p_export)
    p_export.set_defaults(func=cmd_export)

    p_update = sub.add_parser(
        "update",
        help="Edit a scenario you own (description, plot components, scripts, etc.)",
        description="Read-modify-write: fetches the scenario, applies the given "
                    "fields, and sends the whole object back. Text flags accept "
                    "'@path' to read the value from a file.")
    p_update.add_argument("short_id", help="Scenario shortId")
    p_update.add_argument("--title", help="Scenario title")
    p_update.add_argument("--description", help="Description (or @file)")
    p_update.add_argument("--image", help="Cover image URL")
    p_update.add_argument("--tags", nargs="+", help="Replace tags (linted before sending)")
    p_update.add_argument("--rating", choices=["everyone", "teen", "mature", "unrated"],
                          help="Content rating")
    p_update.add_argument("--type", dest="scenario_type", choices=SCENARIO_TYPES,
                          help="Convert scenario type (multipleChoice/characterCreator "
                               f"need child options — see '{PROG} options')")
    p_update.add_argument("--third-person", action=argparse.BooleanOptionalAction,
                          default=None, dest="third_person", help="Third-person perspective")
    p_update.add_argument("--allow-comments", action=argparse.BooleanOptionalAction,
                          default=None, dest="allow_comments", help="Allow comments")
    p_update.add_argument("--scripts-enabled", action=argparse.BooleanOptionalAction,
                          default=None, dest="scripts_enabled", help="Enable scripting")
    p_update.add_argument("--prompt", help="Opening prompt (or @file)")
    p_update.add_argument("--plot-essentials", dest="plot_essentials",
                          help="Plot Essentials (or @file)")
    p_update.add_argument("--authors-note", dest="authors_note",
                          help="Author's Note (or @file)")
    p_update.add_argument("--story-summary", dest="story_summary",
                          help="Story Summary (or @file)")
    p_update.add_argument("--dry-run", action="store_true", dest="dry_run",
                          help="Show the change summary without sending (add --json for full payload)")
    p_update.set_defaults(func=cmd_update)

    p_scripts = sub.add_parser(
        "scripts",
        help="Edit a scenario's scripts (lightweight; only sends what you change)")
    p_scripts.add_argument("short_id", help="Scenario shortId")
    p_scripts.add_argument("--on-input", dest="on_input", help="onInput script (or @file)")
    p_scripts.add_argument("--on-output", dest="on_output", help="onOutput script (or @file)")
    p_scripts.add_argument("--on-context", dest="on_context", help="onModelContext script (or @file)")
    p_scripts.add_argument("--shared-library", dest="shared_library", help="Shared Library script (or @file)")
    p_scripts.add_argument("--scripts-dir", dest="scripts_dir",
                           help="Load from a directory: input.js, output.js, context.js, "
                                "library.js (whichever exist; explicit --on-* flags override)")
    p_scripts.add_argument("--dry-run", action="store_true", dest="dry_run",
                           help="Show what would be sent without sending")
    p_scripts.set_defaults(func=cmd_scripts)

    p_import = sub.add_parser(
        "import-cards",
        help="Replace a scenario's story cards from a JSON/markdown file (destructive; needs --yes)")
    p_import.add_argument("short_id", help="Scenario shortId")
    p_import.add_argument("file", help="Cards file (.json or .md — autodetected)")
    p_import.add_argument("--yes", action="store_true",
                          help="Confirm the replace — without it, just previews")
    p_import.set_defaults(func=cmd_import_cards)

    p_addcards = sub.add_parser(
        "add-cards",
        help="Add story cards from a JSON/markdown file, keeping existing ones (non-destructive)")
    p_addcards.add_argument("short_id", help="Scenario shortId")
    p_addcards.add_argument("file", help="Cards file (.json or .md — autodetected)")
    p_addcards.set_defaults(func=cmd_add_cards)

    p_restore = sub.add_parser("restore", help="Restore a soft-deleted scenario")
    p_restore.add_argument("short_id", help="Scenario shortId")
    p_restore.set_defaults(func=cmd_restore)

    p_options = sub.add_parser(
        "options",
        help="Create child option branches under a scenario (Multiple Choice / Character Creator)")
    p_options.add_argument("short_id", help="Parent scenario shortId")
    p_options.add_argument("--count", type=int, default=2, help="How many options to create (default: 2)")
    p_options.add_argument("--title", help="Title prefix for the created options")
    p_options.set_defaults(func=cmd_options)

    p_mc = sub.add_parser(
        "mc",
        help="Build a Multiple Choice tree from a single layered spec file")
    mc_sub = p_mc.add_subparsers(dest="mc_command", required=True)

    p_mc_build = mc_sub.add_parser(
        "build",
        help="Compile a layer spec into the full per-leaf tree (offline; no network)",
        description="Expand a layered spec (context → species → era …) into every "
                    "root→leaf combination, baking each path's accumulated cards and "
                    "plot components into the leaf, since AID branches don't inherit.")
    p_mc_build.add_argument("spec", help="Layer spec JSON file")
    p_mc_build.add_argument("--out", help="Also write the compiled tree as an export-style dir")
    p_mc_build.set_defaults(func=cmd_mc_build)

    p_mc_sync = mc_sub.add_parser(
        "sync",
        help="Create/update the MC tree on your account from a layer spec (needs --yes)",
        description="Walk the compiled plan against AID: create or match branches by "
                    "title (idempotent re-sync), then write each node with one "
                    "fork-safe updateScenario.")
    p_mc_sync.add_argument("spec", help="Layer spec JSON file")
    p_mc_sync.add_argument("--scenario", help="Existing root shortId to sync into (omit to create new)")
    p_mc_sync.add_argument("--prune", action="store_true",
                           help="Delete existing branches not present in the spec")
    p_mc_sync.add_argument("--yes", action="store_true",
                           help="Apply — without it, just previews the plan")
    p_mc_sync.set_defaults(func=cmd_mc_sync)

    p_card = sub.add_parser(
        "card",
        help="Create, edit, or delete one story card (surgical — avoids the full-scenario payload)")
    p_card.add_argument("short_id", help="Scenario shortId")
    p_card.add_argument("--id", help=f"Card id to edit/delete (see '{PROG} cards <shortId> --json'); "
                                     "omit to create a new card")
    p_card.add_argument("--title", help="Card title")
    p_card.add_argument("--type", dest="card_type", help="Card type (character, location, race, class, …)")
    p_card.add_argument("--keys", help="Trigger keys (comma-separated)")
    p_card.add_argument("--value", help="Card entry text (or @file)")
    p_card.add_argument("--description", help="Card description/notes (or @file)")
    p_card.add_argument("--cc", action=argparse.BooleanOptionalAction, default=None,
                        help="Mark/unmark for character creation")
    p_card.add_argument("--delete", action="store_true",
                        help="Delete this card instead of editing (needs --yes)")
    p_card.add_argument("--yes", action="store_true",
                        help="Confirm a --delete (without it, --delete just previews)")
    p_card.set_defaults(func=cmd_card)

    p_create = sub.add_parser("create", help="Create a new scenario")
    p_create.add_argument("--title", help="Scenario title")
    p_create.add_argument("--description", help="Description (or @file)")
    p_create.add_argument("--prompt", help="Opening prompt (or @file)")
    p_create.add_argument("--plot-essentials", dest="plot_essentials", help="Plot Essentials (or @file)")
    p_create.add_argument("--authors-note", dest="authors_note", help="Author's Note (or @file)")
    p_create.add_argument("--tags", nargs="+", help="Tags (linted before sending)")
    p_create.add_argument("--rating", choices=["everyone", "teen", "mature", "unrated"],
                          help="Content rating")
    p_create.add_argument("--type", dest="scenario_type", choices=SCENARIO_TYPES,
                          help="Scenario type (default: simple)")
    p_create.set_defaults(func=cmd_create)

    p_dup = sub.add_parser("duplicate", help="Duplicate a scenario into your library (any owner)")
    p_dup.add_argument("short_id", help="shortId of the scenario to copy")
    p_dup.set_defaults(func=cmd_duplicate)

    p_delete = sub.add_parser(
        "delete", help="Delete a scenario or option branch you own (destructive; needs --yes)")
    p_delete.add_argument("short_id", help="Scenario/branch shortId")
    p_delete.add_argument("--yes", action="store_true",
                          help="Actually delete — without it, just previews what would go")
    p_delete.set_defaults(func=cmd_delete)

    p_analyze = sub.add_parser("analyze", help="Aggregate analysis of popular/trending scenarios")
    p_analyze.add_argument("sort", nargs="?", default="popular",
                           choices=["popular", "trending"], help="Which list (default: popular)")
    p_analyze.add_argument("--deep", action="store_true",
                           help="Fetch per-scenario details for card counts + patterns (slower)")
    add_search_filter_args(p_analyze)
    p_analyze.set_defaults(func=cmd_analyze)

    p_keys = sub.add_parser("keys", help="Generate trigger keys for a word/phrase")
    p_keys.add_argument("text", nargs="+", help="The word or phrase to build keys for")
    p_keys.add_argument("--existing", help="Existing keys string to merge into")
    p_keys.set_defaults(func=cmd_keys)

    p_convert = sub.add_parser("convert", help="Convert story cards between JSON and markdown")
    p_convert.add_argument("file", help="Input file (.json or .md — autodetected)")
    p_convert.add_argument("--to", choices=["json", "md"], help="Force output direction")
    p_convert.add_argument("--out", help="Write to file instead of stdout")
    p_convert.set_defaults(func=cmd_convert)

    p_tags = sub.add_parser("tags", help="Validate/lint scenario tags (no args = show guide)")
    p_tags.add_argument("tags", nargs="*", help="Tags to check")
    p_tags.set_defaults(func=cmd_tags)

    p_res = sub.add_parser("resources", help="Check your credit/scale balances")
    p_res.set_defaults(func=cmd_resources)

    # Token management commands
    p_tok = sub.add_parser("token", help="Manage stored Firebase tokens")
    tok_sub = p_tok.add_subparsers(dest="token_command", required=True)

    p_tok_import = tok_sub.add_parser("import", help="Import a Firebase JWT + refresh token")
    p_tok_import.add_argument("id_token", help="Firebase ID token (JWT)")
    p_tok_import.add_argument("refresh_token", nargs="?", default=None,
                              help="Firebase refresh token (enables auto-refresh)")
    p_tok_import.set_defaults(func=cmd_token_import)

    p_tok_status = tok_sub.add_parser("status", help="Show stored token status")
    p_tok_status.set_defaults(func=cmd_token_status)

    p_tok_clear = tok_sub.add_parser("clear", help="Clear stored tokens")
    p_tok_clear.set_defaults(func=cmd_token_clear)

    p_tok_extract = tok_sub.add_parser("extract", help="How to get tokens from browser")
    p_tok_extract.set_defaults(func=cmd_token_extract)

    p_tok_refresh = tok_sub.add_parser("refresh", help="Force token refresh now")
    p_tok_refresh.set_defaults(func=cmd_token_force_refresh)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
