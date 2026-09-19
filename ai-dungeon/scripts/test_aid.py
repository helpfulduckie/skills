#!/usr/bin/env python3
"""
Offline tests for the branch-tree helpers. Standard library only, no network:

    python -m unittest discover -s ai-dungeon/scripts

The fixtures mirror the shape the API actually returns, where a node's `options`
is its whole flattened subtree plus itself rather than a list of children.
"""

import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from aid import child_nodes, count_leaves, collect_leaves, index_nodes  # noqa: E402


def node(nid, title, options=None, **extra):
    n = {"id": nid, "shortId": nid, "title": title, "options": options or []}
    n.update(extra)
    return n


def api_shape(tree, nest_limit=3):
    """Render a real tree the way the API returns it.

    Two behaviors matter and both are load-bearing. A node's `options` is its whole
    flattened subtree with itself first, not its children. And the query nests
    `options` only so far, so a copy rendered below `nest_limit` comes back with its
    subtree omitted — which is what makes a deep tree collapse if reconstruction
    trusts whichever copy it happens to reach first.

    `tree` is (id, title, [children]).
    """
    def subtree_ids(spec):
        _, _, kids = spec
        out = []
        for kid in kids:
            out.append(kid)
            out.extend(subtree_ids(kid))
        return out

    def render(spec, level):
        nid, title, _ = spec
        n = node(nid, title)
        if level > nest_limit:
            n["options"] = []          # truncated by the query's nesting limit
            return n
        n["options"] = [n] + [render(d, level + 1) for d in subtree_ids(spec)]
        return n

    return render(tree, 0)


def flattened(root_id, title, menus):
    """A root with `menus`, shaped the way the API returns it.

    Every node lists itself first, and an ancestor lists every descendant, so the
    root's options carry the menus *and* all of their leaves.
    """
    built, all_leaves = [], []
    for menu_id, menu_title, leaf_specs in menus:
        leaves = [node(lid, ltitle) for lid, ltitle in leaf_specs]
        for leaf in leaves:
            leaf["options"] = [leaf]          # a node echoes itself
        menu = node(menu_id, menu_title)
        menu["options"] = [menu] + leaves      # itself, then its subtree
        built.append(menu)
        all_leaves.extend(leaves)
    root = node(root_id, title)
    root["options"] = [root] + built + all_leaves
    return root


class ChildNodesTests(unittest.TestCase):
    def test_grandchildren_are_not_children(self):
        root = flattened("root", "Root", [
            ("m1", "Menu One", [("a", "Ancient"), ("b", "Future")]),
            ("m2", "Menu Two", [("c", "Ancient"), ("d", "Future")]),
        ])
        kids = child_nodes(root, {"root"})
        self.assertEqual([k["id"] for k in kids], ["m1", "m2"])

    def test_leaf_count_is_not_doubled(self):
        root = flattened("root", "Root", [
            ("m1", "Menu One", [("a", "A"), ("b", "B"), ("c", "C")]),
            ("m2", "Menu Two", [("d", "D"), ("e", "E"), ("f", "F")]),
        ])
        self.assertEqual(count_leaves(root), 6)

    def test_paths_name_the_branch_each_leaf_sits_on(self):
        root = flattened("root", "Root", [
            ("m1", "Menu One", [("a", "Ancient")]),
            ("m2", "Menu Two", [("b", "Ancient")]),
        ])
        found = {leaf["id"]: path for path, leaf in collect_leaves(root)}
        self.assertEqual(found["a"], ["Root", "Menu One", "Ancient"])
        self.assertEqual(found["b"], ["Root", "Menu Two", "Ancient"])

    def test_self_reference_alone_is_a_leaf(self):
        leaf = node("only", "Only")
        leaf["options"] = [leaf]
        self.assertEqual(child_nodes(leaf, {"only"}), [])
        self.assertEqual(count_leaves(leaf), 1)

    def test_deleted_branches_are_skipped(self):
        root = node("root", "Root")
        gone = node("gone", "Gone", deletedAt="2026-01-01")
        live = node("live", "Live")
        root["options"] = [root, gone, live]
        self.assertEqual([k["id"] for k in child_nodes(root, {"root"})], ["live"])

    def test_plain_scenario_has_one_leaf(self):
        self.assertEqual(count_leaves(node("solo", "Solo")), 1)


class DeepTreeTests(unittest.TestCase):
    """Depth beyond the query's nesting, which is where a per-generation fix fails."""

    # root > era > region > city > district > two endings. Deep enough that the
    # query's nesting runs out partway down, which is the whole point of the case.
    TREE = ("root", "Root", [
        ("era", "Era", [
            ("region", "Region", [
                ("city", "City", [
                    ("district", "District", [
                        ("end1", "Ending One", []),
                        ("end2", "Ending Two", []),
                    ]),
                ]),
            ]),
        ]),
    ])

    def test_each_level_keeps_exactly_its_own_children(self):
        root = api_shape(self.TREE)
        index = index_nodes(root)

        def only_child(n, expected):
            kids = child_nodes(n, {n["id"]}, index)
            self.assertEqual([k["id"] for k in kids], [expected],
                             f"{n['id']} should have exactly {expected} beneath it")
            return index[expected]

        era = only_child(root, "era")
        region = only_child(era, "region")
        city = only_child(region, "city")
        district = only_child(city, "district")
        seen = {"root", "era", "region", "city", "district"}
        endings = child_nodes(district, seen, index)
        self.assertEqual(sorted(k["id"] for k in endings), ["end1", "end2"])

    def test_deep_leaves_are_counted_once(self):
        self.assertEqual(count_leaves(api_shape(self.TREE)), 2)

    def test_deep_leaf_paths_keep_every_level(self):
        paths = [p for p, _ in collect_leaves(api_shape(self.TREE))]
        self.assertEqual(sorted(paths), [
            ["Root", "Era", "Region", "City", "District", "Ending One"],
            ["Root", "Era", "Region", "City", "District", "Ending Two"],
        ])

    def test_a_truncated_copy_is_not_mistaken_for_a_leaf(self):
        root = api_shape(self.TREE)
        parents = {"era", "region", "city", "district"}

        def truncated_parents(n, found, seen):
            if id(n) in seen:
                return found
            seen.add(id(n))
            for child in n.get("options") or []:
                if child["id"] == n["id"]:
                    continue
                if child["id"] in parents and not child.get("options"):
                    found.add(child["id"])
                truncated_parents(child, found, seen)
            return found

        found = truncated_parents(root, set(), set())
        self.assertTrue(found, "fixture must contain a parent that arrived truncated")
        # Those copies look childless, so anything trusting them would both count
        # them as playable and lose everything beneath them.
        self.assertEqual(count_leaves(root), 2)


if __name__ == "__main__":
    unittest.main()
