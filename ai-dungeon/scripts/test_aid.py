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

from aid import child_nodes, count_leaves, collect_leaves  # noqa: E402


def node(nid, title, options=None, **extra):
    n = {"id": nid, "shortId": nid, "title": title, "options": options or []}
    n.update(extra)
    return n


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


if __name__ == "__main__":
    unittest.main()
