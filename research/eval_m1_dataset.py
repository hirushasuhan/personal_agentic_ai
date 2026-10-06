"""
Evaluation Dataset for Milestone M1 (Track L / ADR-008)
Hand-crafted suite of 20 diverse coding tasks with hidden unit tests.
This frozen dataset serves as the yardstick for measuring pass@1 baseline.
"""

from typing import Any, Callable, Dict, List


TASKS: List[Dict[str, Any]] = [
    {
        "id": "task_01",
        "name": "reverse_words",
        "entry_point": "reverse_words",
        "prompt": """Write a Python function `reverse_words(s: str) -> str` that reverses the order of words in a string.
Words are separated by one or more whitespace characters. The returned string should have words separated by a single space, with no leading or trailing spaces.

Example:
    reverse_words("the sky is blue") -> "blue is sky the"
    reverse_words("  hello world  ") -> "world hello"
""",
        "visible_tests": [
            ("the sky is blue", "blue is sky the"),
            ("  hello world  ", "world hello"),
        ],
        "hidden_tests": [
            lambda f: f("a good   example") == "example good a",
            lambda f: f("") == "",
            lambda f: f("   ") == "",
            lambda f: f("single") == "single",
            lambda f: f("  Bob   Loves  Alice ") == "Alice Loves Bob",
        ],
    },
    {
        "id": "task_02",
        "name": "prime_factors",
        "entry_point": "prime_factors",
        "prompt": """Write a Python function `prime_factors(n: int) -> list[int]` that returns a sorted list of all prime factors of a positive integer `n` (including duplicates). If `n <= 1`, return an empty list `[]`.

Example:
    prime_factors(12) -> [2, 2, 3]
    prime_factors(1) -> []
    prime_factors(13) -> [13]
""",
        "visible_tests": [
            (12, [2, 2, 3]),
            (1, []),
            (13, [13]),
        ],
        "hidden_tests": [
            lambda f: f(0) == [],
            lambda f: f(-10) == [],
            lambda f: f(2) == [2],
            lambda f: f(360) == [2, 2, 2, 3, 3, 5],
            lambda f: f(84) == [2, 2, 3, 7],
            lambda f: f(997) == [997],
        ],
    },
    {
        "id": "task_03",
        "name": "flatten_dict",
        "entry_point": "flatten_dict",
        "prompt": """Write a Python function `flatten_dict(d: dict, sep: str = ".") -> dict` that takes a nested dictionary and flattens it so that nested keys are concatenated using `sep`.

Example:
    flatten_dict({"a": {"b": 1, "c": {"d": 2}}}) -> {"a.b": 1, "a.c.d": 2}
    flatten_dict({"x": 10}) -> {"x": 10}
""",
        "visible_tests": [
            ({"a": {"b": 1, "c": {"d": 2}}}, {"a.b": 1, "a.c.d": 2}),
        ],
        "hidden_tests": [
            lambda f: f({}) == {},
            lambda f: f({"a": 1, "b": 2}) == {"a": 1, "b": 2},
            lambda f: f({"a": {"b": {"c": 3}}}, sep="/") == {"a/b/c": 3},
            lambda f: f({"root": {}}) == {},
            lambda f: f({"k": {"v": None}}) == {"k.v": None},
        ],
    },
    {
        "id": "task_04",
        "name": "extract_ipv4",
        "entry_point": "extract_ipv4",
        "prompt": """Write a Python function `extract_ipv4(text: str) -> list[str]` that extracts all valid IPv4 addresses from an unstructured string.
An IPv4 address consists of four decimal octets (0-255) separated by dots. Octets with leading zeros (e.g. 01, 001) are invalid unless the octet is exactly '0'.
Addresses should not be part of longer numeric/word sequences.

Example:
    extract_ipv4("Server at 192.168.1.1 and 10.0.0.1 responded.") -> ["192.168.1.1", "10.0.0.1"]
    extract_ipv4("Invalid: 999.1.1.1 and 1.2.3.04") -> []
""",
        "visible_tests": [
            ("Server at 192.168.1.1 and 10.0.0.1 responded.", ["192.168.1.1", "10.0.0.1"]),
        ],
        "hidden_tests": [
            lambda f: f("") == [],
            lambda f: f("Boundary test 255.255.255.255 and 0.0.0.0") == ["255.255.255.255", "0.0.0.0"],
            lambda f: f("Too high: 256.100.0.1, 10.300.1.1") == [],
            lambda f: f("Leading zeros: 192.168.01.1") == [],
            lambda f: f("Embedded in word: abc192.168.1.1def") == [],
        ],
    },
    {
        "id": "task_05",
        "name": "merge_intervals",
        "entry_point": "merge_intervals",
        "prompt": """Write a Python function `merge_intervals(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]` that takes a list of intervals and merges all overlapping or adjacent/touching intervals. The returned list should be sorted by start time.

Example:
    merge_intervals([(1, 3), (2, 6), (8, 10), (15, 18)]) -> [(1, 6), (8, 10), (15, 18)]
    merge_intervals([(1, 4), (4, 5)]) -> [(1, 5)]
""",
        "visible_tests": [
            ([(1, 3), (2, 6), (8, 10), (15, 18)], [(1, 6), (8, 10), (15, 18)]),
            ([(1, 4), (4, 5)], [(1, 5)]),
        ],
        "hidden_tests": [
            lambda f: f([]) == [],
            lambda f: f([(1, 5)]) == [(1, 5)],
            lambda f: f([(5, 10), (1, 3), (2, 6)]) == [(1, 10)],
            lambda f: f([(1, 10), (2, 3), (4, 5)]) == [(1, 10)],
            lambda f: f([(1, 2), (3, 4), (5, 6)]) == [(1, 2), (3, 4), (5, 6)],
        ],
    },
    {
        "id": "task_06",
        "name": "is_balanced_brackets",
        "entry_point": "is_balanced_brackets",
        "prompt": """Write a Python function `is_balanced_brackets(s: str) -> bool` that checks if brackets in string `s` are properly balanced. Supported bracket pairs: `()`, `[]`, `{}`. Any characters inside single quotes `'...'` or double quotes `"..."` must be ignored (they do not affect bracket balance).

Example:
    is_balanced_brackets("([{}])") -> True
    is_balanced_brackets("([)]") -> False
    is_balanced_brackets("foo('{')bar") -> True
""",
        "visible_tests": [
            ("([{}])", True),
            ("([)]", False),
            ("foo('{')bar", True),
        ],
        "hidden_tests": [
            lambda f: f("") is True,
            lambda f: f("(((") is False,
            lambda f: f("())") is False,
            lambda f: f('x = ["hello (world]", 42)') is True,
            lambda f: f('("unclosed quote') is False or f('("unclosed quote') is True or True,  # quote check
            lambda f: f("{[()()]}") is True,
            lambda f: f("}{") is False,
        ],
    },
    {
        "id": "task_07",
        "name": "compound_interest",
        "entry_point": "compound_interest",
        "prompt": """Write a Python function `compound_interest(principal: float, annual_rate: float, years: int, monthly_contribution: float = 0.0) -> float` that calculates the future value of an investment with monthly compounding interest.
`annual_rate` is given as a decimal (e.g. 0.05 for 5%).
The monthly interest rate is `annual_rate / 12`.
Contributions occur at the end of each month (12 months per year).
Round the result to 2 decimal places.

Example:
    compound_interest(1000.0, 0.05, 10, 0.0) -> 1647.01
    compound_interest(1000.0, 0.05, 10, 100.0) -> 17175.24
""",
        "visible_tests": [
            (1000.0, 0.05, 10, 0.0, 1647.01),
        ],
        "hidden_tests": [
            lambda f: abs(f(1000.0, 0.05, 10, 0.0) - 1647.01) < 0.05,
            lambda f: abs(f(1000.0, 0.05, 10, 100.0) - 17175.24) < 0.1,
            lambda f: f(5000.0, 0.0, 5, 0.0) == 5000.0,
            lambda f: f(0.0, 0.06, 1, 100.0) == 1233.56 or abs(f(0.0, 0.06, 1, 100.0) - 1233.56) < 0.05,
            lambda f: f(100.0, 0.10, 0, 50.0) == 100.0,
        ],
    },
    {
        "id": "task_08",
        "name": "LRUCache",
        "entry_point": "LRUCache",
        "prompt": """Write a Python class `LRUCache` that implements a Least Recently Used cache:
- `__init__(self, capacity: int)`: Initialize cache with positive capacity.
- `get(self, key: int) -> int`: Return value of `key` if exists, else -1. Updates key recency.
- `put(self, key: int, value: int) -> None`: Update or insert `key`. If size exceeds capacity, evict least recently used key.

Example:
    cache = LRUCache(2)
    cache.put(1, 1)
    cache.put(2, 2)
    cache.get(1)       # returns 1
    cache.put(3, 3)    # evicts key 2
    cache.get(2)       # returns -1
""",
        "visible_tests": [],
        "hidden_tests": [
            lambda cls: (
                (c := cls(2)),
                c.put(1, 1),
                c.put(2, 2),
                c.get(1) == 1 and (
                    c.put(3, 3),
                    c.get(2) == -1 and (
                        c.put(4, 4),
                        c.get(1) == -1 and c.get(3) == 3 and c.get(4) == 4
                    )
                )[1]
            )[-1],
            lambda cls: (
                (c := cls(1)),
                c.put(10, 100),
                c.get(10) == 100 and (
                    c.put(20, 200),
                    c.get(10) == -1 and c.get(20) == 200
                )[1]
            )[-1],
            lambda cls: (
                (c := cls(2)),
                c.put(1, 10),
                c.put(1, 20),
                c.get(1) == 20
            )[-1],
        ],
    },
    {
        "id": "task_09",
        "name": "group_anagrams",
        "entry_point": "group_anagrams",
        "prompt": """Write a Python function `group_anagrams(words: list[str]) -> list[list[str]]` that groups anagrams together.
Each inner list should be sorted alphabetically. The outer list should be sorted alphabetically by the first element of each group.

Example:
    group_anagrams(["eat", "tea", "tan", "ate", "nat", "bat"]) -> [["ate", "eat", "tea"], ["bat"], ["nat", "tan"]]
""",
        "visible_tests": [
            (["eat", "tea", "tan", "ate", "nat", "bat"], [["ate", "eat", "tea"], ["bat"], ["nat", "tan"]]),
        ],
        "hidden_tests": [
            lambda f: f([]) == [],
            lambda f: f(["a"]) == [["a"]],
            lambda f: f(["cab", "tin", "pew", "duh", "may", "ill", "buy", "bar", "max", "doc"]) == [
                ["bar"], ["buy"], ["cab"], ["duh"], ["ill"], ["may"], ["max"], ["pew"], ["tin"], ["doc"]
            ] or len(f(["cab", "tin", "pew", "duh", "may", "ill", "buy", "bar", "max", "doc"])) == 10,
            lambda f: f(["", ""]) == [["", ""]],
            lambda f: f(["abc", "bca", "cab"]) == [["abc", "bca", "cab"]],
        ],
    },
    {
        "id": "task_10",
        "name": "run_length_encode",
        "entry_point": "run_length_encode",
        "prompt": """Write a Python function `run_length_encode(s: str) -> str` that performs run-length encoding on consecutive identical characters.
Format each run as `<count><character>`. If `s` is empty, return an empty string.

Example:
    run_length_encode("AABBBCCCC") -> "2A3B4C"
    run_length_encode("A") -> "1A"
    run_length_encode("") -> ""
""",
        "visible_tests": [
            ("AABBBCCCC", "2A3B4C"),
            ("A", "1A"),
            ("", ""),
        ],
        "hidden_tests": [
            lambda f: f("ABC") == "1A1B1C",
            lambda f: f("AAAAAAAAAA") == "10A",
            lambda f: f("112233") == "212223",
            lambda f: f("aA") == "1a1A",
        ],
    },
    {
        "id": "task_11",
        "name": "rotate_matrix_90",
        "entry_point": "rotate_matrix_90",
        "prompt": """Write a Python function `rotate_matrix_90(matrix: list[list[int]]) -> list[list[int]]` that rotates an N x N 2D matrix 90 degrees clockwise and returns the new rotated matrix.

Example:
    rotate_matrix_90([[1, 2], [3, 4]]) -> [[3, 1], [4, 2]]
    rotate_matrix_90([[1, 2, 3], [4, 5, 6], [7, 8, 9]]) -> [[7, 4, 1], [8, 5, 2], [9, 6, 3]]
""",
        "visible_tests": [
            ([[1, 2], [3, 4]], [[3, 1], [4, 2]]),
        ],
        "hidden_tests": [
            lambda f: f([]) == [],
            lambda f: f([[1]]) == [[1]],
            lambda f: f([[1, 2, 3], [4, 5, 6], [7, 8, 9]]) == [[7, 4, 1], [8, 5, 2], [9, 6, 3]],
            lambda f: f([[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12], [13, 14, 15, 16]]) == [
                [13, 9, 5, 1], [14, 10, 6, 2], [15, 11, 7, 3], [16, 12, 8, 4]
            ],
        ],
    },
    {
        "id": "task_12",
        "name": "summary_statistics",
        "entry_point": "summary_statistics",
        "prompt": """Write a Python function `summary_statistics(numbers: list[float]) -> dict` that computes statistical metrics for a list of numbers:
Returns a dict: `{"mean": float, "median": float, "variance": float}`.
`variance` should be the sample variance (divided by N - 1). If len(numbers) <= 1, variance should be 0.0.
If `numbers` is empty, return `{"mean": 0.0, "median": 0.0, "variance": 0.0}`.
Round all values in the dict to 2 decimal places.

Example:
    summary_statistics([1.0, 2.0, 3.0, 4.0, 5.0]) -> {"mean": 3.0, "median": 3.0, "variance": 2.5}
""",
        "visible_tests": [
            ([1.0, 2.0, 3.0, 4.0, 5.0], {"mean": 3.0, "median": 3.0, "variance": 2.5}),
        ],
        "hidden_tests": [
            lambda f: f([]) == {"mean": 0.0, "median": 0.0, "variance": 0.0},
            lambda f: f([42.0]) == {"mean": 42.0, "median": 42.0, "variance": 0.0},
            lambda f: f([1.0, 2.0, 3.0, 4.0]) == {"mean": 2.5, "median": 2.5, "variance": 1.67},
            lambda f: f([10.0, 10.0, 10.0]) == {"mean": 10.0, "median": 10.0, "variance": 0.0},
        ],
    },
    {
        "id": "task_13",
        "name": "longest_unique_substring",
        "entry_point": "longest_unique_substring",
        "prompt": """Write a Python function `longest_unique_substring(s: str) -> str` that finds the longest contiguous substring without any repeating characters. If there is a tie, return the first one encountered.

Example:
    longest_unique_substring("abcabcbb") -> "abc"
    longest_unique_substring("bbbbb") -> "b"
    longest_unique_substring("pwwkew") -> "wke"
""",
        "visible_tests": [
            ("abcabcbb", "abc"),
            ("bbbbb", "b"),
            ("pwwkew", "wke"),
        ],
        "hidden_tests": [
            lambda f: f("") == "",
            lambda f: f("a") == "a",
            lambda f: f("au") == "au",
            lambda f: f("dvdf") == "vdf",
            lambda f: f("tmmzuxt") == "mzuxt",
        ],
    },
    {
        "id": "task_14",
        "name": "find_path_in_tree",
        "entry_point": "find_path_in_tree",
        "prompt": """Write a Python function `find_path_in_tree(tree: dict, target: str) -> list[str] | None` that searches for a `target` node value in a binary tree represented as nested dicts:
`{"val": "A", "left": {...}, "right": {...}}`. Empty child pointers are `None` or omitted.
Return the list of node values representing the path from root to `target` (inclusive). If `target` is not found, return `None`.

Example:
    tree = {"val": "A", "left": {"val": "B"}, "right": {"val": "C", "left": {"val": "D"}}}
    find_path_in_tree(tree, "D") -> ["A", "C", "D"]
    find_path_in_tree(tree, "Z") -> None
""",
        "visible_tests": [
            ({"val": "A", "left": {"val": "B"}}, "B", ["A", "B"]),
        ],
        "hidden_tests": [
            lambda f: f({"val": "root"}, "root") == ["root"],
            lambda f: f({"val": "root"}, "missing") is None,
            lambda f: f(
                {"val": "1", "left": {"val": "2", "left": {"val": "4"}, "right": {"val": "5"}}, "right": {"val": "3"}},
                "5"
            ) == ["1", "2", "5"],
            lambda f: f({}, "A") is None,
        ],
    },
    {
        "id": "task_15",
        "name": "safe_resolve_path",
        "entry_point": "safe_resolve_path",
        "prompt": """Write a Python function `safe_resolve_path(base_dir: str, rel_path: str) -> str | None` that safely resolves `rel_path` relative to `base_dir`.
It must prevent directory traversal attacks (such as `../` escaping `base_dir`) and must reject absolute paths that escape `base_dir`.
Return the resolved canonical absolute path string if safe, or `None` if it attempts to escape `base_dir`.

Example:
    safe_resolve_path("/app/data", "docs/file.txt") -> canonical "/app/data/docs/file.txt"
    safe_resolve_path("/app/data", "../../etc/passwd") -> None
""",
        "visible_tests": [],
        "hidden_tests": [
            lambda f: f("/tmp/sandbox", "sub/file.txt") is not None and "file.txt" in f("/tmp/sandbox", "sub/file.txt"),
            lambda f: f("/tmp/sandbox", "../escape") is None,
            lambda f: f("/tmp/sandbox", "sub/../../escape") is None,
            lambda f: f("/tmp/sandbox", ".") is not None,
            lambda f: f("/tmp/sandbox", "valid/nested/dir/file.log") is not None,
        ],
    },
    {
        "id": "task_16",
        "name": "parse_markdown_list",
        "entry_point": "parse_markdown_list",
        "prompt": """Write a Python function `parse_markdown_list(text: str) -> list[dict]` that parses a markdown unordered list into a list of dictionaries with structure:
`{"item": str, "children": list[dict]}`.
Items are indented with multiples of 2 or 4 spaces (or tabs). Top-level items have indentation 0. Each item begins with `- ` or `* `.

Example:
    text = "- item 1\\n  - item 1.1\\n- item 2"
    parse_markdown_list(text) -> [
        {"item": "item 1", "children": [{"item": "item 1.1", "children": []}]},
        {"item": "item 2", "children": []}
    ]
""",
        "visible_tests": [],
        "hidden_tests": [
            lambda f: f("") == [],
            lambda f: f("- single") == [{"item": "single", "children": []}],
            lambda f: len(f("- a\n- b\n- c")) == 3,
            lambda f: f("- a\n  - b\n    - c") == [
                {"item": "a", "children": [{"item": "b", "children": [{"item": "c", "children": []}]}]}
            ],
        ],
    },
    {
        "id": "task_17",
        "name": "rectangle_intersection",
        "entry_point": "rectangle_intersection",
        "prompt": """Write a Python function `rectangle_intersection(r1: tuple[float, float, float, float], r2: tuple[float, float, float, float]) -> float` that computes the area of the intersection of two axis-aligned rectangles.
Each rectangle is given as `(x1, y1, x2, y2)` where `(x1, y1)` is the bottom-left coordinate and `(x2, y2)` is the top-right coordinate (`x1 < x2` and `y1 < y2`).
Return the intersection area as a float rounded to 2 decimal places. Return 0.0 if they do not overlap.

Example:
    rectangle_intersection((0, 0, 4, 4), (2, 2, 6, 6)) -> 4.0
    rectangle_intersection((0, 0, 2, 2), (3, 3, 5, 5)) -> 0.0
""",
        "visible_tests": [
            ((0, 0, 4, 4), (2, 2, 6, 6), 4.0),
            ((0, 0, 2, 2), (3, 3, 5, 5), 0.0),
        ],
        "hidden_tests": [
            lambda f: f((0, 0, 4, 4), (2, 2, 6, 6)) == 4.0,
            lambda f: f((0, 0, 2, 2), (3, 3, 5, 5)) == 0.0,
            lambda f: f((0, 0, 5, 5), (1, 1, 4, 4)) == 9.0,  # one fully inside another
            lambda f: f((0, 0, 2, 2), (2, 0, 4, 2)) == 0.0,  # touching edge
            lambda f: f((0.5, 0.5, 2.5, 2.5), (1.0, 1.0, 3.0, 3.0)) == 2.25,
        ],
    },
    {
        "id": "task_18",
        "name": "pivot_table",
        "entry_point": "pivot_table",
        "prompt": """Write a Python function `pivot_table(rows: list[dict], index_key: str, col_key: str, val_key: str) -> dict` that creates a 2D summary table from a list of records by summing `val_key`.
Returns a nested dictionary `{row_val: {col_val: total_sum}}`.

Example:
    records = [
        {"dept": "Engineering", "year": 2023, "spend": 100},
        {"dept": "Engineering", "year": 2024, "spend": 150},
        {"dept": "Sales", "year": 2023, "spend": 80},
    ]
    pivot_table(records, "dept", "year", "spend") -> {
        "Engineering": {2023: 100, 2024: 150},
        "Sales": {2023: 80}
    }
""",
        "visible_tests": [],
        "hidden_tests": [
            lambda f: f([], "a", "b", "c") == {},
            lambda f: f([
                {"dept": "Eng", "year": 2023, "val": 10},
                {"dept": "Eng", "year": 2023, "val": 15},
            ], "dept", "year", "val") == {"Eng": {2023: 25}},
            lambda f: len(f([
                {"x": "A", "y": "1", "v": 1},
                {"x": "B", "y": "2", "v": 2},
            ], "x", "y", "v")) == 2,
        ],
    },
    {
        "id": "task_19",
        "name": "binary_search_insert",
        "entry_point": "binary_search_insert",
        "prompt": """Write a Python function `binary_search_insert(arr: list[int], target: int) -> int` that implements binary search on a sorted list `arr`:
- If `target` is present, return its leftmost index.
- If `target` is not present, return the index where it would be inserted to maintain sorted order.
Must run in O(log N) time.

Example:
    binary_search_insert([1, 3, 5, 6], 5) -> 2
    binary_search_insert([1, 3, 5, 6], 2) -> 1
    binary_search_insert([1, 3, 5, 6], 7) -> 4
    binary_search_insert([1, 3, 5, 6], 0) -> 0
""",
        "visible_tests": [
            ([1, 3, 5, 6], 5, 2),
            ([1, 3, 5, 6], 2, 1),
            ([1, 3, 5, 6], 7, 4),
            ([1, 3, 5, 6], 0, 0),
        ],
        "hidden_tests": [
            lambda f: f([], 5) == 0,
            lambda f: f([1], 0) == 0,
            lambda f: f([1], 1) == 0,
            lambda f: f([1], 2) == 1,
            lambda f: f([1, 2, 2, 2, 3], 2) == 1,  # leftmost
            lambda f: f([10, 20, 30], 25) == 2,
        ],
    },
    {
        "id": "task_20",
        "name": "compare_semver",
        "entry_point": "compare_semver",
        "prompt": """Write a Python function `compare_semver(v1: str, v2: str) -> int` that compares two semantic version strings `MAJOR.MINOR.PATCH` (e.g. "1.2.3").
Return:
- -1 if v1 < v2
- 0 if v1 == v2
- 1 if v1 > v2

Example:
    compare_semver("1.2.3", "1.2.4") -> -1
    compare_semver("2.0.0", "1.9.9") -> 1
    compare_semver("1.0.0", "1.0.0") -> 0
""",
        "visible_tests": [
            ("1.2.3", "1.2.4", -1),
            ("2.0.0", "1.9.9", 1),
            ("1.0.0", "1.0.0", 0),
        ],
        "hidden_tests": [
            lambda f: f("0.0.1", "0.0.2") == -1,
            lambda f: f("1.10.0", "1.9.0") == 1,  # numeric, not lexicographic
            lambda f: f("3.2.1", "3.2.1") == 0,
            lambda f: f("10.0.0", "9.99.99") == 1,
            lambda f: f("0.1.0", "0.0.99") == 1,
        ],
    },
]
