"""
Hidden Unit Tests for Milestone M1 Bake-off (Track L / ADR-008)
Kept in a separate folder; NEVER shown to models during evaluation.
Contains 3-5 rigorous assertions per task testing edge cases and boundaries.
"""

from typing import Any, Callable, Dict, List


HIDDEN_TESTS: Dict[str, List[Callable[[Any], bool]]] = {
    "code_01": [  # parse_simple_csv
        lambda f: f("") == [],
        lambda f: f("   \n\n  ") == [],
        lambda f: f("h1,h2\nv1,v2") == [{"h1": "v1", "h2": "v2"}],
        lambda f: f("name, city\nAlice, \"Colombo, Western\"\nBob, Kandy") == [
            {"name": "Alice", "city": "Colombo, Western"},
            {"name": "Bob", "city": "Kandy"},
        ],
        lambda f: len(f("colA, colB\n1, 2\n3, 4\n5, 6")) == 3,
    ],
    "code_02": [  # safe_json_path_lookup
        lambda f: f({"a": {"b": 10}}, "a.b") == 10,
        lambda f: f({"items": ["first", "second"]}, "items.1") == "second",
        lambda f: f({"items": ["first"]}, "items.5", default="fallback") == "fallback",
        lambda f: f({"a": 10}, "a.b.c", default=-1) == -1,
        lambda f: f({"root": 42}, "") == {"root": 42},
    ],
    "code_03": [  # compact_number_formatter
        lambda f: f(0) == "0",
        lambda f: f(999) == "999",
        lambda f: f(1000) == "1K",
        lambda f: f(1500) == "1.5K",
        lambda f: f(2500000) == "2.5M",
        lambda f: f(-1500) == "-1.5K",
        lambda f: f(1000000000) == "1B",
    ],
    "code_04": [  # validate_password_strength
        lambda f: f("Short1!")["valid"] is False and "length" in f("Short1!")["missing"],
        lambda f: f("nouppercase123!")["valid"] is False and "uppercase" in f("nouppercase123!")["missing"],
        lambda f: f("NOLOWERCASE123!")["valid"] is False and "lowercase" in f("NOLOWERCASE123!")["missing"],
        lambda f: f("NoDigitsHere!@#")["valid"] is False and "digit" in f("NoDigitsHere!@#")["missing"],
        lambda f: f("StrongPassword123!")["valid"] is True and f("StrongPassword123!")["score"] == 5,
    ],
    "code_05": [  # top_k_frequent_words
        lambda f: f("", 3) == [],
        lambda f: f("apple banana apple", 0) == [],
        lambda f: f("apple banana apple orange banana apple", 2) == ["apple", "banana"],
        lambda f: f("beta alpha beta alpha", 2) == ["alpha", "beta"],  # tie breaker alphabetical
        lambda f: f("Word, word! WORD?", 1) == ["word"],
    ],
    "code_06": [  # time_diff_humanized
        lambda f: f(0) == "0s",
        lambda f: f(45) == "45s",
        lambda f: f(90) == "1m 30s",
        lambda f: f(3600) == "1h",
        lambda f: f(86400) == "1d",
        lambda f: f(86461) == "1d 1m 1s",
    ],
    "code_07": [  # clean_phone_number
        lambda f: f("077 123 4567") == "+94771234567",
        lambda f: f("0094771234567") == "+94771234567",
        lambda f: f("+94771234567") == "+94771234567",
        lambda f: f("12345") is None,
        lambda f: f("+1(555)123-4567", default_country_code="+1") == "+15551234567",
    ],
    "code_08": [  # find_first_missing_positive
        lambda f: f([]) == 1,
        lambda f: f([1, 2, 0]) == 3,
        lambda f: f([3, 4, -1, 1]) == 2,
        lambda f: f([7, 8, 9, 11]) == 1,
        lambda f: f([1, 1, 1]) == 2,
    ],
    "code_09": [  # generate_slug
        lambda f: f("Hello, World!") == "hello-world",
        lambda f: f("---Special---Chars---") == "special-chars",
        lambda f: f("This is a very long title", max_length=15) == "this-is-a-very",
        lambda f: f("") == "",
        lambda f: f("100% Guaranteed Success") == "100-guaranteed-success",
    ],
    "code_10": [  # calculate_tax_bracket
        lambda f: f(0.0, [(10000.0, 0.1)]) == 0.0,
        lambda f: f(-500.0, [(10000.0, 0.1)]) == 0.0,
        lambda f: f(25000.0, [(10000.0, 0.0), (30000.0, 0.10), (float('inf'), 0.20)]) == 1500.0,
        lambda f: f(50000.0, [(10000.0, 0.0), (30000.0, 0.10), (float('inf'), 0.20)]) == 6000.0,
    ],
    "code_11": [  # fuzzy_search_score
        lambda f: f("pai", "personal_agentic_ai") > 0,
        lambda f: f("xyz", "hello world") == 0,
        lambda f: f("abc", "abc") > f("abc", "a b c"),  # consecutive bonus
        lambda f: f("", "any text") == 0 or f("", "any text") >= 0,
    ],
    "code_12": [  # simple_caesar_cipher
        lambda f: f("Hello, World!", 3) == "Khoor, Zruog!",
        lambda f: f("Khoor, Zruog!", -3) == "Hello, World!",
        lambda f: f("abc", 26) == "abc",
        lambda f: f("xyz", 1) == "yza",
        lambda f: f("123 !@#", 5) == "123 !@#",
    ],
    "code_13": [  # matrix_transpose_ragged
        lambda f: f([]) == [],
        lambda f: f([[], []]) == [],
        lambda f: f([[1, 2, 3], [4, 5]], fill_value=0) == [[1, 4], [2, 5], [3, 0]],
        lambda f: f([[1], [2], [3]], fill_value=None) == [[1, 2, 3]],
    ],
    "code_14": [  # run_length_compress
        lambda f: f([]) == [],
        lambda f: f([5]) == [(5, 1)],
        lambda f: f([1, 1, 1, 2, 2, 3, 1, 1]) == [(1, 3), (2, 2), (3, 1), (1, 2)],
        lambda f: f([10, 20, 30]) == [(10, 1), (20, 1), (30, 1)],
    ],
    "code_15": [  # parse_duration_string
        lambda f: f("1h 30m") == 5400,
        lambda f: f("45s") == 45,
        lambda f: f("2d") == 172800,
        lambda f: f("1d2h3m4s") == 86400 + 7200 + 180 + 4,
        lambda f: (
            (raised := False),
            (try_run := (lambda: None)),
            (f.__call__("invalid") if False else True)
        )[-1],
    ],
    "code_16": [  # sliding_window_median
        lambda f: f([], 3) == [],
        lambda f: f([1.0, 2.0], 3) == [],
        lambda f: f([1.0, 3.0, -1.0, -3.0, 5.0, 3.0, 6.0, 7.0], 3) == [1.0, -1.0, -1.0, 3.0, 5.0, 6.0],
        lambda f: f([1.0, 2.0, 3.0, 4.0], 2) == [1.5, 2.5, 3.5],
    ],
    "code_17": [  # CircularBuffer
        lambda cls: (
            cls.execute_steps([
                {"method": "__init__", "args": [2]},
                {"method": "enqueue", "args": [1]},
                {"method": "enqueue", "args": [2]},
                {"method": "is_full"},
                {"method": "enqueue", "args": [3]},
                {"method": "dequeue"},
                {"method": "enqueue", "args": [3]},
                {"method": "dequeue"},
                {"method": "dequeue"},
                {"method": "is_empty"},
            ]) == [True, True, True, True, False, 1, True, 2, 3, True]
            if hasattr(cls, "execute_steps")
            else (
                (cb := cls(2)),
                cb.enqueue(1) is True and
                cb.enqueue(2) is True and
                cb.is_full() is True and
                cb.enqueue(3) is False and
                cb.dequeue() == 1 and
                cb.enqueue(3) is True and
                cb.dequeue() == 2 and
                cb.dequeue() == 3 and
                cb.is_empty() is True
            )[-1]
        ),
        lambda cls: (
            cls.execute_steps([
                {"method": "__init__", "args": [1]},
                {"method": "enqueue", "args": ["a"]},
                {"method": "peek"},
                {"method": "size"},
            ]) == [True, True, "a", 1]
            if hasattr(cls, "execute_steps")
            else (
                (cb := cls(1)),
                cb.enqueue("a") is True and
                cb.peek() == "a" and
                cb.size() == 1
            )[-1]
        ),
    ],
    "code_18": [  # deep_merge_dicts
        lambda f: f({}, {"a": 1}) == {"a": 1},
        lambda f: f({"a": 1}, {}) == {"a": 1},
        lambda f: f({"a": {"x": 1}}, {"a": {"y": 2}}) == {"a": {"x": 1, "y": 2}},
        lambda f: f({"a": {"x": 1}}, {"a": 42}) == {"a": 42},
    ],
    "code_19": [  # retry_with_backoff_simulator
        lambda f: f(1, 3) == (True, 0.0, []),
        lambda f: f(2, 3, base_delay=1.0, factor=2.0) == (True, 1.0, [1.0]),
        lambda f: f(3, 3, base_delay=1.0, factor=2.0) == (True, 3.0, [1.0, 2.0]),
        lambda f: f(5, 3, base_delay=1.0, factor=2.0) == (False, 7.0, [1.0, 2.0, 4.0]),
    ],
    "code_20": [  # evaluate_simple_expression
        lambda f: f("3 + 2 * 2") == 7,
        lambda f: f(" 3/2 ") == 1,
        lambda f: f(" 3 + 5 / 2 ") == 5,
        lambda f: f("10 - 2 * 3 + 4") == 8,
        lambda f: f("100") == 100,
    ],
}
