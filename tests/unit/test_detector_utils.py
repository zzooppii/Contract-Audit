"""Unit tests for shared detector utility functions."""

import pytest

from contract_audit.detectors.utils import (
    extract_functions,
    strip_comments,
    strip_interfaces,
)


class TestStripComments:
    def test_single_line_comments(self):
        source = "uint x = 1; // inline comment\n// full line comment\nuint y = 2;"
        result = strip_comments(source)
        assert "inline comment" not in result
        assert "full line comment" not in result
        assert "uint x = 1;" in result
        assert "uint y = 2;" in result

    def test_multi_line_comments(self):
        source = "uint x = 1;\n/* this is\na multi-line\ncomment */\nuint y = 2;"
        result = strip_comments(source)
        assert "multi-line" not in result
        assert "uint x = 1;" in result
        assert "uint y = 2;" in result

    def test_nested_comment_styles(self):
        source = "// outer /* inner */\nuint x = 1;"
        result = strip_comments(source)
        assert "outer" not in result
        assert "uint x = 1;" in result

    def test_string_containing_comment_chars(self):
        """Comment-like chars inside strings get stripped (known limitation)."""
        source = 'string s = "hello // world";'
        result = strip_comments(source)
        # The regex strips // even inside strings — document this behavior
        assert "hello" in result

    def test_empty_input(self):
        assert strip_comments("") == ""

    def test_no_comments(self):
        source = "uint x = 1;\nuint y = 2;"
        assert strip_comments(source) == source


class TestStripInterfaces:
    def test_single_interface(self):
        source = (
            "interface IERC20 {\n"
            "    function transfer(address, uint) external;\n"
            "}\n"
            "contract Token { uint x; }"
        )
        result = strip_interfaces(source)
        assert "IERC20" not in result
        assert "contract Token" in result

    def test_multiple_interfaces(self):
        source = (
            "interface IA { function a() external; }\n"
            "interface IB { function b() external; }\n"
            "contract C { uint x; }"
        )
        result = strip_interfaces(source)
        assert "IA" not in result
        assert "IB" not in result
        assert "contract C" in result

    def test_empty_interface(self):
        source = "interface IEmpty { }\ncontract C { uint x; }"
        result = strip_interfaces(source)
        assert "IEmpty" not in result
        assert "contract C" in result

    def test_no_interfaces(self):
        source = "contract Foo { uint x; }"
        assert strip_interfaces(source) == source

    def test_empty_input(self):
        assert strip_interfaces("") == ""


class TestExtractFunctions:
    def test_single_function(self):
        source = (
            "contract Foo {\n"
            "    function bar() public {\n"
            "        uint x = 1;\n"
            "    }\n"
            "}"
        )
        funcs = extract_functions(source)
        assert len(funcs) == 1
        assert funcs[0]["name"] == "bar"
        assert funcs[0]["visibility"] == "public"
        assert not funcs[0]["is_view_pure"]
        assert "uint x = 1" in funcs[0]["body"]

    def test_multiple_functions(self):
        source = (
            "contract Foo {\n"
            "    function a() external { }\n"
            "    function b() public view returns (uint) { return 1; }\n"
            "}"
        )
        funcs = extract_functions(source)
        assert len(funcs) == 2
        assert funcs[0]["name"] == "a"
        assert funcs[0]["visibility"] == "external"
        assert funcs[1]["name"] == "b"
        assert funcs[1]["is_view_pure"] is True

    def test_multiline_signature(self):
        source = (
            "contract Foo {\n"
            "    function bar(\n"
            "        uint a,\n"
            "        uint b\n"
            "    ) public returns (uint) {\n"
            "        return a + b;\n"
            "    }\n"
            "}"
        )
        funcs = extract_functions(source)
        assert len(funcs) == 1
        assert funcs[0]["name"] == "bar"
        assert "signature" in funcs[0]

    def test_empty_input(self):
        assert extract_functions("") == []

    def test_no_functions(self):
        source = "contract Foo { uint x; mapping(address => uint) balances; }"
        assert extract_functions(source) == []

    def test_skips_interface_functions(self):
        source = (
            "interface IFoo {\n"
            "    function bar() external;\n"
            "}\n"
            "contract Foo {\n"
            "    function baz() public { }\n"
            "}"
        )
        funcs = extract_functions(source)
        assert len(funcs) == 1
        assert funcs[0]["name"] == "baz"

    def test_start_line_is_1_indexed(self):
        source = "contract Foo {\n    function bar() public { }\n}"
        funcs = extract_functions(source)
        assert funcs[0]["start"] == 2

    def test_private_visibility(self):
        source = "contract Foo {\n    function _internal() private { }\n}"
        funcs = extract_functions(source)
        assert funcs[0]["visibility"] == "private"

    def test_pure_function(self):
        source = "contract Foo {\n    function add(uint a, uint b) internal pure returns (uint) { return a + b; }\n}"
        funcs = extract_functions(source)
        assert funcs[0]["is_view_pure"] is True
