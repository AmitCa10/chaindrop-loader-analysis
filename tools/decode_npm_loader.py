#!/usr/bin/env python3
import argparse
import ast
import hashlib
import json
import math
import re
import urllib.parse
from pathlib import Path

EXPECTED_SHA256 = "54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668"


def evaluate_arithmetic(expression):
    def evaluate(node):
        if isinstance(node, ast.Expression):
            return evaluate(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return node.value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
            value = evaluate(node.operand)
            return value if isinstance(node.op, ast.UAdd) else -value
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub, ast.Mult, ast.Div)):
            left = evaluate(node.left)
            right = evaluate(node.right)
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            return left / right
        raise ValueError(f"Unsupported arithmetic expression: {ast.dump(node)}")

    return evaluate(ast.parse(expression, mode="eval"))


def javascript_parse_int(value):
    match = re.match(r"^\s*([+-]?\d+)", value)
    return int(match.group(1)) if match else math.nan


def decode_base64(value):
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
    accumulator = 0
    bits = 0
    decoded = bytearray()
    for character in value:
        if character == "=":
            break
        index = alphabet.find(character)
        if index < 0:
            continue
        accumulator = (accumulator << 6) | index
        bits += 6
        if bits >= 8:
            bits -= 8
            decoded.append((accumulator >> bits) & 0xFF)
            accumulator &= (1 << bits) - 1
    return urllib.parse.unquote("".join(f"%{byte:02x}" for byte in decoded))


def rc4(value, key):
    decoded = decode_base64(value)
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + ord(key[i % len(key)])) % 256
        state[i], state[j] = state[j], state[i]
    i = 0
    j = 0
    output = []
    for character in decoded:
        i = (i + 1) % 256
        j = (j + state[i]) % 256
        state[i], state[j] = state[j], state[i]
        output.append(chr(ord(character) ^ state[(state[i] + state[j]) % 256]))
    return "".join(output)


def decode_sample(source):
    array_match = re.search(r"function w\(\)\{const Tt=(\[.*?\]);w=function", source, re.DOTALL)
    target_match = re.search(r"\}\(w,(.*?)\)\);", source, re.DOTALL)
    offset_match = re.search(r"T=T-\((.*?)\);", source, re.DOTALL)
    rotation_match = re.search(r"const J=(.*?);if\(J===f\)", source, re.DOTALL)
    constants_match = re.search(r"const wS=\{(.*?)\};function Y", source, re.DOTALL)
    if not all((array_match, target_match, offset_match, rotation_match, constants_match)):
        raise ValueError("Unexpected npm loader structure")

    strings = ast.literal_eval(array_match.group(1))
    target = evaluate_arithmetic(target_match.group(1))
    offset = evaluate_arithmetic(offset_match.group(1))
    constants = {}
    raw_constants = {}
    for object_name, content in re.findall(r"([A-Za-z0-9]{1,3})=\{([^{}]*)\}", source, re.DOTALL):
        for name, value in re.findall(r"([A-Za-z]+):('[^']*'|0x[0-9a-f]+|\d+)", content):
            raw_constants[(object_name, name)] = value.strip("'")
            try:
                constants[(object_name, name)] = int(value.strip("'"), 0)
            except ValueError:
                continue

    def decode_key(value):
        if value.startswith(("'", '"')):
            return value[1:-1]
        if "." in value:
            object_name, name = value.split(".", 1)
            return raw_constants.get((object_name, name), value)
        return value

    def evaluate(value):
        value = re.sub(r"'([^']*)'", r"\1", value)
        value = re.sub(r'"([^"]*)"', r"\1", value)
        value = re.sub(r"([+-])0x", r"\1 0x", value)
        for (object_name, name), constant in constants.items():
            value = re.sub(rf"\b{object_name}\.{name}\b", str(constant), value)
        value = value.strip()
        if value.startswith("-"):
            return -evaluate_arithmetic(value[1:].strip())
        return evaluate_arithmetic(value)

    def decode_index(function_name, value):
        if function_name == "Y":
            return evaluate(value) + 0x2B4 - offset
        if function_name == "b":
            return evaluate(value) - 0x235 - offset
        return evaluate(value) - offset

    rotation_call = re.compile(r"parseInt\((Y)\(([^,]+),([^)]+)\)\)")
    rotation_expression = re.sub(r"Y\('([^']*)',", r"Y(\1,", rotation_match.group(1))
    rotation_expression = re.sub(r"Y\(-'([^']*)',", r"Y(-\1,", rotation_expression)
    for _ in range(len(strings) * 2):
        try:
            expression = rotation_call.sub(
                lambda match: str(javascript_parse_int(rc4(strings[decode_index("Y", match.group(2))], decode_key(match.group(3))))),
                rotation_expression,
            )
            if evaluate_arithmetic(expression) == target:
                break
        except (ArithmeticError, IndexError, UnicodeError, ValueError):
            pass
        strings.append(strings.pop(0))
    else:
        raise ValueError("Unable to resolve string-array rotation")

    aliases = {"Y": ("i", -0x2B4), "b": ("i", 0x235), "i": ("i", 0)}
    for alias, wrapper, delta_expression in re.findall(
        r"function ([A-Za-z]+)\(e,f\)\{return ([bi])\(e-([^,]+),f\);\}",
        source,
    ):
        aliases[alias] = (wrapper, evaluate(delta_expression))

    def replace_call(match):
        function_name = match.group(1)
        if function_name not in aliases:
            return match.group(0)
        wrapper, delta = aliases[function_name]
        try:
            index = evaluate(match.group(2)) - delta
            if wrapper == "Y":
                index += 0x2B4
            elif wrapper == "b":
                index -= 0x235
            index -= offset
            return json.dumps(rc4(strings[index], decode_key(match.group(3))))
        except (ArithmeticError, IndexError, UnicodeError, ValueError):
            return match.group(0)

    for alias in aliases:
        source = re.sub(rf"\b({alias})\(([^,]+),([^)]+)\)", replace_call, source)
    return source


def main():
    parser = argparse.ArgumentParser(description="Statically decode the ChainDrop npm loader")
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    raw = args.input.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != EXPECTED_SHA256:
        raise SystemExit(f"Refusing unexpected sample with SHA-256 {digest}")
    decoded = decode_sample(raw.decode("utf-8"))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(decoded, encoding="utf-8")
    print(f"Wrote statically decoded text to {args.output}")


if __name__ == "__main__":
    main()
