#!/usr/bin/env python3
"""Add two numbers from the command line or interactively."""

import sys


def add(a: float, b: float) -> float:
    return a + b


def main() -> None:
    if len(sys.argv) == 3:
        a = float(sys.argv[1])
        b = float(sys.argv[2])
    else:
        a = float(input("Enter first number: "))
        b = float(input("Enter second number: "))

    result = add(a, b)
    print(f"{a} + {b} = {result}")


if __name__ == "__main__":
    main()
