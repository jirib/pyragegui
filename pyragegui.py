#!/usr/bin/env python3

import importlib.util
import os

gui = "pysimplegui"

if __name__ == "__main__":
    cwd = os.path.dirname(os.path.realpath(__file__))
    if gui == "pysimplegui":
        spec = importlib.util.spec_from_file_location("pysimplegui", f"{cwd}/pysimplegui.py")
        pysimplegui = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pysimplegui)
        pysimplegui.main()
