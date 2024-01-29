#!/usr/bin/env python3

import importlib.util

gui = "pysimplegui"

if __name__ == "__main__":
    if gui == "pysimplegui":
        spec = importlib.util.spec_from_file_location("pysimplegui", "pysimplegui.py")
        pysimplegui = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pysimplegui)
        pysimplegui.main()
