"""Generate soar/imperva_ioc_block_global_code.py = imperva_lib.py + vt_lib.py + imperva_soar_handler.py

Paste the generated file into the SOAR playbook's *Global Custom Code*.
Run:  python3 soar/build_global_code.py
"""
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "..", "TA-imperva-ioc-block", "bin", "imperva_lib.py")
VTLIB = os.path.join(HERE, "..", "TA-imperva-ioc-block", "bin", "vt_lib.py")
HANDLER = os.path.join(HERE, "imperva_soar_handler.py")
OUT = os.path.join(HERE, "imperva_ioc_block_global_code.py")


def build():
    lib = open(LIB).read()
    vtlib = open(VTLIB).read()
    handler = open(HANDLER).read()
    handler = re.sub(r"# --- BEGIN LIB IMPORT.*?# --- END LIB IMPORT ---\n",
                     "import json\nimport os\n", handler, flags=re.S)
    head = ("# GENERATED FILE - do not edit. Source: imperva_lib.py + vt_lib.py + imperva_soar_handler.py\n"
            "# Rebuild with: python3 soar/build_global_code.py\n"
            "# Paste ALL of this into the SOAR playbook > Global Custom Code.\n\n")
    return head + "# " + "=" * 74 + "\n# imperva_lib\n# " + "=" * 74 + "\n" + lib + \
        "\n\n# " + "=" * 74 + "\n# vt_lib\n# " + "=" * 74 + "\n" + vtlib + \
        "\n\n# " + "=" * 74 + "\n# SOAR handler\n# " + "=" * 74 + "\n" + handler


if __name__ == "__main__":
    with open(OUT, "w") as f:
        f.write(build())
    print("wrote", OUT)
