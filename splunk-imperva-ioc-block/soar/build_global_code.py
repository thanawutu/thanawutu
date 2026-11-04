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
OUT_BLOCK = os.path.join(HERE, "imperva_ioc_block_code_block.py")


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


def build_code_block():
    """
    Same code, indented 4 spaces, for playbook editors without a Global Custom Code
    section (e.g. SOAR 8.x VPE): paste it between "## Custom Code Start" and
    "## Custom Code End" of the code block. It defines everything inside the block
    function and then calls the handler.
    """
    body = build().replace("# Paste ALL of this into the SOAR playbook > Global Custom Code.",
                           "# Paste ALL of this between '## Custom Code Start' and '## Custom Code End'\n"
                           "# of the playbook's code block (it is already indented 4 spaces).")
    lines = [("    " + ln) if ln.strip() else "" for ln in body.splitlines()]
    lines += ["", "    # ---- run ----", "    imperva_soar_handle(container, phantom)", ""]
    return "\n".join(lines)


if __name__ == "__main__":
    with open(OUT, "w") as f:
        f.write(build())
    with open(OUT_BLOCK, "w") as f:
        f.write(build_code_block())
    print("wrote", OUT)
    print("wrote", OUT_BLOCK)
