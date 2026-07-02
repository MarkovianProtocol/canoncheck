"""Interactive canoncheck demo (Gradio / Hugging Face Space).

Paste a JSON record, see its RFC 8785 canonical form and both digests. Duplicate keys and
non-finite numbers are rejected the same way the library rejects them.
"""
import os
import sys

import gradio as gr

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import canoncheck as cc

EXAMPLES = [
    '{"agent":"resolver-01","block_height":800000,"result":"MATCH"}',
    '{"b":1,"a":2,"z":[3,true,null,"x"]}',
    '{"a":1.0,"b":1e2,"c":100}',
    '{"é":"café","a":"plain","emoji":"😀"}',
    '{"a":1,"a":2}',
]


def run(raw):
    try:
        value = cc.parse_strict(raw)
        data = cc.canonicalize(value)
        return (
            data.decode("utf-8"),
            cc.digest_bytes(data, "sha256"),
            cc.digest_bytes(data, "keccak256"),
        )
    except Exception as e:  # noqa: BLE001
        return ("rejected: " + str(e), "", "")


with gr.Blocks(title="canoncheck") as demo:
    gr.Markdown(
        "# canoncheck\n"
        "RFC 8785 canonical JSON with matching Python and JS implementations. "
        "Paste a record, get the canonical form and its sha256 / keccak256. "
        "Duplicate keys and NaN/Infinity are rejected."
    )
    inp = gr.Textbox(label="JSON record", lines=4, value=EXAMPLES[0])
    btn = gr.Button("Canonicalize")
    canon = gr.Textbox(label="canonical form (RFC 8785)")
    sha = gr.Textbox(label="sha256")
    kec = gr.Textbox(label="keccak256")
    btn.click(run, inputs=inp, outputs=[canon, sha, kec])
    gr.Examples(EXAMPLES, inputs=inp)

if __name__ == "__main__":
    demo.launch()
