from pathlib import Path


def byte_counts(data: bytes) -> list[int]:
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    return counts


def compare_modes(plaintext: bytes, keys, selected_mode: str,
                  selected_ciphertext: bytes, iv: bytes | None) -> dict[str, bytes]:
    from venture128.block_modes import cbc, cfb, ctr, ecb, ofb
    from venture128.modules.iv import generate_iv

    comparison_iv = iv if iv is not None else generate_iv()
    encryptors = {
        "ecb": ecb.ecb_encrypt, "cbc": cbc.cbc_encrypt, "cfb": cfb.cfb_encrypt,
        "ofb": ofb.ofb_encrypt, "ctr": ctr.ctr_encrypt,
    }
    ciphertexts = {}
    for mode, encrypt in encryptors.items():
        if mode == selected_mode:
            ciphertexts[mode] = selected_ciphertext
        elif mode == "ecb":
            ciphertexts[mode] = encrypt(plaintext, keys)
        else:
            ciphertexts[mode] = encrypt(plaintext, keys, comparison_iv)[0]
    return ciphertexts


def write_histogram_png(path: Path, plaintext: bytes,
                        ciphertexts: dict[str, bytes], title: str) -> None:
    """Render plaintext + five modes without opening a GUI window."""
    from matplotlib.backends.backend_agg import FigureCanvasAgg
    from matplotlib.figure import Figure

    datasets = [("Plaintext", plaintext)] + [
        (mode.upper(), ciphertexts[mode]) for mode in ("ecb", "cbc", "cfb", "ofb", "ctr")
    ]
    frequencies = []
    for label, data in datasets:
        percentages = [100 * c / max(len(data), 1) for c in byte_counts(data)]
        frequencies.append((label, len(data), percentages))
    figure = Figure(figsize=(10, 8), layout="constrained")
    FigureCanvasAgg(figure)
    axes = figure.subplots(3, 2, sharex=True, sharey=True)
    for ax, (label, total, values) in zip(axes.flat, frequencies):
        ax.bar(range(256), values)
        ax.axhline(100 / 256, linestyle="--")
        ax.set(title=f"{label} ({total} bytes)",
               xlabel="Byte value", ylabel="Frequency (%)")
        if not total:
            ax.text(0.5, 0.5, "Empty data", transform=ax.transAxes, ha="center")
    axes.flat[0].set_ylim(bottom=0)
    figure.suptitle(title)
    path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(path)
