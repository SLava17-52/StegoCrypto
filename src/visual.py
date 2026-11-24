import os
import numpy as np
from PIL import Image
import matplotlib.pyplot as plt


def make_diff_and_hist(
    cover_path: str,
    stego_path: str,
    diff_out: str,
    hist_out: str,
    title_suffix: str,
    gain: int = 64,
) -> None:
    cover_arr = np.array(Image.open(cover_path).convert("RGB"), dtype=np.int16)
    stego_arr = np.array(Image.open(stego_path).convert("RGB"), dtype=np.int16)

    diff = np.abs(cover_arr - stego_arr)
    diff_vis = np.clip(diff * gain, 0, 255).astype(np.uint8)
    Image.fromarray(diff_vis).save(diff_out)

    plt.figure(figsize=(10, 5))
    plt.hist(cover_arr.flatten(), bins=256, range=(0, 256), alpha=0.55, label="Cover")
    plt.hist(stego_arr.flatten(), bins=256, range=(0, 256), alpha=0.55, label="Encrypted Random LSB")
    plt.title(f"Гистограмма значений компонент ({title_suffix})")
    plt.xlabel("Значение компоненты (0–255)")
    plt.ylabel("Частота")
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(hist_out, dpi=200)
    plt.close()


def main() -> None:
    os.makedirs("../results", exist_ok=True)

    pairs = [
        (
            "../imgs/akashi.png",
            "../imgs/stego_akashi_random.png",
            "../results/difference.png",
            "../results/histogram.png",
            "akashi.png",
        ),
        (
            "../imgs/gradient.png",
            "../imgs/stego_gradient_random.png",
            "../results/difference_gradient.png",
            "../results/histogram_gradient.png",
            "gradient.png",
        ),
    ]

    for cover_p, stego_p, d_out, h_out, label in pairs:
        if os.path.exists(cover_p) and os.path.exists(stego_p):
            make_diff_and_hist(cover_p, stego_p, d_out, h_out, label)
            print(f"[OK] Построены графики для {label}: {d_out}, {h_out}")
        else:
            print(f"[WARN] Пропущено (нет файлов): {cover_p} или {stego_p}")


if __name__ == "__main__":
    main()