import os
import csv
import numpy as np
from PIL import Image
import matplotlib.pyplot as plt
from skimage.metrics import peak_signal_noise_ratio as compute_psnr
from skimage.metrics import structural_similarity as compute_ssim
from scipy.stats import chi2


def generate_visualizations_and_metrics(cover_path, stego_dict):
    cover_img = Image.open(cover_path).convert('RGB')
    cover_arr = np.array(cover_img, dtype=np.int16)
    max_cap = cover_arr.size

    # Создаем папку results в корне проекта
    os.makedirs("../results", exist_ok=True)

    # 1. Генерация карты разности (на примере Encrypted Random LSB)
    stego_target_path = stego_dict.get("Encrypted Random LSB", list(stego_dict.values())[0])
    stego_target_img = Image.open(stego_target_path).convert('RGB')
    stego_target_arr = np.array(stego_target_img, dtype=np.int16)

    diff = np.abs(cover_arr - stego_target_arr)
    diff_amplified = np.clip(diff * 50, 0, 255).astype(np.uint8)
    Image.fromarray(diff_amplified).save("../results/difference.png")
    print("Карта разности сохранена в results/difference.png")

    # 2. Сравнительная гистограмма
    plt.figure(figsize=(10, 5))
    plt.hist(cover_arr.flatten(), bins=256, range=(0, 256), alpha=0.5, color='blue', label='Cover')
    plt.hist(stego_target_arr.flatten(), bins=256, range=(0, 256), alpha=0.5, color='orange', label='Stego (Random)')
    plt.title('Сравнение гистограмм исходного и стего-изображения')
    plt.xlabel('Яркость (0-255)')
    plt.ylabel('Частота')
    plt.legend()
    plt.grid(True, alpha=0.5)
    plt.savefig("../results/histogram.png", dpi=300)
    plt.close()
    print("Гистограмма сохранена в results/histogram.png")

    #  Сбор и расчет метрик для всех вариантов
    variants = {"Cover": cover_arr}
    for name, path in stego_dict.items():
        variants[name] = np.array(Image.open(path).convert('RGB'), dtype=np.int16)

    csv_rows = []
    print(
        f"\n{'Вариант':<25} | {'PSNR':<8} | {'SSIM':<8} | {'Changed(%)':<10} | {'P(LSB=1)':<10} | {'chi2':<10} | {'p-value':<10}")
    print("-" * 95)

    for name, arr in variants.items():
        lsbs = arr & 1
        p1 = np.sum(lsbs == 1) / lsbs.size
        flat = arr.flatten()

        # Хи-квадрат анализ по парам (2k, 2k+1)
        chi2_vals = [
            ((np.sum(flat == k) - (np.sum(flat == k) + np.sum(flat == k + 1)) / 2) ** 2) /
            ((np.sum(flat == k) + np.sum(flat == k + 1)) / 2 + 1e-9)
            for k in range(0, 256, 2)
        ]
        c_stat = sum(chi2_vals)
        p_val = 1 - chi2.cdf(c_stat, df=127)

        if name == "Cover":
            csv_rows.append([name, "-", "-", "-", f"{p1:.4f}", f"{c_stat:.2f}", f"{p_val:.4f}"])
            print(f"{name:<25} | {'-':<8} | {'-':<8} | {'-':<10} | {p1:<10.4f} | {c_stat:<10.2f} | {p_val:<10.4f}")
            continue

        psnr = compute_psnr(cover_arr, arr, data_range=255)
        ssim = compute_ssim(cover_arr, arr, channel_axis=2, data_range=255)
        diff_count = np.sum(cover_arr != arr)
        changed_ratio = (diff_count / max_cap) * 100

        csv_rows.append(
            [name, f"{psnr:.2f}", f"{ssim:.4f}", f"{changed_ratio:.2f}%", f"{p1:.4f}", f"{c_stat:.2f}", f"{p_val:.4f}"])
        print(
            f"{name:<25} | {psnr:<8.2f} | {ssim:<8.4f} | {changed_ratio:<10.2f} | {p1:<10.4f} | {c_stat:<10.2f} | {p_val:<10.4f}")

    csv_path = "../results/metrics.csv"
    with open(csv_path, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Variant", "PSNR", "SSIM", "Changed Ratio", "P(LSB=1)", "Chi2", "p-value"])
        writer.writerows(csv_rows)
    print(f"\nТаблица метрик сохранена в '{csv_path}'")


if __name__ == "__main__":
    cover_image = "../imgs/akashi.png"
    stego_paths = {
        "Plain LSB": "../imgs/stego_plain.png",
        "Encrypted LSB": "../imgs/stego_encrypted.png",
        "Encrypted Random LSB": "../imgs/stego_random.png"
    }

    generate_visualizations_and_metrics(cover_image, stego_paths)