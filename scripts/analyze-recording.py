#!/usr/bin/env python3
"""
Покадровий розбір запису екрана — єдиний спосіб перевірити плавність на iOS.

ЧОМУ ЦЕ ПОТРІБНО. Пісочниця й CI дають Chromium, а прод — WebKit у webview
Telegram. Різниця не косметична: `_blur-cost.spec.ts` заміряв, що в Chromium
`backdrop-filter` під анімацією коштує РІВНО СТІЛЬКИ Ж, скільки без нього
(p50 16.7мс в обох випадках), тож локальний прогін не побачить ані ривка, ані
його полагодження. CLAUDE.md фіксує це прямо: поведінка блюру на iOS — «єдине
про плавність, що вимагає живого пристрою».

ЩО ВІН МІРЯЄ. Для кожного кадру — скільки пікселів змінилось проти попереднього.
Рівна анімація дає плавний профіль; втрачені кадри видно як два сусідні
екстремуми: величезний стрибок (за один кадр пройдено пів шляху) і майже
нульовий кадр одразу за ним.

ЖИВИЙ ПРИКЛАД (запис відкриття меню бази, 43.6 к/с, ДО фікса):

    f078  1 994 102   ← 67% екрана за ОДИН кадр
    f079    963 593
    f080    409 594
    f081     61 594   ← провал: кадр майже без руху
    f082    191 857   ← рух відновився

Саме цей профіль і був діагнозом: кадри на старті губились, бо відкриття шита
створює два нові backdrop-шари поверх екрана, повного скляних карток.

ВЖИВАННЯ:
    python3 scripts/analyze-recording.py запис.mp4
    python3 scripts/analyze-recording.py запис.mp4 --threshold 3000

Потрібен `opencv-python` (у пісочниці вже є). ffmpeg НЕ потрібен.
"""
import sys
import argparse


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('video', help='файл запису екрана (.mp4/.mov)')
    ap.add_argument('--threshold', type=int, default=3000,
                    help='скільки змінених пікселів вважати рухом (типово 3000)')
    ap.add_argument('--pixel-delta', type=int, default=12,
                    help='наскільки має змінитись піксель, щоб рахуватись (типово 12)')
    args = ap.parse_args()

    try:
        import cv2
    except ImportError:
        print('Потрібен opencv-python:  pip install opencv-python-headless', file=sys.stderr)
        return 2

    cap = cv2.VideoCapture(args.video)
    if not cap.isOpened():
        print(f'Не вдалося відкрити {args.video}', file=sys.stderr)
        return 2

    fps = cap.get(cv2.CAP_PROP_FPS) or 60.0
    w = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    h = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    total_px = w * h
    print(f'{args.video}: {w}x{h}, {fps:.1f} к/с')

    prev = None
    rows = []
    i = 0
    while True:
        ok, frame = cap.read()
        if not ok:
            break
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        changed = 0 if prev is None else int((cv2.absdiff(gray, prev) > args.pixel_delta).sum())
        prev = gray
        rows.append((i, i / fps, changed))
        i += 1

    moving = [r for r in rows if r[2] > args.threshold]
    print(f'кадрів {len(rows)}, з рухом {len(moving)}\n')
    if not moving:
        print('Руху не знайдено — знизь --threshold.')
        return 0

    for idx, t, changed in moving:
        share = changed / total_px * 100
        print(f'f{idx:04d}  t={t * 1000:7.0f}мс  змінено={changed:9d}  ({share:5.1f}% екрана)')

    # Втрачений кадр: різкий провал між двома кадрами з рухом. Саме ця пара —
    # «величезний стрибок, потім майже нічого» — і є ривком, який видно оком.
    print()
    stalls = []
    for k in range(1, len(moving) - 1):
        prev_c, cur_c, next_c = moving[k - 1][2], moving[k][2], moving[k + 1][2]
        neighbours = (prev_c + next_c) / 2
        if neighbours > 0 and cur_c < neighbours * 0.35:
            stalls.append((moving[k][0], cur_c, int(neighbours)))
    if stalls:
        print('ПРОВАЛИ (кадр рухався втричі менше за сусідів — ознака втраченого кадру):')
        for idx, cur_c, neigh in stalls:
            print(f'  f{idx:04d}: {cur_c} проти ~{neigh} у сусідів')
    else:
        print('Провалів не знайдено — профіль рівний.')

    peak = max(moving, key=lambda r: r[2])
    print(f'\nНайбільший стрибок: f{peak[0]:04d} — {peak[2]} px '
          f'({peak[2] / total_px * 100:.1f}% екрана за один кадр)')
    print('Орієнтир: якщо один кадр забирає понад ~40% екрана, анімація '
          'стартувала стрибком, а не виїздом.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
