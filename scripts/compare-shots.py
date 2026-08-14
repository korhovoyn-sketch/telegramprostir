#!/usr/bin/env python3
"""
Порівняння двох тек із кадрами, знятими ОДНИМ браузером на двох версіях коду.

ЧОМУ ЦЕ ПОТРІБНО. Візуальні бейслайни належать раннеру (Chromium 148), а
пісочниця має заморожений 141 — тобто кадр, знятий тут, проти бейслайна завжди
дає шум. Але якщо зняти ДВІ версії коду тут же, різниця збірок входить в обидва
знімки однаково і в різниці зникає: лишається рівно те, що зробила зміна.

Друкує для кожного кадру частку змінених пікселів і, головне, МЕЖІ області
зміни — щоб було видно, чи вона там, де ти правив, чи поїхала верстка.

Вживання:
    python3 scripts/compare-shots.py /tmp/before /tmp/after
"""
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    before, after = Path(sys.argv[1]), Path(sys.argv[2])

    try:
        import cv2
        import numpy as np
    except ImportError:
        print('Потрібен opencv-python', file=sys.stderr)
        return 2

    names = sorted({p.name for p in before.glob('*.png')} & {p.name for p in after.glob('*.png')})
    if not names:
        print('Спільних кадрів не знайдено')
        return 1

    print(f'{len(names)} спільних кадрів\n')
    print(f'{"кадр":28s} {"змінено":>9s}  область зміни (x0,y0)-(x1,y1)')
    for n in names:
        a = cv2.imread(str(before / n))
        b = cv2.imread(str(after / n))
        if a is None or b is None or a.shape != b.shape:
            print(f'{n[:28]:28s} {"РОЗМІР":>9s}  {a.shape if a is not None else "?"} → '
                  f'{b.shape if b is not None else "?"}')
            continue
        diff = cv2.absdiff(cv2.cvtColor(a, cv2.COLOR_BGR2GRAY), cv2.cvtColor(b, cv2.COLOR_BGR2GRAY))
        mask = diff > 12
        changed = int(mask.sum())
        share = changed / mask.size * 100
        if changed == 0:
            print(f'{n[:28]:28s} {"—":>9s}')
            continue
        ys, xs = np.where(mask)
        print(f'{n[:28]:28s} {share:8.2f}%  ({xs.min():3d},{ys.min():4d})-({xs.max():3d},{ys.max():4d})')
    return 0


if __name__ == '__main__':
    sys.exit(main())
