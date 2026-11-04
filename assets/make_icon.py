# Draws app.ico: the clock face from theme::window_icon(), at the sizes Windows
# asks for. Needs Pillow. Run it from the repository root.
import math
from PIL import Image

ACCENT = (0x2F, 0x7D, 0xF6)
SIZES = [256, 64, 48, 40, 32, 24, 20, 16]


def draw(n):
    s = n / 64  # the shape is defined on a 64-pixel grid
    c = (n - 1) / 2
    img = Image.new("RGBA", (n, n))
    px = img.load()
    hands = [(300.0, 17.0 * s, 2.6 * s), (60.0, 23.0 * s, 2.0 * s)]
    for y in range(n):
        for x in range(n):
            dx, dy = x - c, y - c
            d = math.hypot(dx, dy)
            disc = min(max(30.5 * s - d, 0.0), 1.0)
            if disc <= 0:
                continue
            white = 0.0
            for deg, length, hw in hands:
                a = math.radians(deg)
                ux, uy = math.sin(a), -math.cos(a)
                t = min(max(dx * ux + dy * uy, 0.0), length)
                dist = math.hypot(dx - ux * t, dy - uy * t)
                white = max(white, min(max(hw + 0.5 - dist, 0.0), 1.0))
            white = max(white, min(max(4.0 * s - d, 0.0), 1.0))
            for tx, ty in [(0, -1), (1, 0), (0, 1), (-1, 0)]:
                along = dx * tx + dy * ty
                across = abs(dx * ty - dy * tx)
                if 21 * s <= along < 27 * s:
                    white = max(white, min(max(2.0 * s - across, 0.0), 1.0))
            mix = lambda a: round(a + (255 - a) * white)
            px[x, y] = (mix(ACCENT[0]), mix(ACCENT[1]), mix(ACCENT[2]), int(disc * 255))
    return img


images = [draw(n) for n in SIZES]
images[0].save("assets/app.ico", sizes=[(n, n) for n in SIZES], append_images=images[1:])
print("wrote assets/app.ico")
