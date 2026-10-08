"""Dependency-free angular pixel wordmark inspired by the approved reference image.

This draws vector rectangles on Tk Canvas, not an embedded or redistributed font.
"""
import tkinter as tk

GLYPHS = {
    "P": ("11110","10001","10001","11110","10000","10000","10000"),
    "i": ("00100","00000","01100","00100","00100","00100","01110"),
    "p": ("00000","11110","10001","11110","10000","10000","10000"),
    "e": ("00000","01110","10001","11111","10000","01110","00000"),
    "l": ("11000","01000","01000","01000","01000","00110","00000"),
    "n": ("00000","11110","10001","10001","10001","10001","00000"),
    "G": ("01111","10000","10000","10111","10001","10001","01111"),
    "u": ("00000","10001","10001","10001","10001","01111","00000"),
    "a": ("00000","01110","00001","01111","10001","01111","00000"),
    "r": ("00000","10110","11001","10000","10000","10000","00000"),
    "d": ("00001","00001","01111","10001","10001","01111","00000"),
}

def draw_wordmark(canvas, x, y, scale=3, color="#B8DA79"):
    """Draw PipelineGuard; return rendered width for positioning."""
    start = x
    for letter in "PipelineGuard":
        glyph = GLYPHS[letter]
        for row, bits in enumerate(glyph):
            for col, bit in enumerate(bits):
                if bit == "1":
                    canvas.create_rectangle(
                        x + col * scale, y + row * scale,
                        x + (col + 1) * scale, y + (row + 1) * scale,
                        fill=color, outline="", tags="wordmark",
                    )
        x += 6 * scale
    return x - start

def draw_cat_shield(canvas, x, y, scale=1, color="#B8DA79"):
    """Draw a restrained geometric cyber-cat shield mark."""
    pts = [(2,0),(20,0),(24,4),(24,22),(13,32),(2,22),(2,4)]
    canvas.create_polygon(*[v * scale + (x if i % 2 == 0 else y)
                            for i, v in enumerate(sum(([a,b] for a,b in pts), []))],
                          outline=color, fill="", width=max(1,scale), tags="cat-logo")
    # Ears and angular face stay inside the shield.
    for coords in (((6,10),(6,18),(12,22),(12,14)),
                   ((20,10),(20,18),(14,22),(14,14))):
        canvas.create_polygon(*[v * scale + (x if i % 2 == 0 else y)
                                for i,v in enumerate(sum(([a,b] for a,b in coords), []))],
                              fill=color, outline="", tags="cat-logo")
    canvas.create_line(x+10*scale,y+24*scale,x+13*scale,y+26*scale,
                       x+16*scale,y+24*scale,fill=color,width=max(1,scale),
                       tags="cat-logo")
