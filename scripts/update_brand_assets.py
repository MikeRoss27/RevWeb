#!/usr/bin/env python3
"""Regenerate brand SVGs with outlined text; fonts are needed only at generation."""
import argparse
import copy
from pathlib import Path
import xml.etree.ElementTree as ET
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / 'docs/assets'
NS = 'http://www.w3.org/2000/svg'
ET.register_namespace('', NS)
ORANGE, INK, CREAM, STONE = '#E5653F', '#211C1C', '#FAF4E8', '#A39A92'
TAGLINE = 'Inspect. Probe. Investigate.'
MODES = 'STATIC / DYNAMIC / ACTIVE / CLI / TUI'


def element(parent, tag, **attrs):
    return ET.SubElement(parent, f'{{{NS}}}{tag}', {k.replace('_', '-'): str(v) for k, v in attrs.items()})


def canvas(width, height, title, description, background):
    root = ET.Element(f'{{{NS}}}svg', {'viewBox': f'0 0 {width} {height}', 'width': str(width),
        'height': str(height), 'role': 'img', 'aria-label': description})
    element(root, 'title').text = title
    element(root, 'desc').text = description
    element(root, 'rect', width=width, height=height, fill=background)
    return root


class OutlineFont:
    def __init__(self, path, weight=None):
        self.font = TTFont(path)
        if 'fvar' in self.font:
            axes = {a.axisTag: a.defaultValue for a in self.font['fvar'].axes}
            if weight is not None: axes['wght'] = weight
            if 'opsz' in axes: axes['opsz'] = 32
            self.font = instantiateVariableFont(self.font, axes)
        self.glyphs = self.font.getGlyphSet()
        self.cmap = self.font.getBestCmap()
        self.units = self.font['head'].unitsPerEm

    def text(self, root, text, x, y, size, color=INK, tracking=0, align='left'):
        scale = size / self.units
        width = sum(self.glyphs[self.cmap[ord(c)]].width * scale + tracking for c in text) - tracking
        if align == 'right': x -= width
        elif align == 'center': x -= width / 2
        pen = SVGPathPen(self.glyphs, ntos=lambda n: f'{n:.2f}'.rstrip('0').rstrip('.'))
        offset = x
        for c in text:
            glyph = self.glyphs[self.cmap[ord(c)]]
            glyph.draw(TransformPen(pen, (scale, 0, 0, -scale, offset, y)))
            offset += glyph.width * scale + tracking
        path = element(root, 'path', d=pen.getCommands(), fill=color)
        element(path, 'title').text = text
        return width


def save(root, name):
    ET.indent(root, space='  ')
    (ASSETS / name).write_bytes(ET.tostring(root, encoding='utf-8') + b'\n')


def hero(body, mono):
    previous = ET.parse(ASSETS / 'hero.svg').getroot()
    lockup = next(c for c in previous if c.tag == f'{{{NS}}}g')
    root = canvas(1280, 400, 'webrev — web security toolkit',
        f'webrev: {TAGLINE} Static analysis, dynamic investigation and active security probes. CLI and TUI.', ORANGE)
    root.append(copy.deepcopy(lockup))
    mono.text(root, 'WEB SECURITY TOOLKIT', 1208, 100, 14, align='right')
    element(root, 'path', d='M72 228H1208', stroke='#A34028', stroke_width=1)
    body.text(root, TAGLINE, 72, 292, 56)
    badge = element(root, 'rect', x=72, y=318, width=0, height=39, fill=INK)
    width = mono.text(root, MODES, 92, 344, 14, CREAM, tracking=0.8)
    badge.set('width', str(round(width + 40, 2)))
    save(root, 'hero.svg')


def social(body, mono):
    root = canvas(1280, 640, 'webrev — web security toolkit',
        f'webrev: {TAGLINE} Static, dynamic and active web security analysis.', ORANGE)
    body.text(root, 'webrev', 72, 100, 36)
    mono.text(root, 'WEB SECURITY TOOLKIT', 1208, 94, 14, align='right')
    element(root, 'path', d='M72 128H1208', stroke='#A34028', stroke_width=1)
    for word, y in [('Inspect.', 248), ('Probe.', 330), ('Investigate.', 412)]:
        body.text(root, word, 72, y, 80)
    badge = element(root, 'rect', x=72, y=462, width=0, height=44, fill=INK)
    width = mono.text(root, MODES, 92, 491, 14, CREAM, tracking=1)
    badge.set('width', str(round(width + 40, 2)))
    element(root, 'rect', x=832, y=176, width=376, height=376, fill=INK)
    for x, y, w, h in [(918,274,204,45), (918,274,48,183), (1026,361,96,48), (1074,361,48,96)]:
        element(root, 'rect', x=x, y=y, width=w, height=h, fill=ORANGE)
    save(root, 'social-preview.svg')


def pipeline(body, mono):
    root = canvas(1188, 460, 'webrev analysis and testing workflow',
        'Seeds feed static analysis, dynamic browser investigation and active security probes. '
        'Findings stay in memory and feed reports and the live TUI.', '#1A1616')
    mono.text(root, 'WEB SECURITY / STATIC + DYNAMIC + ACTIVE', 30, 40, 13, STONE)

    def card(x, y, width, title, lines, primary=False):
        element(root, 'rect', x=x, y=y, width=width, height=84, fill=ORANGE if primary else INK,
            stroke='none' if primary else '#3A3333')
        color = INK if primary else CREAM
        body.text(root, title, x + width/2, y+32, 20, color, align='center')
        for i, line in enumerate(lines):
            mono.text(root, line, x+width/2, y+55+i*16, 11, color if primary else STONE, align='center')

    def arrow(path, point, direction, color=ORANGE):
        element(root, 'path', d=path, stroke=color, stroke_width=2, fill='none')
        x, y = point
        tip = {'right': f'M{x-7} {y-5}L{x} {y}L{x-7} {y+5}',
               'down': f'M{x-5} {y-7}L{x} {y}L{x+5} {y-7}',
               'up': f'M{x-5} {y+7}L{x} {y}L{x+5} {y+7}'}[direction]
        element(root, 'path', d=tip, stroke=color, stroke_width=2, fill='none')

    card(30,72,200,'Seeds',['URLs + scope'],True)
    card(262,72,200,'Fetch',['HTML / JS / source maps'])
    card(494,72,200,'Static analysis',['endpoints / secrets / tech'])
    card(726,72,200,'Memory session',['findings + evidence'])
    card(958,72,200,'Reports',['JSON / JSONL / CSV','URLs / text triage'])
    for x in [236,468,700,932]: arrow(f'M{x} 114H{x+18}', (x+18,114), 'right')
    card(262,272,432,'Dynamic investigation',['browser interaction / hooks / HAR','WebSocket traffic + click attribution'])
    card(726,272,200,'Active probes',['CORS / access / redirects','XSS + SQLi signals'])
    card(958,272,200,'Live TUI',['triage / secrets / stack'])
    arrow('M130 162V314H254', (254,314), 'right')
    arrow('M700 314H718V218H778V164', (778,164), 'up')
    arrow('M802 162V264', (802,264), 'down')
    arrow('M850 266V164', (850,164), 'up')
    mono.text(root,'URLs',810,208,10,STONE)
    mono.text(root,'findings',866,242,10,STONE)
    arrow('M900 162V208H1058V264', (1058,264), 'down', STONE)
    mono.text(root,'live results',965,194,10,STONE)
    arrow('M130 162V400H826V364', (826,364), 'up')
    mono.text(root,'seed URLs also feed active probes',262,424,11,STONE)
    save(root, 'pipeline.svg')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inter', type=Path, required=True)
    parser.add_argument('--mono', type=Path, required=True)
    args = parser.parse_args()
    body, mono = OutlineFont(args.inter, 800), OutlineFont(args.mono, 600)
    hero(body, mono)
    social(body, mono)
    pipeline(body, mono)


if __name__ == '__main__':
    main()
