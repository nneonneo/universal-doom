#!/usr/bin/env python3
''' Pack a DOS binary and a Windows binary into a single "universal" .exe file.

The DOS binary should be using the DOS/4GW extender. '''

from struct import pack_into, unpack_from

# Previous attempt: place the Windows EXE (plus all headers) after the entire DOS executable.
# Windows hates this because it doesn't like it if next_offset is too large.
# Workaround: patch the DOS binary header to include enough space for the PE header.

dos = bytearray(open('DOOMD.EXE', 'rb').read())
win = bytearray(open('DOOMW.EXE', 'rb').read())

msg = b'Universal DOOM (DOS/WIN) by @nneonneo, 2020-11-29\0'
msg = msg.ljust(len(msg) + (-len(msg)) % 4, b'\0')

next_offset, = unpack_from('<I', win, 0x3c)
num_sect, = unpack_from('<H', win, next_offset + 6)
opt_header_size, = unpack_from('<H', win, next_offset + 20)
win_header_size = 24 + opt_header_size + num_sect * 40

num_relocs, header_paragraphs = unpack_from('<HH', dos, 0x6)
min_dos_header_size = 0x40 + 4 * num_relocs + len(msg) + win_header_size
if header_paragraphs * 16 < min_dos_header_size:
    # Expand the DOS header to make room for the PE header
    new_header_paragraphs = (min_dos_header_size + 15) // 16
    padlen = (new_header_paragraphs - header_paragraphs) * 16
    dos = dos[:header_paragraphs * 16] + b'\0' * padlen + dos[header_paragraphs * 16:]
    header_paragraphs = new_header_paragraphs
    pack_into('<H', dos, 0x8, header_paragraphs)

    # Correct DOS file size
    sz_lo, sz_hi = unpack_from('<HH', dos, 2)
    sz_hi, sz_lo = divmod(sz_hi * 512 + sz_lo + padlen, 512)
    pack_into('<HH', dos, 2, sz_lo, sz_hi)

    # Correct EXP file header if present
    bw_off = sz_hi * 512 + sz_lo
    if sz_lo:
        bw_off -= 512
    if unpack_from('<2s', dos, bw_off)[0] == b'BW':
        le_off, = unpack_from('<I', dos, bw_off + 0x1c)
        pack_into('<I', dos, bw_off + 0x1c, le_off + padlen)

reloc_table_offset, = unpack_from('<H', dos, 0x18)
if reloc_table_offset < 0x40:
    # Need to shift the relocation table past next_offset at 0x3c:0x40
    reloc_table_size = num_relocs * 4
    dos[0x40:0x40 + reloc_table_size] = dos[reloc_table_offset:reloc_table_offset + reloc_table_size]
    pack_into('<H', dos, 0x18, 0x40)
    reloc_table_offset = 0x40

padlen = (-len(dos)) % 512
dos += b'\0' * padlen

# For simplicity, we just include the entire Windows binary after the DOS binary 
win_off = len(dos)
msg_off = 0x40 + 4 * num_relocs
win_header_off = msg_off + len(msg)
dos[win_header_off:win_header_off + win_header_size] = win[next_offset:next_offset + win_header_size]
dos[msg_off:msg_off + len(msg)] = msg
pack_into('<I', dos, 0x3c, win_header_off)

# relocate sections
if opt_header_size > 64:
    total_header_size, = unpack_from('<I', dos, win_header_off + 24 + 60)
    pack_into('<I', dos, win_header_off + 24 + 60, min_dos_header_size)
for i in range(num_sect):
    sect_offset = win_header_off + 24 + opt_header_size + 40 * i
    for off in (20, 24, 28):
        fptr, = unpack_from('<I', dos, sect_offset + off)
        if fptr != 0:
            pack_into('<I', dos, sect_offset + off, fptr + win_off)

with open('DOOM.EXE', 'wb') as outf:
    outf.write(dos)
    outf.write(win)
