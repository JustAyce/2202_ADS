import struct
import collections
import glob
import fnmatch
import os
import sys


def doseek(f, n):
    try:
        f.seek(n)
    except:
        print("[!] unable to seek properly")


def readat(f, s, n):
    """
    Getter method to return packed data
    :param f: Input disk file
    :param s: Starting offset byte
    :param n: Number of bytes to look at
    :return: Returns n number of bytes starting from s
    """
    pos = f.tell()
    doseek(f, s)
    res = f.read(n)
    doseek(f, pos)
    return res


def retFilename(s):
    ref, = struct.unpack('<Q', s[:8])
    flen = ord(s[64:65])
    fname = s[66:66 + flen * 2].decode('UTF-16-LE')
    return ref, fname


def retRaw(s):
    return s


FILE_SIGNATURES = {
    0x10: ('standard_info', 'STANDARD_INFORMATION ', None),
    0x20: ('attr_list', 'ATTRIBUTE_LIST ', None),
    0x30: ('filename', 'FILE_NAME ', retFilename),
    0x40: ('obj_id', 'OBJECT_ID ', None),
    0x50: ('security', 'SECURITY_DESCRIPTOR ', None),
    0x60: ('vol_name', 'VOLUME_NAME ', None),
    0x70: ('vol_info', 'VOLUME_INFORMATION ', None),
    0x80: ('data', 'DATA ', None),
    0x90: ('index_root', 'INDEX_ROOT ', None),
    0xA0: ('index_alloc', 'INDEX_ALLOCATION ', None),
    0xB0: ('bitmap', 'BITMAP ', None),
    0xC0: ('sym_link', 'SYMBOLIC_LINK', None),
}


def get_value(v):
    if not v:
        return 0
    return int(v[::-1].hex(), 16)


def get_non_res(f, bpc, entry):
    """
        Non resident is when data is too big to fit the 1024 MFT entry, as such, they will be place else where and found
        using the run list
        :param f:
        :param bpc:
        :param entry:
        :return:
        """
    run_list_off = struct.unpack('<H', entry[32:34])[0]
    # print(f"run_list_off: {run_list_off}, attrb_entry:{entry}\n,mfte:{mfte}\n\n")
    size_actual = struct.unpack('<Q', entry[48:56])[0]
    run_list_pos = run_list_off
    runlist = []
    helper = 0

    # reading data run, Header = 0x21 - 1 byte length, 2 byte offset, len 1 byte, 2 byte offset
    while run_list_pos < len(entry):
        header = ord(entry[run_list_pos:run_list_pos + 1])
        if not header:
            break
        run_list_pos += 1
        length = header & 0xf
        offlen = header >> 4

        if run_list_pos + length + offlen > len(entry):
            print("[!] Invalid runlist header")
            break
        thislen = get_value(entry[run_list_pos:run_list_pos + length])
        run_list_pos += length
        thisoff = get_value(entry[run_list_pos:run_list_pos + offlen])

        # print(f"header{header}, This len{thislen} and this off{thisoff}")
        run_list_pos += offlen
        helper += thisoff
        runlist.append((thislen, helper))

    out = bytearray()
    for rlen, roff in runlist:
        out += readat(f, roff * bpc, rlen * bpc)
    data = bytes(out)[:size_actual]

    return data


def parse_attrb(f, bpc, attrb_entry):
    """
    First 42 bytes are fixed, following bytes are data, with 00 00 00 00 as end
    :param f: Input bytes
    :param bpc: bytes per cluster (bps*spc)
    :param attrb_entry:
    :return:
    """

    # Get signatures/information needed to find file data and other information
    file_entry_type, size, nonres, namelen, nameoff = struct.unpack('<iiBBH', attrb_entry[:12])

    if namelen:
        fname = attrb_entry[nameoff:nameoff + namelen * 2].decode('UTF-16-LE')
    else:
        fname = None

    # tries to get known information based on file type, if not, return as type as unknown and raw data
    data_type, data_name, data_parser = FILE_SIGNATURES.get(file_entry_type, (f'unk_{file_entry_type}', str(file_entry_type), retRaw))

    if data_parser is None:
        data_parser = retRaw
    data_name = data_name.strip()

    # if non resident file, get runlist offset, len etc
    if nonres:
        non_res_data=get_non_res(f, bpc, attrb_entry)
        attrdata = lambda: data_parser(non_res_data)

    else:

        attrlen, attroff = struct.unpack('<IH', attrb_entry[16:22])
        data = attrb_entry[attroff:attroff + attrlen]
        # Attr data = function of the parser
        attrdata = lambda: data_parser(data)

    return data_name, fname, attrdata


def parse_file(f, entryoff, bpc, entry):
    """
    Take in MFT entry of 1024 bytes, and returns dictionary of tuples
    :param f: Original input file
    :param entryoff:
    :param bpc: bytes per cluster (bps * spc)
    :param entry:
    :return: dictionary of tuples, {STD_INFO:info, FILE_NAME:info, DATA:info, BITMAP:info}
    """
    magic, usa_ofs, usa_count, lsn, seq, link, attr_offset, flags, used_size, allocated_size = struct.unpack('<IHHQHHHHHI', entry[:30])
    attrs = collections.defaultdict(dict)
    try:
        entry = bytearray(entry)
        if usa_ofs == 0 or usa_count == 0:
            pass

        usa_pos = usa_ofs
        usa_num = entry[usa_pos:usa_pos + 2]
        usa_pos += 2
        for i in range(len(entry) // 512):
            curr_pos = i * 512 + 510
            if entry[curr_pos:curr_pos + 2] != usa_num:
                print(f"[-] Warning: bad USA data at MBR offset {entryoff + curr_pos} - disk corrupt?")
            else:
                entry[curr_pos:curr_pos + 2] = entry[usa_pos:usa_pos + 2]
            usa_pos += 2

    except Exception as e:
        print(f"[-] Entry at offset: {entryoff}: failed to perform USA fixup: {e}")

    # creates a "pointer" to file offset
    pos = attr_offset
    while 1:
        if pos > len(entry) - 12:
            break
        type, size, nonres, namelen, nameoff = struct.unpack('<iIBBH', entry[pos:pos + 12])
        if type == -1:
            break

        try:
            data_name, name, data = parse_attrb(f, bpc, entry[pos:pos + size])
            attrs[data_name][name] = data
        except Exception as e:
            print(f"[-] File at offset {entryoff}: failed to parse attr type={type} pos={pos}: {e}")
            sys.exit()

        pos += size
    return attrs


def parse_mft(inFile, bytes_per_cluster, mft):
    """
    Gets all entries from MFT and returns a list of ALL entries\n
    Each MFT entry is 1024 bytes, with a file signature of 46 49 4C 45 (FILE)
    :param inFile: Input Disk
    :param bytes_per_cluster: Bytes per cluster in decimal
    :param mft: Master File table, if given
    :return: List of ALL MFT entries
    """
    mft_out = []
    file_sign = b'FILE'
    print("[*] Attempting to iterate through MFT entries")
    # Iterate every 1024 bytes(MFT Entry) and check for FILE signature
    # Range is found by modding the length of MFT by 1024. This is always possible because every MFT entry is 1024 bytes
    mft_length = len(mft)
    entry_size = 1024

    for entrys in range(mft_length // entry_size):
        # Assign each iteration into a temp value "entry", every 1024 bytes
        mft_entry = mft[entrys * entry_size:(entrys + 1) * entry_size]

        # Checks entry to see if signiture is a FILE.
        "Search for FILE signature(46 49 4C 45) in mft_entry"
        if mft_entry[:4] == file_sign:

            # If entry is a file, append to out variable.
            mft_out.append(parse_file(inFile, entrys * entry_size, bytes_per_cluster, mft_entry))
        else:
            mft_out.append(None)

    print("[+] Completed scan!")
    return mft_out


def read_mft(f, bpc, mft_cluster, clusters_per_mft):
    """
    Determines offset of MFT from MBR then returns whole MFT
    :param f: Input Disk
    :param bpc: Bytes per cluster in decimal
    :param mft_cluster:
    :param clusters_per_mft:
    :return: Full MFT file
    """
    print(f"[*] Loading MFT from cluster {mft_cluster}")
    mft = readat(f, mft_cluster * bpc, clusters_per_mft * bpc)
    print(f"[*] Reading MFT at offset {mft_cluster * bpc}")
    try:
        mftattr = parse_file(f, 0, bpc, mft[:1024])
        newmft = mftattr['DATA'][None]()
        if len(newmft) < len(mft):
            raise Exception("$MFT truncated")
        mft = newmft
    except Exception as e:
        print(f"[!] WARNING: Failed to load $MFT ({e}), proceeding with partial MFT.")
    print("[+] Done reading MFT!")
    return mft


def get_filepath(mft, i):
    bits = []
    next_offset = 0xffffffffffff
    # MFT[i] is a collection class
    # collection class is used to store multiple types like list, dict, set tuple.
    # in this case, they are all collections.defaultdict.
    # mft[i]['FILE_NAME'][None]() this gives the file name and parent file
    # mft[i]['File_NAME'][NONE] is a type function, still  unknown for now

    "print(type(mft[i]['FILE_NAME'][None]))"

    while 1:
        parent, name = mft[i]['FILE_NAME'][None]()
        if name == '.':
            break
        bits.append(name)
        i = parent & next_offset
    return bits[::-1]


def open_output_file(destfname):
    if not os.path.isfile(destfname):
        return open(destfname, 'wb')

    t = 0
    while True:
        fname = destfname + '_%04d' % t
        if not os.path.isfile(fname):
            return open(fname, 'wb')
        t += 1
    raise OSError("File exists.")


def save_file(mfti, destfname):
    """

    :param mfti: FILE entry from parse_mft()
    :param destfname: output file dir
    :return:
    """
    if '/' in destfname:
        try:
            os.makedirs(destfname.rsplit('/', 1)[0])
        except OSError:
            pass

    with open_output_file(destfname) as outf:
        outf.write(mfti['DATA'][None]())

    for ads in mfti['DATA']:
        if ads is None:
            continue
        with open_output_file(destfname + '~' + ads) as outf:
            outf.write(mfti['DATA'][ads]())


def convert_img(f):
    """
    Removes first 0x102000 bytes and saves output to ./fname_modified
    :param f: NTFS img
    :return:
    """
    import re

    fname = re.sub("\.img", "_modified.img", f)
    with open(f, "rb") as d:
        print("[*] Reading data from offset 0x102000")
        d.seek(0x102000)
        entry = d.read()
    with open(fname, "wb") as w:
        print(f"[*] Writing data to {fname}")
        w.write(entry)
    print("[+] Completed img conversion!")
    return fname


def parse_args(argv):
    import argparse
    parser = argparse.ArgumentParser(description="Recover files from an NTFS volume")
    parser.add_argument('--sector-size', type=int,
                        help='Sector size in bytes (default: trust filesystem)')
    parser.add_argument('--cluster-size', type=int,
                        help='Cluster size in sectors (default: trust filesystem)')
    parser.add_argument('--mft', type=argparse.FileType('rb'),
                        help='Use given file as MFT')
    parser.add_argument('--save-mft', type=argparse.FileType('wb'),
                        help='Write extracted MFT to given file')
    parser.add_argument('-p', '--pattern', action='append',
                        help='Recover files matching pattern')
    parser.add_argument('-o', '--outdir',
                        help='Output directory (default .)')
    parser.add_argument('disk', help='NTFS partition (e.g. /dev/disk*, \\\\.\\Harddisk*Partition*)')
    return parser.parse_args(argv)


def main(argv):
    args = parse_args(argv)

    f = open(args.disk, 'rb')

    if args.outdir:
        try:
            os.makedirs(args.outdir)
        except OSError:
            pass
        os.chdir(args.outdir)

    if args.outdir is None and args.pattern is not None:
        raise AttributeError("[!] You need to specify an output dir for recovery!")


    # Identify if file type, if not NTFS, raise an error
    if readat(f, 0x3, 8) == b'NTFS    ':
        pass
    elif readat(f, 0x102003, 8) == b'NTFS    ':
        # Remove first 0x102000 to make code usable
        print(f"[!] Cloned img detected!")
        f = open(convert_img(args.disk), 'rb')
    else:
        raise ValueError("[!] Not a NTFS disk or acceptable img format!")

    bps, spc = struct.unpack('<HB', readat(f, 0xb, 3))
    if args.sector_size:
        bps = args.sector_size
    if args.cluster_size:
        spc = args.cluster_size
    bpc = bps * spc
    mft_clust, mftmirr_clust, clust_per_mft = struct.unpack('<QQB', readat(f, 0x30, 17))
    print(f"[*] Calculated MFT info: mft_clust={mft_clust}, mftmirr_clust={mftmirr_clust}, clust_per_mft={clust_per_mft}")

    if args.mft:
        print("[*] Reading from given mft...")
        mftbytes = args.mft.read()
    else:
        print("[*] No MFT given, reading from disk...")
        mftbytes = read_mft(f, bpc, mft_clust, clust_per_mft)

    if args.save_mft:
        print("[*] Saving to mft...")
        args.save_mft.write(mftbytes)

    # Extracted MFT with paired attributes done in parse_file
    mft = parse_mft(f, bpc, mftbytes)

    for i, file in enumerate(mft):

        try:
            fname = file['FILE_NAME'][None]()[1]
        except Exception as e:
            continue

        try:
            fullpath = '/'.join(get_filepath(mft, i))

        except Exception as e:
            fullpath = '__ORPHANED__/' + fname

        if not args.pattern:
            print("\n", fullpath, end=" ")
            if file['DATA']:
                for ads in file['DATA']:
                    if ads is not None:
                        print(f"ADS:{ads}", end="")
            # else:
            #     print(fullpath)
            continue

        for pat in args.pattern:
            pat = pat.lower().encode('utf8')
            if fnmatch.fnmatch(fname.lower().encode('utf8'), pat) or fnmatch.fnmatch(fullpath.lower().encode('utf8'), pat):
                print("Recovering", fullpath, end=' ')
                try:
                    save_file(file, fullpath)
                except Exception as e:
                    print("failed:", e)
                else:
                    print("Success!")


if __name__ == '__main__':
    import sys

    exit(main(sys.argv[1:]))
