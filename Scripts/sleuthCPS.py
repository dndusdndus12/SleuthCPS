import argparse
import csv
import os
import shlex

def print_banner():
    """Prints the ASCII art banner."""
    banner = r"""
  /$$$$$$  /$$                       /$$     /$$              /$$$$$$  /$$$$$$$   /$$$$$$ 
 /$$__  $$| $$                      | $$    | $$             /$$__  $$| $$__  $$ /$$__  $$
| $$  \__/| $$  /$$$$$$  /$$   /$$ /$$$$$$  | $$$$$$$       | $$  \__/| $$  \ $$| $$  \__/
|  $$$$$$ | $$ /$$__  $$| $$  | $$|_  $$_/  | $$__  $$      | $$      | $$$$$$$/|  $$$$$$ 
 \____  $$| $$| $$$$$$$$| $$  | $$  | $$    | $$  \ $$      | $$      | $$____/  \____  $$
 /$$  \ $$| $$| $$_____/| $$  | $$  | $$ /$$| $$  | $$      | $$    $$| $$       /$$  \ $$
|  $$$$$$/| $$|  $$$$$$$|  $$$$$$/  |  $$$$/| $$  | $$      |  $$$$$$/| $$      |  $$$$$$/
 \______/ |__/ \_______/ \______/    \___/  |__/  |__/       \______/ |__/       \______/                             
    """
    print(banner)

def hexdump(data, start_offset=0):
    """Generates a hexdump of the given data."""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        offset_str = f"0x{start_offset + i:08X}"
        hex_part = ' '.join(f"{b:02X}" for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        lines.append(f"{offset_str} | {hex_part:<48} | {ascii_part}")
    return "\n".join(lines)

class SleuthParser:
    def __init__(self, binary_file, csv_profile):
        """Initializes the parser by loading the binary and CSV files."""
        if not os.path.exists(binary_file):
            raise FileNotFoundError(f"Error: Binary file '{binary_file}' not found.")
        if not os.path.exists(csv_profile):
            raise FileNotFoundError(f"Error: CSV profile file '{csv_profile}' not found.")

        with open(binary_file, 'rb') as f:
            self.binary_data = f.read()

        self.structures = {}
        with open(csv_profile, 'r', newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Strip whitespace from field names
                clean_row = {k.strip(): v.strip() for k, v in row.items()}
                self.structures[clean_row['name']] = clean_row

        self.resolved_offsets = {}
        # store sizes discovered when resolving metadata pointers
        self.resolved_sizes = {}

    def _get_absolute_offset(self, name, visited=None):
        """Recursively resolves the absolute offset of a structure."""
        if visited is None:
            visited = set()

        if name in self.resolved_offsets:
            return self.resolved_offsets[name]

        if name in visited:
            raise RecursionError(f"Error: Circular reference detected (e.g., A -> B -> A). Path: {' -> '.join(visited)} -> {name}")
        
        visited.add(name)

        structure = self.structures.get(name)
        if not structure:
            raise KeyError(f"Error: Structure named '{name}' not found in the profile.")

        # Case 1: Absolute 'offset' is directly provided.
        if structure.get('offset'):
            try:
                offset = int(structure['offset'], 0)
                self.resolved_offsets[name] = offset
                return offset
            except ValueError:
                raise ValueError(f"Error: Invalid offset value for '{name}': {structure['offset']}")
        
        # Case 2: Relative 'rOffset' and 'parent' are provided.
        elif structure.get('rOffset') and structure.get('parent'):
            parent_name = structure['parent']
            try:
                r_offset = int(structure['rOffset'], 0)
            except ValueError:
                raise ValueError(f"Error: Invalid rOffset value for '{name}': {structure['rOffset']}")

            parent_offset = self._get_absolute_offset(parent_name, visited)
            # rOffset points to metadata located at parent_offset + r_offset
            meta_ptr = parent_offset + r_offset
            try:
                meta = self._read_metadata(meta_ptr)
            except Exception:
                meta = None

            if meta is not None:
                data_ptr, size = meta
                # store resolved data pointer and discovered size
                self.resolved_offsets[name] = data_ptr
                self.resolved_sizes[name] = size
                return data_ptr

            # fallback: treat as relative data location
            absolute_offset = parent_offset + r_offset
            self.resolved_offsets[name] = absolute_offset
            return absolute_offset
        else:
            raise ValueError(f"Error: Structure '{name}' must have either an 'offset' or both 'rOffset' and 'parent' defined.")

    def _read_metadata(self, meta_ptr):
        """
        Read metadata at meta_ptr. Tries to read (data_ptr, size).
        Supports two layouts:
          - 4-byte data_ptr + 4-byte size (8 bytes total)
          - 8-byte data_ptr + 4-byte size (12 bytes total)
        Assumes little-endian.
        Returns tuple (data_ptr, size) or raises on error.
        """
        bd = self.binary_data
        n = len(bd)
        if meta_ptr < 0 or meta_ptr >= n:
            raise ValueError('Metadata pointer out of range')

        # Try 4-byte pointer + 4-byte size
        if meta_ptr + 8 <= n:
            data_ptr_32 = int.from_bytes(bd[meta_ptr:meta_ptr+4], 'little')
            size_32 = int.from_bytes(bd[meta_ptr-4:meta_ptr], 'little')
            if 0 <= data_ptr_32 < n and 0 <= data_ptr_32 + size_32 <= n:
                return (data_ptr_32, size_32)


        raise ValueError('No valid metadata found at pointer')

    def resolve_all_offsets(self):
        """Resolves offsets for all structures defined in the CSV."""
        for name in self.structures:
            if name not in self.resolved_offsets:
                self._get_absolute_offset(name)
    
    def list_structures(self):
        """Lists all structures and their resolved offsets."""
        self.resolve_all_offsets()
        print(f"{'Structure Name':<30} {'Absolute Offset':<20} {'Size'}")
        print("-" * 60)
        for name, details in self.structures.items():
            offset = self.resolved_offsets.get(name)
            offset_str = f"0x{offset:X}" if offset is not None else "N/A"
            size = details.get('size', 'N/A')
            print(f"{name:<30} {offset_str:<20} {size}")

    def view_structure(self, name):
        """Displays the content of a structure as a hexdump."""
        offset = self._get_absolute_offset(name)
        details = self.structures[name]
        try:
            size = int(details['size'], 0)
        except (ValueError, KeyError):
            raise ValueError(f"Error: Invalid or missing size value for '{name}'.")
        
        data_slice = self.binary_data[offset:offset+size]
        print(f"--- Contents of '{name}' (Offset: 0x{offset:X}, Size: {size} bytes) ---")
        print(hexdump(data_slice, start_offset=offset))
        print("--- End of data ---")

    def dump_structure(self, name, output_file=None):
        """Dumps the content of a structure to a binary file."""
        if output_file is None:
            output_file = f"{name}.bin"
        
        offset = self._get_absolute_offset(name)
        details = self.structures[name]
        try:
            size = int(details['size'], 0)
        except (ValueError, KeyError):
            raise ValueError(f"Error: Invalid or missing size value for '{name}'.")
            
        data_slice = self.binary_data[offset:offset+size]
        with open(output_file, 'wb') as f:
            f.write(data_slice)
        print(f"Success: Dumped {size} bytes from '{name}' to '{output_file}'.")

    def write_resolved_csv(self, output_csv_path):
        """Writes a new CSV file with all absolute offsets filled in."""
        self.resolve_all_offsets()
        
        fieldnames = ['name', 'offset', 'size', 'rOffset', 'parent']
        with open(output_csv_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for name, details in self.structures.items():
                new_row = {
                    'name': name,
                    'offset': f"0x{self.resolved_offsets.get(name, 0):X}",
                    'size': details.get('size', ''),
                    'rOffset': details.get('rOffset', ''),
                    'parent': details.get('parent', '')
                }
                writer.writerow(new_row)
        print(f"Success: Wrote resolved profile with absolute offsets to '{output_csv_path}'.")

def main():
    # Make help explicit so -h/--help works even when add_help is disabled
    parser = argparse.ArgumentParser(
        description="A SleuthCPS forensic tool (interactive mode).",
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False
    )
    # explicit help flag only; script runs interactively without positional args
    parser.add_argument('-h', '--help', action='store_true', help='Show this help message and exit')
    parser.add_argument('-q', '--quiet', action='store_true', help="Do not display the ASCII art banner.")
    parser.add_argument('-p', '--profile', dest='profile', help='Path to CSV profile to preload into the REPL')
    parser.add_argument('-i', '--input', '--image', dest='image', help='Path to binary image to preload into the REPL')

    args = parser.parse_args()

    # If user asked for help via CLI, show argparse help and exit
    if getattr(args, 'help', False):
        parser.print_help()
        return

    # Start interactive REPL
    if not args.quiet:
        print_banner()

    class InteractiveSleuth:
        def __init__(self):
            self.binary_path = None
            self.binary_data = None
            self.csv_path = None
            self.structures = {}
            self.resolved_offsets = {}
            self.resolved_sizes = {}
            self.outputs = []

        def load_binary(self, path):
            try:
                with open(path, 'rb') as f:
                    self.binary_data = f.read()
                self.binary_path = path
                print(f"Loaded binary: {path} ({len(self.binary_data)} bytes)")
            except Exception as e:
                cwd = os.getcwd()
                abs_path = os.path.abspath(path)
                print(f"Error loading binary '{path}': {e}")
                print(f" Current working directory: {cwd}")
                print(f" Attempted path (absolute): {abs_path}")

        def load_csv(self, path, print_contents=True):
            try:
                with open(path, 'r', newline='') as f:
                    reader = csv.DictReader(f)
                    self.structures = {}
                    for row in reader:
                        clean_row = {k.strip(): (v.strip() if v is not None else '') for k, v in row.items()}
                        name = clean_row.get('name')
                        if name:
                            self.structures[name] = clean_row
                self.csv_path = path
                print(f"Loaded CSV profile: {path} ({len(self.structures)} entries)")
                if print_contents:
                    self.print_csv()
            except Exception as e:
                cwd = os.getcwd()
                abs_path = os.path.abspath(path)
                print(f"Error loading CSV '{path}': {e}")
                print(f" Current working directory: {cwd}")
                print(f" Attempted path (absolute): {abs_path}")

        def print_csv(self):
            if not self.structures:
                print("No CSV profile loaded.")
                return
            print(f"{'name':<20} {'offset':<12} {'size':<8} {'rOffset':<8} {'parent'}")
            print('-' * 60)
            for name, d in self.structures.items():
                print(f"{name:<20} {d.get('offset',''):<12} {d.get('size',''):<8} {d.get('rOffset',''):<8} {d.get('parent','')}")

        def hexdump(self, data, start_offset=0, width=16):
            lines = []
            for i in range(0, len(data), width):
                chunk = data[i:i+width]
                offset_str = f"0x{start_offset + i:08X}"
                hex_part = ' '.join(f"{b:02X}" for b in chunk)
                ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                lines.append(f"{offset_str} | {hex_part:<{width*3}} | {ascii_part}")
            return "\n".join(lines)

        def dump_slice(self, offset, size, name=None):
            if self.binary_data is None:
                print("No binary loaded.")
                return
            if offset < 0 or offset + size > len(self.binary_data):
                print(f"Requested range out of bounds: 0x{offset:X} - 0x{offset+size:X}")
                return
            data_slice = self.binary_data[offset:offset+size]
            fname = f"{name or 'unknown'}_{offset}_{size}.img"
            try:
                with open(fname, 'wb') as f:
                    f.write(data_slice)
                print(f"Wrote extract to: {fname}")
                # track outputs for status
                try:
                    self.outputs.append(os.path.abspath(fname))
                except Exception:
                    self.outputs.append(fname)
            except Exception as e:
                print(f"Error writing extract file: {e}")

        def parse_num(self, s):
            s = s.strip()
            try:
                return int(s, 0)
            except Exception:
                raise ValueError(f"Invalid number: {s}")

        def analyze_abs(self, name, width=16, extract=False):
            try:
                if name not in self.structures:
                    print(f"Structure '{name}' not found in profile.")
                    return
                details = self.structures[name]
                if not details.get('offset'):
                    print(f"Structure '{name}' has no absolute offset in CSV.")
                    return
                offset = self.parse_num(details['offset'])
                if not details.get('size'):
                    print(f"Structure '{name}' has no size in CSV.")
                    return
                size = self.parse_num(details['size'])
                if self.binary_data is None:
                    print("No binary loaded.")
                    return
                if offset < 0 or offset + size > len(self.binary_data):
                    print(f"[WARNING] The address(offset) is out of range when analyzing '{name}': 0x{offset:X} + {size} bytes.")

                data_slice = self.binary_data[offset:offset+size]
                print(f"--- Contents of '{name}' (Offset: 0x{offset:X}, Size: {size} bytes) ---")
                print(self.hexdump(data_slice, start_offset=offset, width=width))
                print('--- End of data ---')
                if extract:
                    self.dump_slice(offset, size, name=name)
            except Exception as e:
                print(f"Error in analyze_abs('{name}'): {e}")

        def _resolve_offset_recursive(self, name, visited=None):
            if visited is None:
                visited = set()
            if name in self.resolved_offsets:
                return self.resolved_offsets[name]
            if name in visited:
                raise RecursionError(f"Circular reference detected: {' -> '.join(list(visited) + [name])}")
            visited.add(name)
            struct = self.structures.get(name)
            if not struct:
                raise KeyError(f"Structure '{name}' not found")
            if struct.get('offset'):
                off = self.parse_num(struct['offset'])
                self.resolved_offsets[name] = off
                return off
            if struct.get('rOffset') and struct.get('parent'):
                parent = struct['parent']
                r = self.parse_num(struct['rOffset'])
                parent_off = self._resolve_offset_recursive(parent, visited)
                # rOffset points to metadata located at parent_off + r
                meta_ptr = parent_off + r
                meta = None
                try:
                    meta = self._read_metadata(meta_ptr)
                except Exception:
                    meta = None

                if meta is not None:
                    data_ptr, size = meta
                    # store resolved data pointer and size
                    self.resolved_offsets[name] = data_ptr
                    self.resolved_sizes[name] = size
                    return data_ptr
                # fallback: treat as relative data location
                off = parent_off + r
                self.resolved_offsets[name] = off
                return off
            raise ValueError(f"Structure '{name}' must have either 'offset' or both 'rOffset' and 'parent'.")

        def _read_metadata(self, meta_ptr):
            """
            Read metadata at meta_ptr. Tries to read (data_ptr, size).
            Supports two layouts:
              - 4-byte data_ptr + 4-byte size (8 bytes total)
              - 8-byte data_ptr + 4-byte size (12 bytes total)
            Assumes little-endian.
            Returns tuple (data_ptr, size) or raises on error.
            """
            bd = self.binary_data
            n = len(bd)
            # try 8-byte read first (4+4)
            if meta_ptr < 0 or meta_ptr + 8 > n:
                raise ValueError('Metadata pointer out of range')
            # read 4-byte pointer and 4-byte size
            data_ptr_32 = int.from_bytes(bd[meta_ptr:meta_ptr+4], 'little')
            size_32 = int.from_bytes(bd[meta_ptr-4:meta_ptr], 'little')
            # validate
            if 0 <= data_ptr_32 < n and 0 <= data_ptr_32 + size_32 <= n:
                return (data_ptr_32, size_32)

            # try 64-bit pointer + 32-bit size if enough room
            if meta_ptr + 12 <= n:
                data_ptr_64 = int.from_bytes(bd[meta_ptr:meta_ptr+8], 'little')
                size_64 = int.from_bytes(bd[meta_ptr+8:meta_ptr+12], 'little')
                if 0 <= data_ptr_64 < n and 0 <= data_ptr_64 + size_64 <= n:
                    return (data_ptr_64, size_64)

            raise ValueError('No valid metadata found at pointer')

        def analyze_rel(self, name, width=16, extract=False):
            print_data_slice = True
            try:
                if self.binary_data is None:
                    print("No binary loaded.")
                    return
                if name not in self.structures:
                    print(f"Structure '{name}' not found in profile.")
                    return
                # Resolve absolute offset using rOffset chain
                try:
                    absolute = self._resolve_offset_recursive(name)
                except Exception as e:
                    print(f"Failed to resolve absolute offset for '{name}': {e}")
                    return
                # If metadata resolved a size earlier, use it
                size = None
                if name in self.resolved_sizes:
                    size = self.resolved_sizes[name]
                else:
                    # size is read from 4 bytes immediately before absolute offset
                    size_ptr = absolute - 4
                    if size_ptr < 0 or size_ptr + 4 > len(self.binary_data):
                        print(f"Cannot read size for '{name}': size pointer out of range (0x{size_ptr:X})")
                        return
                    size_bytes = self.binary_data[size_ptr:size_ptr+4]
                    size = int.from_bytes(size_bytes, 'little')
                    # Some layouts store size immediately before a 4-byte pointer at 'absolute'.
                    # In that case the actual data pointer is the 4 bytes starting at 'absolute'.
                    # If possible, read a 4-byte pointer at 'absolute' and update the resolved offset.
                    if absolute + 4 <= len(self.binary_data):
                        try:
                            new_ptr = int.from_bytes(self.binary_data[absolute:absolute+4], 'little')
                            # validate
                            # if 0 <= new_ptr <= len(self.binary_data):
                                # update absolute to the real data pointer and record resolved info
                            absolute = new_ptr
                            self.resolved_offsets[name] = absolute
                            self.resolved_sizes[name] = size
                        except Exception:
                            # if we can't parse the pointer, leave absolute as-is
                            pass
                # compare with csv size
                csv_size = None
                csv_offset = None
                try:
                    csv_size = self.parse_num(self.structures[name].get('size','')) if self.structures[name].get('size') else None
                    csv_offset = self.parse_num(self.structures[name].get('offset','')) if self.structures[name].get('offset') else None
                except Exception:
                    csv_size = None
                    csv_offset = None
                if csv_size is None or csv_size != size or csv_offset is None or csv_offset != absolute:
                    print(f"Size mismatch or missing for '{name}': CSV={csv_size} Binary={size} -> updating CSV output file.")
                    # update CSV file by writing a new CSV with corrected size
                    if self.csv_path:
                        updated_path = f"{self.csv_path}_updated.csv"
                    else:
                        updated_path = "profile_updated.csv"
                    try:
                        fieldnames = ['name','offset','size','rOffset','parent']
                        with open(updated_path, 'w', newline='') as f:
                            writer = csv.DictWriter(f, fieldnames=fieldnames)
                            writer.writeheader()
                            for nm, details in self.structures.items():
                                out = {
                                    'name': nm,
                                    'offset': details.get('offset',''),
                                    'size': details.get('size',''),
                                    'rOffset': details.get('rOffset',''),
                                    'parent': details.get('parent','')
                                }
                                if nm == name:
                                    out['size'] = f"0x{size:X}"
                                    out['offset'] = f"0x{absolute:X}"
                                writer.writerow(out)
                        print(f"Wrote updated CSV to: {updated_path}")
                        print(f"[WARNING] Set profile to updated CSV for future operations.\n")
                        self.load_csv(updated_path, print_contents=False)
                    except Exception as e:
                        print(f"Failed to write updated CSV: {e}")
                # now print content
                if absolute < 0 or absolute + size > len(self.binary_data):
                    print(f"[WARNING] The address(offset) is out of range when analyzing '{name}': 0x{absolute:X} + {size:X} bytes\n\
                          Absolute offset has been updated.")
                    print_data_slice = False
                    # return
                print(f"--- Contents of '{name}' (Resolved Offset: 0x{absolute:X}, Size (from binary): {size:X} bytes) ---")

                if print_data_slice:
                    data_slice = self.binary_data[absolute:absolute+size]
                    print(self.hexdump(data_slice, start_offset=absolute, width=width))
                    print('--- End of data ---')

                if extract:
                    self.dump_slice(absolute, size, name=name)
            except Exception as e:
                print(f"Error in analyze_rel('{name}'): {e}")

    repl = InteractiveSleuth()

    # Pre-load profile/image if provided via CLI
    if getattr(args, 'profile', None):
        try:
            repl.load_csv(args.profile)
        except Exception as e:
            print(f"Failed to preload profile '{args.profile}': {e}")
    if getattr(args, 'image', None):
        try:
            repl.load_binary(args.image)
        except Exception as e:
            print(f"Failed to preload image '{args.image}': {e}")

    HELP_TEXT = '''Available commands:
  h|help                       Show this help text
  loadcsv <path>               Load CSV profile and display its contents
  setimg <path>                Set target image dump for analysis
  showcsv                      Print currently loaded CSV entries
  status                       Show current CSV, target image, and generated output files
  list                         List structures (names and known offsets)
  hex <offset> <size> [w=N] [extract]
                               Show hex dump from absolute offset (offset can be 0x... or decimal). Default width is [w=16]
  aa|analyze_abs <name> [w=N] [extract]
                               Analyze named structure using CSV absolute offset and CSV size. Default width is [w=16]
  ar|analyze_rel <name> [w=N] [extract]
                               Analyze named structure by resolving rOffset chain and reading size from 4 bytes before the resolved offset
  exit                         Exit the program. Default width is [w=16]
'''

    print("Interactive mode. Type 'h' or 'help' for commands.")
    try:
        while True:
            try:
                line = input('sleuth> ').strip()
            except EOFError:
                print('\nExiting.')
                break
            if not line:
                continue
            # parse shell-like tokens so quoted paths with spaces are handled
            try:
                parts = shlex.split(line)
            except ValueError as e:
                # likely unmatched quotes; provide helpful guidance for Windows paths
                print(f"Input parse error: {e}")
                print("If your path contains spaces, wrap it in quotes. If it ends with a backslash, escape it or use forward slashes.")
                parts = line.split()
            cmd = parts[0].lower()
            args2 = parts[1:]
            if cmd in ('h','help'):
                print(HELP_TEXT)
                continue
            if cmd == 'loadcsv' or cmd =='setcsv':
                if not args2:
                    print('Usage: loadcsv <path>')
                    continue
                repl.load_csv(args2[0])
                continue
            if cmd == 'setimg' or cmd == 'loadbin' or cmd == 'setbin' or cmd == 'loadimg':
                if not args2:
                    print('Usage: setimg <path>')
                    continue
                repl.load_binary(args2[0])
                continue
            if cmd == 'showcsv':
                repl.print_csv()
                continue
            if cmd == 'status':
                print('Current status:')
                print(f" CSV profile: {repl.csv_path or 'None'}")
                print(f" Target image: {repl.binary_path or 'None'}")
                print(' Generated outputs:')
                if repl.outputs:
                    for out in repl.outputs:
                        print(f"  - {out}")
                else:
                    print('  (none)')
                continue
            if cmd == 'list':
                # show resolved offsets where possible
                if not repl.structures:
                    print('No CSV loaded.')
                    continue
                print(f"{'name':<20} {'resolved_offset':<18} {'size'}")
                print('-'*60)
                # attempt to resolve offsets for all
                repl.resolved_offsets = {}
                for nm in repl.structures:
                    try:
                        off = repl._resolve_offset_recursive(nm)
                        print(f"{nm:<20} 0x{off:08X} {repl.structures[nm].get('size','')}")
                    except Exception:
                        print(f"{nm:<20} {'N/A':<18} {repl.structures[nm].get('size','')}")
                continue
            if cmd == 'hex':
                if len(args2) < 2:
                    print('Usage: hex <offset> <size> [w=N] [extract]')
                    continue
                try:
                    off = repl.parse_num(args2[0])
                    sz = repl.parse_num(args2[1])
                    width = 16
                    extract = False
                    for a in args2[2:]:
                        if a.startswith('w='):
                            width = int(a.split('=',1)[1])
                        if a == 'extract' or a == '-e':
                            extract = True
                    if repl.binary_data is None:
                        print('No binary loaded.')
                        continue
                    if off < 0 or off+sz > len(repl.binary_data):
                        print('Requested range out of bounds.')
                        continue
                    print(repl.hexdump(repl.binary_data[off:off+sz], start_offset=off, width=width))
                    if extract:
                        repl.dump_slice(off, sz, name=None)
                except Exception as e:
                    print(f'Error in hex: {e}')
                continue
            if cmd == 'aa' or cmd == 'analyze_abs':
                if not args2:
                    print('Usage: analyze_abs <name> [w=N] [extract]')
                    continue
                name = args2[0]
                width = 16
                extract = False
                for a in args2[1:]:
                    if a.startswith('w='):
                        width = int(a.split('=',1)[1])
                    if a == 'extract' or a == '-e':
                        extract = True
                repl.analyze_abs(name, width=width, extract=extract)
                continue
            if cmd == 'ar' or cmd == 'analyze_rel':
                if not args2:
                    print('Usage: analyze_rel <name> [w=N] [extract]')
                    continue
                name = args2[0]
                width = 16
                extract = False
                for a in args2[1:]:
                    if a.startswith('w='):
                        width = int(a.split('=',1)[1])
                    if a == 'extract' or a == '-e':
                        extract = True
                repl.analyze_rel(name, width=width, extract=extract)
                continue
            if cmd == 'exit' or cmd == 'quit':
                print('Exiting.')
                break
            print(f"Unknown command: {cmd}. Type 'h' for help.")
    except KeyboardInterrupt:
        print('\nInterrupted. Exiting.')

if __name__ == "__main__":
    main()

