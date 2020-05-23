#include <fstream>
#include <iomanip>
#include <iostream>

#include "icemu/MemoryDump.h"
#include "icemu/emu/Memory.h"

using namespace std;
using namespace icemu;

// https://gist.github.com/shreyasbharath/32a8092666303a916e24a81b18af146b
void HexDump(const uint8_t *bytes, size_t size, std::ostream &stream) {
  char buff[17];
  size_t i = 0;

  stream << std::hex;

  // Process every byte in the data.
  for (i = 0; i < size; i++) {
    // Multiple of 16 means new line (with line offset).

    if ((i % 16) == 0) {
      // Just don't print ASCII for the zeroth line.
      if (i != 0) {
        stream << "  " << buff << std::endl;
      }

      // Output the offset.
      stream << "  " << std::setw(8) << std::setfill('0')
             << static_cast<unsigned int>(i);
    }

    // Now the hex code for the specific character.
    stream << " " << std::setw(2) << std::setfill('0')
           << static_cast<unsigned int>(bytes[i]);

    // And store a printable ASCII character for later.
    if ((bytes[i] < 0x20) || (bytes[i] > 0x7e)) {
      buff[i % 16] = '.';
    } else {
      buff[i % 16] = bytes[i];
    }
    buff[(i % 16) + 1] = '\0';
  }

  stream << std::dec;

  // Pad out last line if not exactly 16 characters.
  while ((i % 16) != 0) {
    stream << "   ";
    i++;
  }

  // And print the final ASCII bit.
  stream << "  " << buff << std::endl;
}

static string dump_filename(const memseg_t &m, string &prefix, string dt_str) {
  string filename = prefix + m.name + dt_str;
  return filename;
}

bool MemoryDump::dump(Memory &mem, string prefix, enum dump_type dt) {
  for (const auto &m : mem.memory) {
    switch (dt) {
      case HEX: {
        string filename = dump_filename(m, prefix, "-hex.txt");
        cout << "Dumping Segment: " << m.name << " to file: " << filename
             << endl;
        ofstream outfile;
        outfile.open(filename, ios::out | ios::trunc);
        HexDump((const uint8_t *)m.data, m.length, outfile);
        outfile.close();
      } break;
      case BIN: {
        string filename = dump_filename(m, prefix, ".bin");
        cout << "Dumping Segment: " << m.name << " to file: " << filename
             << endl;
        ofstream outfile;
        outfile.open(filename, ios::out | ios::trunc | ios::binary);
        outfile.write((const char *)m.data, m.length);
        outfile.close();
      } break;
    }
  }
  return true;
}
