// Copyright Eric Chauvin 2020.



/*
winnt.h has this struct:

typedef struct _IMAGE_DOS_HEADER
{ WORD   e_magic;
  WORD   e_cblp;
  WORD   e_cp;
  WORD   e_crlc;
  WORD   e_cparhdr;
  WORD   e_minalloc;
  WORD   e_maxalloc;
  WORD   e_ss;
  WORD   e_sp;
  WORD   e_csum;
  WORD   e_ip;
  WORD   e_cs;
  WORD   e_lfarlc;
  WORD   e_ovno;
  WORD   e_res[4];
  WORD   e_oemid;
  WORD   e_oeminfo;
  WORD   e_res2[10];
  LONG   e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
*/




public class ImageDosHeader
  {
  private MainApp mApp;

  // Using Java int and long because the struct
  // contains unsigned values.  See readFromBytes().

  public int e_magic;  // Identify the kind of file this is.
  public int e_cblp;   // Bytes on the last page.
  public int e_cp; // Pages in file.
  public int e_crlc; // Relocations.
  public int e_cparhdr; // Size of header in paragraphs.
  public int e_minalloc; // Minimum extra paragraphs needed
  public int e_maxalloc; // Maximum extra paragraphs needed
  public int e_ss; // Initial (relative) SS value
  public int e_sp; // Initial SP value
  public int e_csum; // Checksum
  public int e_ip;   // Initial IP value
  public int e_cs;   // Initial (relative) CS value
  public int e_lfarlc; // File address of relocation table
  public int e_ovno;   // Overlay number
  // public int[] e_res = new int[4]; // Array of reserved words.
  public int e_oemid;  // OEM identifier
  public int e_oeminfo;  // OEM information
  // public int[] e_res2 = new int[10]; //  Array of reserved words.
  public long e_lfanew;   // Four bytes. Offest of PE
                          // file header.




  private ImageDosHeader()
    {

    }



  public ImageDosHeader( MainApp useApp )
    {
    mApp = useApp;

    }



  public boolean readFromBytes( byte[] buf )
    {
    final int last = buf.length;
    if( last < 64 )
      {
      mApp.showStatusAsync( "The PE file buffer is less than 64 bytes long." );
      return false;
      }

    int b1 = 0;
    int b2 = 0;
    int b3 = 0;
    int b4 = 0;
    int i = 0;

    // e_magic; 

    b1 = Utility.ByteToShort( buf[0] );
    if( b1 != 'M' ) // Why it's called an MZ header.
      {
      mApp.showStatusAsync( "The Magic letter M is not right." );
      return false;
      }

    b2 = Utility.ByteToShort( buf[1] );
    if( b2 != 'Z' )
      {
      mApp.showStatusAsync( "The Magic letter Z is not right." );
      return false;
      }


    b1 = Utility.ByteToShort( buf[2] );
    b2 = Utility.ByteToShort( buf[3] );

    // Big Endian:
    // int i = b1 << 8;
    // i = i | b2;

    // For Little Endian byte order, the least
    // significant byte is at the smallest address.
    i = b2 << 8;
    i = i | b1;
    // mApp.showStatusAsync( "Little Endian: " + i );
    // mApp.showStatusAsync( "Little Endian hex: " + Integer.toHexString( i ));
    e_cblp = i;

    b1 = Utility.ByteToShort( buf[4] );
    b2 = Utility.ByteToShort( buf[5] );
    i = b2 << 8;
    i = i | b1;
    e_cp = i;
    // mApp.showStatusAsync( "Pages in file: " + i );

    b1 = Utility.ByteToShort( buf[6] );
    b2 = Utility.ByteToShort( buf[7] );
    i = b2 << 8;
    i = i | b1;
    e_crlc = i;

    b1 = Utility.ByteToShort( buf[8] );
    b2 = Utility.ByteToShort( buf[9] );
    i = b2 << 8;
    i = i | b1;
    e_cparhdr = i;

    b1 = Utility.ByteToShort( buf[10] );
    b2 = Utility.ByteToShort( buf[11] );
    i = b2 << 8;
    i = i | b1;
    e_minalloc = i;

    b1 = Utility.ByteToShort( buf[12] );
    b2 = Utility.ByteToShort( buf[13] );
    i = b2 << 8;
    i = i | b1;
    e_maxalloc = i;

    b1 = Utility.ByteToShort( buf[14] );
    b2 = Utility.ByteToShort( buf[15] );
    i = b2 << 8;
    i = i | b1;
    e_ss = i;

    b1 = Utility.ByteToShort( buf[16] );
    b2 = Utility.ByteToShort( buf[17] );
    i = b2 << 8;
    i = i | b1;
    e_sp = i;

    b1 = Utility.ByteToShort( buf[18] );
    b2 = Utility.ByteToShort( buf[19] );
    i = b2 << 8;
    i = i | b1;
    e_csum = i;

    b1 = Utility.ByteToShort( buf[20] );
    b2 = Utility.ByteToShort( buf[21] );
    i = b2 << 8;
    i = i | b1;
    e_ip = i;

    b1 = Utility.ByteToShort( buf[22] );
    b2 = Utility.ByteToShort( buf[23] );
    i = b2 << 8;
    i = i | b1;
    e_cs = i;

    b1 = Utility.ByteToShort( buf[24] );
    b2 = Utility.ByteToShort( buf[25] );
    i = b2 << 8;
    i = i | b1;
    e_lfarlc = i;

    b1 = Utility.ByteToShort( buf[26] );
    b2 = Utility.ByteToShort( buf[27] );
    i = b2 << 8;
    i = i | b1;
    e_ovno = i;

    // = Utility.ByteToShort( buf[28] );
    // = Utility.ByteToShort( buf[29] );
    // = Utility.ByteToShort( buf[30] );
    // = Utility.ByteToShort( buf[31] );
    // = Utility.ByteToShort( buf[32] );
    // = Utility.ByteToShort( buf[33] );
    // = Utility.ByteToShort( buf[34] );
    // = Utility.ByteToShort( buf[35] );
    // e_res[4]; //  Array of reserved words.

    b1 = Utility.ByteToShort( buf[36] );
    b2 = Utility.ByteToShort( buf[37] );
    i = b2 << 8;
    i = i | b1;
    e_oemid = i;

    b1 = Utility.ByteToShort( buf[38] );
    b2 = Utility.ByteToShort( buf[39] );
    i = b2 << 8;
    i = i | b1;
    e_oeminfo = i;

    // = Utility.ByteToShort( buf[40] );
    // = Utility.ByteToShort( buf[41] );
    // = Utility.ByteToShort( buf[42] );
    // = Utility.ByteToShort( buf[43] );
    // = Utility.ByteToShort( buf[44] );
    // = Utility.ByteToShort( buf[45] );
    // = Utility.ByteToShort( buf[46] );
    // = Utility.ByteToShort( buf[47] );
    // = Utility.ByteToShort( buf[48] );
    // = Utility.ByteToShort( buf[49] );
    // = Utility.ByteToShort( buf[50] );
    // = Utility.ByteToShort( buf[51] );
    // = Utility.ByteToShort( buf[52] );
    // = Utility.ByteToShort( buf[53] );
    // = Utility.ByteToShort( buf[54] );
    // = Utility.ByteToShort( buf[55] );
    // = Utility.ByteToShort( buf[56] );
    // = Utility.ByteToShort( buf[57] );
    // = Utility.ByteToShort( buf[58] );
    // = Utility.ByteToShort( buf[59] );
    // e_res2[10]; // Array of reserved words.

    b1 = Utility.ByteToShort( buf[60] );
    b2 = Utility.ByteToShort( buf[61] );
    b3 = Utility.ByteToShort( buf[62] );
    b4 = Utility.ByteToShort( buf[63] );

    i = b4 << 24;
    i = i | (b3 << 16);
    i = i | (b2 << 8);
    i = i | b1;
    e_lfanew = i;   // Offest of PE file header.

    mApp.showStatusAsync( "The DOS header is OK." );
    return true;
    }


  public long getOffsetOfPEFileHeader()
    {
    return e_lfanew;
    }



  }
