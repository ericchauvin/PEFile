// Copyright Eric Chauvin 2020.



// This is a standard COFF file header.

// winnt.h has this struct:
// typedef struct _IMAGE_FILE_HEADER




public class ImageFileHeader
  {
  private MainApp mApp;
  private int Machine;
  private int NumberOfSections;
  private long TimeDateStamp;
  private int PointerToSymbolTable;
  private int NumberOfSymbols;
  private int SizeOfOptionalHeader;
  private int Characteristics;



  private ImageFileHeader()
    {
    }


  public ImageFileHeader( MainApp useApp )
    {
    mApp = useApp;
    }



  public boolean readFromBytes( byte[] buf, int start )
    {
    final int last = buf.length;
    if( last < (start + 64) )
      {
      mApp.showStatusAsync( "The PE file buffer is too short." );
      return false;
      }

    int b1 = 0;
    int b2 = 0;
    int b3 = 0;
    int b4 = 0;
    int i = 0;

    b1 = Utility.ByteToShort( buf[start + 0] );
    b2 = Utility.ByteToShort( buf[start + 1] );

    // For Little Endian byte order, the least
    // significant byte is at the smallest address.
    i = b2 << 8;
    i = i | b1;
    Machine = i;
    mApp.showStatusAsync( "Machine type: " + Integer.toHexString( i ));

// IMAGE_FILE_MACHINE_AMD64   0x8664
// IMAGE_FILE_MACHINE_I386     0x14c  // Intel 386 or later.

 
    b1 = Utility.ByteToShort( buf[start + 2] );
    b2 = Utility.ByteToShort( buf[start + 3] );
    i = b2 << 8;
    i = i | b1;
    NumberOfSections = i;

    // = Utility.ByteToShort( buf[start + 4] );
    // = Utility.ByteToShort( buf[start + 5] );
    // = Utility.ByteToShort( buf[start + 6] );
    // = Utility.ByteToShort( buf[start + 7] );
    //   DWORD   TimeDateStamp;

    b1 = Utility.ByteToShort( buf[start + 8] );
    b2 = Utility.ByteToShort( buf[start + 9] );
    b3 = Utility.ByteToShort( buf[start + 10] );
    b4 = Utility.ByteToShort( buf[start + 11] );

    if( (b4 & 0x80) != 0 )
      {
      mApp.showStatusAsync( "The unsigned PointerToSymbolTable value has gone negative." );
      return false;
      }

    i = b4 << 24;
    i = i | (b3 << 16);
    i = i | (b2 << 8);
    i = i | b1;
    PointerToSymbolTable = i;

    b1 = Utility.ByteToShort( buf[start + 12] );
    b2 = Utility.ByteToShort( buf[start + 13] );
    b3 = Utility.ByteToShort( buf[start + 14] );
    b4 = Utility.ByteToShort( buf[start + 15] );

    if( (b4 & 0x80) != 0 )
      {
      mApp.showStatusAsync( "The unsigned NumberOfSymbols value has gone negative." );
      return false;
      }

    i = b4 << 24;
    i = i | (b3 << 16);
    i = i | (b2 << 8);
    i = i | b1;
    NumberOfSymbols = i;

    b1 = Utility.ByteToShort( buf[start + 16] );
    b2 = Utility.ByteToShort( buf[start + 17] );
    i = b2 << 8;
    i = i | b1;
    SizeOfOptionalHeader = i;

    b1 = Utility.ByteToShort( buf[start + 18] );
    b2 = Utility.ByteToShort( buf[start + 19] );
    i = b2 << 8;
    i = i | b1;
    Characteristics = i;

    return true;
    }



  }
