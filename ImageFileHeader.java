// Copyright Eric Chauvin 2020.


// This is a standard COFF file header.

/*
winnt.h has this struct:

typedef struct _IMAGE_FILE_HEADER
{ WORD   Machine;
  WORD   NumberOfSections;
  DWORD   TimeDateStamp;
  DWORD   PointerToSymbolTable;
  DWORD   NumberOfSymbols;
  WORD   SizeOfOptionalHeader;
  WORD   Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
*/



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
 
/*

 WORD   NumberOfSections;
  DWORD   TimeDateStamp;
  DWORD   PointerToSymbolTable;
  DWORD   NumberOfSymbols;
  WORD   SizeOfOptionalHeader;
  WORD   Characteristics;
*/

    return true;
    }



  }
