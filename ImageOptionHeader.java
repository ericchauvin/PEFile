// Copyright Eric Chauvin 2020.



// winnt.h has these structures:
// typedef struct _IMAGE_OPTIONAL_HEADER
// This is for the 64 bit version of the PE file.
// typedef struct _IMAGE_OPTIONAL_HEADER64



public class ImageOptionalHeader
  {
  private MainApp mApp;
  private int Magic;
  private int MajorLinkerVersion;
  private int MinorLinkerVersion;
  private long SizeOfCode;
  private long SizeOfInitializedData;
  private long SizeOfUninitializedData;
  private long AddressOfEntryPoint;
  private long BaseOfCode;
  private long BaseOfData;
  // Apparently the standard COFF fields end here.
  // More Windows fields start here.
  private long ImageBase;
  private long SectionAlignment;
  private long FileAlignment;
  private int MajorOperatingSystemVersion;
  private int MinorOperatingSystemVersion;
  private int MajorImageVersion;
  private int MinorImageVersion;
  private int MajorSubsystemVersion;
  private int MinorSubsystemVersion;
  private long Win32VersionValue;
  private long SizeOfImage;
  private long SizeOfHeaders;
  private long CheckSum;
  private int Subsystem;
  private int DllCharacteristics;
  private long SizeOfStackReserve;
  private long SizeOfStackCommit;
  private long SizeOfHeapReserve;
  private long SizeOfHeapCommit;
  private long LoaderFlags;
  private long NumberOfRvaAndSizes;
  
  // IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];




  private ImageOptionalHeader()
    {
    }


  public ImageOptionalHeader( MainApp useApp )
    {
    mApp = useApp;
    }


  public int readPEType( byte[] buf, int start )
    {
    if( buf.length < (start + 2))
      {
      mApp.showStatusAsync( "The PE file buffer is too short." );
      return 0;
      }

    int b1 = Utility.ByteToShort( buf[start + 0] );
    int b2 = Utility.ByteToShort( buf[start + 1] );
    int i = b2 << 8;
    i = i | b1;
    return i;
    }



  public boolean readFromBytes( byte[] buf, int start )
    {
    int PEType = readPEType( buf, start );
    if( PEType == 0x10b ) // PE32
      {
      mApp.showStatusAsync( "PE type is PE32." );
      return readPE32FromBytes( buf, start );
      }

    if( PEType == 0x20b ) // PE32+
      {
      mApp.showStatusAsync( "PE type is PE32+." );
      return readPE32PlusFromBytes( buf, start );
      }

    mApp.showStatusAsync( "The PE file type is not known." );
    return false;
    }



  public boolean readPE32FromBytes( byte[] buf, int start )
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

    return true;
    }



  public boolean readPE32PlusFromBytes( byte[] buf, int start )
    {
    return true;
    }


  }
