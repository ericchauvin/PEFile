// Copyright Eric Chauvin 2020.



// Portable Executable File
// Common Object File Format (COFF)

// For 64 bits PE32+ or PE+.
// Almost exactly the same as the PE format
// But see struct IMAGE_OPTIONAL_HEADER64
// instead of IMAGE_OPTIONAL_HEADER.
// 32 bit addresses are changed to 64 bit addresses.
// See also the structs IMAGE_TLS_DIRECTORY
// and IMAGE_LOAD_CONFIG_DIRECTORY.

// For Linux it's the ELF format.
// Executable and Linkable Format


// A PE file starts with an old MS-DOS structure at
// the beginning of the file.  It is defined in
// ImageDosHeader.java.

// winnt.h has struct definitions used for the PEFile.

// After that is the real-mode DOS stub program.
// It would run if you actually tried to
// run it on DOS.  (Obviously this file format
// has a long history.)



public class ViewPEFile
  {
  private MainApp mApp;
  private byte[] fileBytes;

 

  private ViewPEFile()
    {
    }



  public ViewPEFile( MainApp useApp )
    {
    mApp = useApp;
    }

  


  public boolean startView()
    {
    StrA fileName = new StrA(
                        "\\EricMain\\cpp\\main.exe" );

    mApp.showStatusAsync( "Started PEFile view." );
    fileBytes = FileUtility.readFileBytes(
                                       mApp,
                                           fileName );

    if( fileBytes == null )
      {
      mApp.showStatusAsync( "fileBytes was null." );
      return false;
      }

    final int last = fileBytes.length;
    mApp.showStatusAsync( "Bytes in file: " + last );

    ImageDosHeader dosHeader = new 
                              ImageDosHeader( mApp );

    if( !dosHeader.readFromBytes( fileBytes ))
      return false;

    int peOffSet = dosHeader.getOffsetOfPEFileHeader();

    mApp.showStatusAsync( "peOffSet: " + peOffSet );
    // mApp.showStatusAsync( "peOffSet hex: " + Integer.toHexString( (int)peOffSet ));
    // int test = 0x3C;
    // mApp.showStatusAsync( "0x3C: " + test );

    int b = Utility.ByteToShort( fileBytes[peOffSet] );
    if( b != 'P' )
      {
      mApp.showStatusAsync( "Sig byte 0 is not P." );
      return false;
      }

    b = Utility.ByteToShort( fileBytes[peOffSet + 1] );
    if( b != 'E' )
      {
      mApp.showStatusAsync( "Sig byte 1 is not E." );
      return false;
      }

    b = Utility.ByteToShort( fileBytes[peOffSet + 2] );
    if( b != 0 )
      {
      mApp.showStatusAsync( "Sig byte 2 is not 0." );
      return false;
      }

    b = Utility.ByteToShort( fileBytes[peOffSet + 3] );
    if( b != 0 )
      {
      mApp.showStatusAsync( "Sig byte 3 is not 0." );
      return false;
      }

    ImageFileHeader coffHeader = new 
                             ImageFileHeader( mApp );

    if( !coffHeader.readFromBytes( fileBytes,
                                   peOffSet + 4 ))
      {
      // mApp.showStatusAsync( "" );
      return false;
      }


    mApp.showStatusAsync( "PE file is OK." );
    return true;
    }



  
  }
