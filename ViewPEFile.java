// Copyright Eric Chauvin 2020.



// Portable Executable File
// Common Object File Format (COFF)

// For Linux it's the ELF format.
// Executable and Linkable Format

// Integer.toHexString( i )


// A section is "the basic unit of code or data
// within a PE or COFF file."
// Sections can have different levels of memory
// protection once they get mapped in to memory.
// Like executable code is mapped to
// an area that is read-only/executable.
// And a data area is marked so it's not executable.


// A PE file starts with an old MS-DOS structure at
// the beginning of the file.  It is defined in
// ImageDosHeader.java.

// winnt.h has struct definitions used for the PEFile.

// After that is the real-mode DOS stub program
// that just says something like "This program
// requires Windows..." if you actually tried to
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

    long peOffSet = dosHeader.getOffsetOfPEFileHeader();

    return true;
    }



  
  }
