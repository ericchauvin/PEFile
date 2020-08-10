// Copyright Eric Chauvin 2020.




// For Linux it's the ELF format.
// Executable and Linkable Format


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

  


  public void startView()
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
      return;
      }

    final int last = fileBytes.length;
    mApp.showStatusAsync( "Bytes in file: " + last );
    }



  
  }
