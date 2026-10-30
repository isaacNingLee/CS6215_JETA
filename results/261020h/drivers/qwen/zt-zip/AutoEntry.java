public class AutoEntry {
  public static void main(String[] args) throws Exception {
    // Construct and configure
    org.zeroturnaround.zip.Zips z = org.zeroturnaround.zip.Zips.get(new java.io.File("analysis-input"));
    z.destination(new java.io.File("analysis-output"))
     .charset(java.nio.charset.Charset.defaultCharset())
     .preserveTimestamps();
    
    // Process externally supplied files
    z.addFile(new java.io.File("analysis-input/file1.txt"))
     .addFile(new java.io.File("analysis-input/file2.txt"))
     .addEntry(new org.zeroturnaround.zip.ByteSource("resource.txt", "content".getBytes()))
     .process();
    
    // Use untrusted input
    String untrusted = System.getenv("UNTRUSTED_INPUT");
    byte[] data = org.zeroturnaround.zip.ZipUtil.unpackEntry(new java.io.File("analysis-input"), untrusted);
    
    // Pack and unpack operations
    org.zeroturnaround.zip.ZipUtil.pack(new java.io.File("analysis-input"), new java.io.File("analysis-output/packed.zip"));
    org.zeroturnaround.zip.ZipUtil.unpack(new java.io.File("analysis-output/packed.zip"), new java.io.File("analysis-output/unpacked"));
  }
}
