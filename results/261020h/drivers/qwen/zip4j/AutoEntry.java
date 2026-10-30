public class AutoEntry {
    public static void main(String[] args) throws Exception {
        // Construct and configure ZipFile
        net.lingala.zip4j.core.ZipFile zipFile = new net.lingala.zip4j.core.ZipFile("analysis-input.zip");
        
        // Configure with parameters
        net.lingala.zip4j.model.ZipParameters parameters = new net.lingala.zip4j.model.ZipParameters();
        parameters.setIncludeRootFolder(false);
        
        // Create zip file from folder
        zipFile.createZipFileFromFolder("analysis-input", parameters, true, 0);
        
        // Add files to zip
        java.util.ArrayList<java.io.File> files = new java.util.ArrayList<>();
        files.add(new java.io.File("analysis-input/file1.txt"));
        zipFile.addFiles(files, parameters);
        
        // Add a single file
        zipFile.addFile(new java.io.File("analysis-input/file2.txt"), parameters);
        
        // Add a folder
        zipFile.addFolder("analysis-input/subdir", parameters);
        
        // Extract all files
        zipFile.extractAll("analysis-output");
        
        // Extract specific file
        net.lingala.zip4j.model.FileHeader header = zipFile.getFileHeader("file1.txt");
        if (header != null) {
            zipFile.extractFile(header, "analysis-output");
        }
        
        // Extract with unzipping parameters
        net.lingala.zip4j.model.UnzipParameters unzipParams = new net.lingala.zip4j.model.UnzipParameters();
        zipFile.extractFile("file2.txt", "analysis-output", unzipParams);
        
        // Process untrusted input
        String untrustedResource = System.getenv("UNTRUSTED_INPUT");
        if (untrustedResource != null) {
            zipFile.extractFile(untrustedResource, "analysis-output", unzipParams);
        }
        
        // Get file headers
        java.util.List headers = zipFile.getFileHeaders();
        
        // Check if encrypted
        boolean isEncrypted = zipFile.isEncrypted();
        
        // Set password if needed
        if (isEncrypted) {
            zipFile.setPassword("password");
        }
        
        // Set comment
        zipFile.setComment("Analysis completed");
        
        // Get comment
        String comment = zipFile.getComment();
        
        // Validate zip file
        boolean isValid = zipFile.isValidZipFile();
        
        // Merge split files if needed
        if (zipFile.isSplitArchive()) {
            zipFile.mergeSplitFiles(new java.io.File("analysis-input.zip"));
        }
    }
}
