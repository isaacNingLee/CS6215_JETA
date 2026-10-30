public class AutoEntry {
    public static void main(String[] args) throws Exception {
        // Simulate a realistic workflow for static analysis
        org.codehaus.plexus.archiver.manager.ArchiverManager archiverManager = 
            new org.codehaus.plexus.archiver.manager.DefaultArchiverManager();
        
        // Configure and create an archive
        org.codehaus.plexus.archiver.Archiver archiver = 
            archiverManager.getArchiver("jar");
        archiver.setDestFile(new java.io.File("analysis-output.jar"));
        archiver.addDirectory(new java.io.File("analysis-input"));
        archiver.createArchive();
        
        // Configure and extract an archive
        org.codehaus.plexus.archiver.UnArchiver unarchiver = 
            archiverManager.getUnArchiver("zip");
        unarchiver.setSourceFile(new java.io.File("analysis-input.zip"));
        unarchiver.setDestDirectory(new java.io.File("analysis-output"));
        unarchiver.extract();
        
        // Process resource collections
        org.codehaus.plexus.components.io.resources.PlexusIoResourceCollection resourceCollection = 
            archiverManager.getResourceCollection(System.getenv("UNTRUSTED_INPUT"));
        archiver.addResources(resourceCollection);
        
        // Use a specific unarchiver with additional configuration
        org.codehaus.plexus.archiver.zip.ZipUnArchiver zipUnarchiver = 
            new org.codehaus.plexus.archiver.zip.ZipUnArchiver();
        zipUnarchiver.setSourceFile(new java.io.File("analysis-input.zip"));
        zipUnarchiver.setDestDirectory(new java.io.File("analysis-output"));
        zipUnarchiver.extract();
        
        // Use tar unarchiver with compression
        org.codehaus.plexus.archiver.tar.TarUnArchiver tarUnarchiver = 
            new org.codehaus.plexus.archiver.tar.TarUnArchiver();
        tarUnarchiver.setSourceFile(new java.io.File("analysis-input.tar"));
        tarUnarchiver.setDestDirectory(new java.io.File("analysis-output"));
        tarUnarchiver.setCompression(org.codehaus.plexus.archiver.tar.TarUnArchiver.UntarCompressionMethod.GZIP);
        tarUnarchiver.extract();
    }
}
