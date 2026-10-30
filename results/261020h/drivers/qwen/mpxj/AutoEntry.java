public class AutoEntry {
    public static void main(String[] args) throws Exception {
        // Create reader instances
        net.sf.mpxj.mpp.MPPReader mppReader = new net.sf.mpxj.mpp.MPPReader();
        net.sf.mpxj.mpx.MPXReader mpxReader = new net.sf.mpxj.mpx.MPXReader();

        // Configure readers
        mppReader.setPreserveNoteFormatting(true);
        mppReader.setUseRawTimephasedData(false);
        mppReader.setReadPresentationData(true);
        mppReader.setReadPropertiesOnly(false);
        mppReader.setRespectPasswordProtection(true);

        mpxReader.setLocale(java.util.Locale.getDefault());
        mpxReader.setIgnoreTextModels(false);

        // Process input files
        java.io.File inputFile = new java.io.File("analysis-input");
        java.io.File outputFile = new java.io.File("analysis-output");

        // Ensure output directory exists
        net.sf.mpxj.common.FileHelper.mkdirs(outputFile.getParentFile());

        // Read project files
        net.sf.mpxj.ProjectFile project = mppReader.read(inputFile);
        java.util.List<net.sf.mpxj.ProjectFile> projects = mpxReader.readAll(inputFile);

        // Handle untrusted input
        String untrustedResource = System.getenv("UNTRUSTED_INPUT");
        if (untrustedResource != null) {
            // Process untrusted resource name
            java.io.File tempFile = new java.io.File(untrustedResource);
            if (tempFile.exists()) {
                net.sf.mpxj.ProjectFile untrustedProject = mppReader.read(tempFile);
                // Further processing...
            }
        }
    }
}
