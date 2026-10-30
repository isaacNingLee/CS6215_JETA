import java.io.File;
import org.codehaus.plexus.util.DirectoryScanner;
import org.codehaus.plexus.util.DirectoryWalker;
import org.codehaus.plexus.util.Expand;
import org.codehaus.plexus.util.FileUtils;
import org.codehaus.plexus.util.NioFiles;

public class AutoEntry {
    public static void main(String[] args) throws Exception {
        // 1. DirectoryScanner: scan a directory for files
        DirectoryScanner scanner = new DirectoryScanner();
        scanner.setBasedir("analysis-input");
        scanner.setFollowSymlinks(true);
        scanner.scan();
        String[] includedFiles = scanner.getIncludedFiles();

        // 2. DirectoryWalker: walk a directory with includes/excludes
        DirectoryWalker walker = new DirectoryWalker();
        walker.setBaseDir(new File("analysis-input"));
        walker.addInclude("**/*.txt");
        walker.addExclude("**/exclude.txt");
        walker.addSCMExcludes();
        walker.setDebugMode(false);
        walker.scan();

        // 3. Expand: extract an archive
        Expand expand = new Expand();
        expand.setSrc(new File("analysis-input/archive.zip"));
        expand.setDest(new File("analysis-output/expanded"));
        expand.setOverwrite(true);
        expand.execute();

        // 4. FileUtils: copy a file to a directory
        FileUtils.copyFileToDirectory("analysis-input/source.txt", "analysis-output");

        // 5. FileUtils: read a file whose name comes from untrusted input
        String untrustedFileName = System.getenv("UNTRUSTED_INPUT");
        String content = FileUtils.fileRead(untrustedFileName);

        // 6. FileUtils: write content to an output file
        FileUtils.fileWrite("analysis-output/result.txt", content);

        // 7. FileUtils: delete a directory
        FileUtils.deleteDirectory("analysis-output/temp");

        // 8. NioFiles: check symbolic link, copy, and get last modified
        File link = new File("analysis-input/link");
        if (NioFiles.isSymbolicLink(link)) {
            File target = NioFiles.readSymbolicLink(link);
            NioFiles.copy(target, new File("analysis-output/copied_link_target"));
        }
        long lastModified = NioFiles.getLastModified(new File("analysis-input/source.txt"));
    }
}
