import java.io.File;
import org.codehaus.plexus.archiver.zip.ZipUnArchiver;

/** Analysis entry point only: the benchmark runner never executes this class. */
public class PlexusArchiverEntry {
    public static void main(String[] args) throws Exception {
        ZipUnArchiver unarchiver = new ZipUnArchiver();
        unarchiver.setSourceFile(new File("analysis-input.zip"));
        unarchiver.setDestDirectory(new File("analysis-output"));
        unarchiver.extract();
    }
}
