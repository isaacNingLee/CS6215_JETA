import net.lingala.zip4j.core.ZipFile;
import net.lingala.zip4j.exception.ZipException;

/** Entry point for static analysis; the runner does not execute this program. */
public class Zip4jEntry {
    public static void main(String[] args) throws ZipException {
        ZipFile archive = new ZipFile("analysis-input.zip");
        archive.setRunInThread(false);
        archive.extractAll("analysis-output");
    }
}
