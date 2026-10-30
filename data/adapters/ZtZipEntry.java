import java.io.File;
import org.zeroturnaround.zip.ZipUtil;

/** Analysis entry point only: the benchmark runner never executes this class. */
public class ZtZipEntry {
    public static void main(String[] args) {
        ZipUtil.unpack(new File("analysis-input.zip"), new File("analysis-output"));
    }
}
