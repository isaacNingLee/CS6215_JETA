import java.io.FileInputStream;
import net.sf.mpxj.common.InputStreamHelper;

/** Analysis entry only; never executed by the Tai-e benchmark. */
public class MpxjEntry {
    public static void main(String[] args) throws Exception {
        InputStreamHelper.writeZipStreamToTempDir(new FileInputStream("analysis-input.zip"));
    }
}
