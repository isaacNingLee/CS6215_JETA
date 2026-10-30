import java.io.File;
import org.codehaus.plexus.util.Expand;

/** Analysis entry point only: the benchmark runner never executes this class. */
public class PlexusUtilsEntry {
    public static void main(String[] args) throws Exception {
        Expand expand = new Expand();
        expand.setSrc(new File("analysis-input.zip"));
        expand.setDest(new File("analysis-output"));
        expand.execute();
    }
}
