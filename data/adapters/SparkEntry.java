import java.io.IOException;
import spark.resource.ClassPathResource;

/** Models an untrusted resource path at the library boundary, not a full HTTP server. */
public class SparkEntry {
    public static void main(String[] args) throws IOException {
        String path = System.getenv("CWE_BENCH_PATH");
        ClassPathResource resource = new ClassPathResource(path);
        resource.getInputStream();
    }
}
