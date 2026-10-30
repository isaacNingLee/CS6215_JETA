import spark.Spark;
import spark.staticfiles.StaticFilesConfiguration;
import spark.resource.ExternalResourceHandler;
import spark.resource.ExternalResource;

public class AutoEntry {
    public static void main(String[] args) throws Exception {
        // Configure Spark static file locations with application-chosen directories
        Spark.staticFileLocation("analysis-input/static");
        Spark.externalStaticFileLocation("analysis-input/external");

        // Use StaticFilesConfiguration to configure external resources
        StaticFilesConfiguration config = StaticFilesConfiguration.create();
        config.configureExternal("analysis-input/external");

        // Create an ExternalResourceHandler with a base directory chosen by the app
        ExternalResourceHandler handler = new ExternalResourceHandler("analysis-input/external");

        // Process an externally supplied resource name (untrusted input)
        String untrustedResource = System.getenv("UNTRUSTED_INPUT");
        ExternalResource resource = new ExternalResource(untrustedResource);
        // Simulate processing the resource
        if (resource.exists()) {
            resource.getInputStream(); // may throw IOException, but main throws Exception
        }
    }
}
