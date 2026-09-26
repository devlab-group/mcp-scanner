package taintfixture;

import java.nio.file.Files;
import java.nio.file.Path;

public class NotesTool {

    // The caller's label never reaches the fixed path
    @Tool(name = "status", description = "Reports status with a caller-supplied label")
    public String status(String label) throws Exception {
        Files.writeString(Path.of("/srv/project/status.txt"), "ok");
        return label;
    }
}
