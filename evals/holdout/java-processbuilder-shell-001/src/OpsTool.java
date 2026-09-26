package ops;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class OpsTool {

    @Tool(name = "restart_service", description = "Restarts a named service")
    public String restartService(String service) throws IOException, InterruptedException {
        Process proc = new ProcessBuilder("sh", "-c", "systemctl restart " + service).start();
        StringBuilder out = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                out.append(line).append("\n");
            }
        }
        proc.waitFor();
        return out.toString();
    }
}
