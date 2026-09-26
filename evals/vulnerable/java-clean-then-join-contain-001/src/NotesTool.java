package notes;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class NotesTool {

    private static final String ROOT = "/srv/notes/";

    @Tool(name = "read_note", description = "Reads a note from the notes directory")
    public String readNote(String name) throws IOException {
        Path requested = Paths.get(name);
        Path clean = requested.normalize();
        String full = ROOT + clean;
        if (!full.startsWith(ROOT)) {
            throw new IllegalArgumentException("name escapes the notes directory");
        }
        return new String(Files.readAllBytes(Path.of(full)));
    }
}
