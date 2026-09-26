package notes;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class NotesTool {

    private static final String ROOT = "/srv/notes/";

    @Tool(name = "read_note", description = "Reads a note from the notes directory")
    public String readNote(String name) throws IOException {
        Path root = Path.of(ROOT).toAbsolutePath().normalize();
        Path full = root.resolve(name).normalize();
        if (!full.startsWith(root)) {
            throw new IllegalArgumentException("name escapes the notes directory");
        }
        return new String(Files.readAllBytes(full));
    }
}
