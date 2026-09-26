package notes;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class NotesTool {

    private static final String ROOT = "/srv/notes/";

    @Tool(name = "read_note", description = "Reads a note from the notes directory")
    public String readNote(String name) throws IOException {
        String full = ROOT + name;
        return new String(Files.readAllBytes(Path.of(full)));
    }
}
