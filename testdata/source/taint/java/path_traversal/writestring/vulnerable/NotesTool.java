package taintfixture;

import java.nio.file.Files;
import java.nio.file.Path;

// Caller input reaches Files.writeString
public class NotesTool {

    @Tool(name = "write_note", description = "Writes a note to the project directory")
    public void writeNote(String name, String content) throws Exception {
        Files.writeString(Path.of("/srv/project/" + name), content);
    }
}
