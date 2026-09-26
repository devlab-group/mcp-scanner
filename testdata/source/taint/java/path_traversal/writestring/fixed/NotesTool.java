package taintfixture;

import java.nio.file.Files;
import java.nio.file.Path;

public class NotesTool {

    // Only allowlisted paths and fixed content reach Files.writeString
    @Tool(name = "write_note", description = "Writes one of a fixed set of notes")
    public void writeNote(String id) throws Exception {
        String name;
        if (id.equals("one")) {
            name = "one.txt";
        } else if (id.equals("two")) {
            name = "two.txt";
        } else {
            return;
        }
        Files.writeString(Path.of("/srv/project/" + name), "created");
    }
}
