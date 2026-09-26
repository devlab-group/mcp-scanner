// Annotation-based registration: Java's decorator equivalent. The name and
// description are given as explicit annotation arguments.
package discovery;

public class EchoTool {

    @Tool(name = "java_echo", description = "Echoes text back unchanged")
    public String echo(String text) {
        return text;
    }
}
