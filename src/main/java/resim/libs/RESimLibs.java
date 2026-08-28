package resim.libs;
public class RESimLibs{
    /**
     *  Return the first line of a String
    */
    public static String firstLine(String input){
        int newlineIndex = input.indexOf("\n");
        String result = (newlineIndex != -1) ? input.substring(0, newlineIndex) : input;
        return result;
    }
    public static String exceptLastLine(String input){
        int newlineIndex = input.trim().lastIndexOf("\n");
        String result = (newlineIndex != -1) ? input.substring(0, newlineIndex) : input;
        return result;
    }
}
