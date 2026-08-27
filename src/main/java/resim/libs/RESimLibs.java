package resim.libs;
public class RESimLibs{
    public static String firstLine(String input){
        int newlineIndex = input.indexOf("\n");
        String result = (newlineIndex != -1) ? input.substring(0, newlineIndex) : input;
        return result;
    }
}
