package resim.utils;
import generic.json.*;
import java.util.*;
import ghidra.util.Msg;
public class Json {
        public static Object getJson(String all_string){
        	
            int start_dict = all_string.indexOf('{');
            int start_list = all_string.indexOf('[');
            if(start_dict < 0 && start_list < 0){
                Msg.info(null, "Error, failed to get json from \n"+all_string);
                return null;
            }
            String jstring = null;
            if(start_dict < 0 || start_list < start_dict){
                int end = all_string.lastIndexOf(']')+1;
                jstring = all_string.substring(start_list, end);
        	
            }else if(start_list < 0 || start_dict < start_list) {
            	int end = all_string.lastIndexOf('}')+1;
                jstring = all_string.substring(start_dict, end);
            }
            //Msg.info(null, "in getJson string "+jstring);
            char[] console_char = jstring.toCharArray();
                JSONParser parser = new JSONParser();
                List<Object> objs = new ArrayList<Object>();
                List<JSONToken> tokens = new ArrayList<JSONToken>();

                JSONError r = parser.parse(console_char, tokens);
                switch(r){
                case JSMN_SUCCESS:
                        break;
                case JSMN_ERROR_NOMEM:
                        Msg.error(null,"out of memory");
                        return null;
                case JSMN_ERROR_INVAL:
                        Msg.error(null,"invalid json input");
                        return null;
                case JSMN_ERROR_PART:
                	Msg.error(null,"incomplete json input");
                        return null;
                default:
                	Msg.error(null,"json parser returned undefined status");
                        return null;
                }
                if(tokens.get(0).start == -1){
                	Msg.error(null,"invalid json input");
                        return null;
                }
                Msg.debug(null,"len of tokens is "+tokens.size());
                JSONParser parser2 = new JSONParser();
                // Ghidra json parser does not let you reset internal ndx value; so hack is to create a 2nd parser.
                Object obj = parser2.convert(console_char, tokens);
                //Msg.debug(null,"returning obj from getJson len of objs is ");
                return obj;
        }
}
