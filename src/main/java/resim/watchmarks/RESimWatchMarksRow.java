/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package resim.watchmarks;


import ghidra.program.model.address.Address;

public class RESimWatchMarksRow {


    private final RESimWatchMarksProvider provider;

    final String msg;
    private int index;
    Address pc;
    long cycle;
    String tid;
    
    public RESimWatchMarksRow(RESimWatchMarksProvider provider, int index, String msg, Address pc, long cycle, String tid) {
        this.provider = provider;
        this.msg = msg;
        this.index = index;
        this.pc = pc;
        this.cycle = cycle;
        this.tid = tid;
    }



    public int getIndex() {
        return index;
    }

    public Address getProgramCounter() {
        return pc;
    }

    public String getMsg() {
        return msg;
    }
    public String getTid() {
        return tid;
    }
    public long getCycle() {
        return cycle;
    }


    protected void update() {

    }
}
