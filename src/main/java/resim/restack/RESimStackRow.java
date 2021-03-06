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
package resim.restack;


import ghidra.program.model.address.Address;

public class RESimStackRow {


    private final RESimStackProvider provider;

    final String instruct;
    final String fun;
    final String fname;
    private int index;
    Address pc;

    public RESimStackRow(RESimStackProvider provider, int index, String instruct, String fun, String fname, Address pc) {
        this.provider = provider;
        this.instruct = instruct;
        this.fun = fun;
        this.fname = fname;
        this.index = index;
        this.pc = pc;
    }



    public int getIndex() {
        return index;
    }

    public Address getProgramCounter() {
        return pc;
    }

    public String getInstruct() {
        return instruct;
    }
    public String getFun() {
        return fun;
    }
    public String getFname() {
        return fname;
    }


    protected void update() {

    }
}
