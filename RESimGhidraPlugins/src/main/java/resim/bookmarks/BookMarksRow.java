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
package resim.bookmarks;


import ghidra.program.model.address.Address;

public class BookMarksRow {


	private final DebuggerBookMarksProvider provider;

	final String msg;
	private int index;
	Address pc;
	long cycle;
	long pid;
	String mark;
	String fun;
	String instruct;

	public BookMarksRow(DebuggerBookMarksProvider provider, int index, String mark, Address pc, long cycle, long pid, String instruct, String fun, String msg) {
		this.provider = provider;
		this.msg = msg;
		this.pc = pc;
		this.fun = fun;
		this.index = index;
		this.mark = mark;
		this.cycle = cycle;
		this.pid = pid;
		this.instruct = instruct;

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
	public String getMark() {
		return mark;
	}
	public String getInstruct() {
		return instruct;
	}	
	public String getFunction() {
		return fun;
	}
	public long getCycle() {
		return cycle;
	}	
	public long getPid() {
		return pid;
	}



	protected void update() {

	}
}
