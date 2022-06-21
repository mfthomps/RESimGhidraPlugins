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
package resim.hover;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.codebrowser.hover.ListingHoverService;
import ghidra.app.plugin.core.codebrowser.hover.ScalarOperandListingHover;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;

/**
 * A plugin to show tool tip text for hovering over memory reference values in the listing.
 *
 * 
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Regiseter Operand Hover",
	description = "Pop-up display value of register operands.",
	servicesProvided = { ListingHoverService.class }
)
//@formatter:on
public class RegisterOperandListingHoverPlugin extends Plugin {

	private RegisterOperandListingHover registerHoverService;

	public RegisterOperandListingHoverPlugin(PluginTool tool) {
		super(tool);
		registerHoverService = new RegisterOperandListingHover(tool);
		registerServiceProvided(ListingHoverService.class, registerHoverService);
	}

	@Override
	public void dispose() {
		registerHoverService.dispose();
	}
}
