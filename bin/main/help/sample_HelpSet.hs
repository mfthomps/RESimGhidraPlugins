<?xml version='1.0' encoding='ISO-8859-1' ?>
<!DOCTYPE helpset PUBLIC "-//Sun Microsystems Inc.//DTD JavaHelp HelpSet Version 2.0//EN" "http://java.sun.com/products/javahelp/helpset_2_0.dtd">

<!-- HelpSet auto-generated on Tue May 24 14:09:34 PDT 2022 -->
<helpset version="2.0">
	<title>sample HelpSet</title>
	<maps>
		<mapref location="sample_map.xml" />
	</maps>
	<view mergetype="javax.help.UniteAppendMerge">
		<name>TOC</name>
		<label>Ghidra Table of Contents</label>
		<type>docking.help.CustomTOCView</type>
		<data>sample_TOC.xml</data>
	</view>
	<view>
		<name>Search</name>
		<label>Search for Keywords</label>
		<type>docking.help.CustomSearchView</type>
		<data engine="com.sun.java.help.search.DefaultSearchEngine">sample_JavaHelpSearch</data>
	</view>
	<view>
		<name>Favorites</name>
		<label>Ghidra Favorites</label>
		<type>docking.help.CustomFavoritesView</type>
	</view>
</helpset>
