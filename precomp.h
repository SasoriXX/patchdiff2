/* 
   Patchdiff2
   Portions (C) 2010 - 2011 Nicolas Pouvesle
   Portions (C) 2007 - 2009 Tenable Network Security, Inc.
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License version 2 as 
   published by the Free Software Foundation.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


#pragma once

#include <stdio.h>
#include <stack>

#define NO_OBSOLETE_FUNCS

#include <ida.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <pro.h>
#include <xref.hpp>
#include <gdl.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <fpro.h>
#include <diskio.hpp>
#include <name.hpp>
#include <ua.hpp>
#include <demangle.hpp>
#include <loader.hpp>
#include <auto.hpp>
#if IDA_SDK_VERSION >= 700
#include <range.hpp>
#else
#include <area.hpp>
#endif


// The graph API spams "forcing value to bool" warnings...
#pragma warning(push)
#pragma warning(disable: 4800)
#include <graph.hpp>
#pragma warning(pop)

static_assert(IDA_SDK_VERSION >= 650, "This plugin expects a minimum IDA SDK 6.5");

#ifndef __PRECOMP_H
#define __PRECOMP_H

//help with the transition to IDA 7.0

#if IDA_SDK_VERSION >= 700

#define askbuttons_c ask_buttons
#define AskUsingForm_c ask_form
#define askfile_c ask_file
#define form_type widget_type

#define AST_DISABLE_FOR_FORM AST_DISABLE_FOR_WIDGET
#define AST_ENABLE_FOR_FORM AST_ENABLE_FOR_WIDGET
#define SETMENU_CTXIDA 0
#define procName procname
#define autoWait auto_wait

#define startEA start_ea
#define endEA end_ea

#define get_long(ea) get_dword(ea)
#define get_func_name2(n, a) get_func_name(n, a)
#define demangle_name2 demangle_name
#define get_many_bytes(e, b, s) get_bytes(b, s, e)

#define getFlags(ea) get_full_flags(ea)
#define isFlow(f) is_flow(f)
#define isCode(f) is_code(f)
#define isASCII(f) is_strlit(f)
#define isOff(f, o) is_off(f, o)

#define get_max_ascii_length get_max_strlit_length

/*

#define OpenForm_c open_form
#define FORM_TAB WOPN_TAB
#define FORM_QWIDGET 0

#define sup1st(n) supfirst(n)
#define supnxt(n, t) supnext(n, t)

#define get_flags_novalue(ea) get_flags(ea)
#define isEnum0(f) is_enum0(f)
#define isEnum1(f) is_enum1(f)
#define isStroff0(f) is_stroff0(f)
#define isStroff1(f) is_stroff1(f)
#define isOff0(f) is_off0(f)
#define isOff1(f) is_off1(f)
#define isOff(f, n) is_off(f, n)
#define isEnum(f, n) is_enum(f, n)
#define isStroff(f, n) is_stroff(f, n)

#define isStruct(f) is_struct(f)
#define isASCII(f) is_strlit(f)

#define get_member_name2 get_member_name
*/
#else
// IDASDK_VERSION < 700

#define ask_buttons askbuttons_c
#define ask_form AskUsingForm_c
#define ask_file askfile_c
#define widget_type form_type

#define AST_DISABLE_FOR_WIDGET AST_DISABLE_FOR_FORM
#define AST_ENABLE_FOR_WIDGET AST_ENABLE_FOR_FORM
#define procname procName
#define auto_wait autoWait

#define start_ea startEA
#define end_ea endEA

#define get_dword(ea) get_long(ea)

#define get_full_flags getFlags
#define is_flow(f) isFlow(f)
#define is_code(f) isCode(f)
#define is_strlit(f) isASCII(f)
#define is_off(f) isOff(f)

#define get_max_strlit_length get_max_ascii_length

/*

#define open_form OpenForm_c
#define WOPN_TAB FORM_TAB

#define supfirst(n) sup1st(n)
#define supnext(n, t) supnxt(n, t)

#define ev_add_cref add_cref
#define ev_add_dref add_dref
#define ev_del_cref del_cref
#define ev_del_dref del_dref
#define ev_auto_queue_empty auto_queue_empty
#define set_func_start func_setstart 
#define set_func_end func_setend
*/
#endif


#endif