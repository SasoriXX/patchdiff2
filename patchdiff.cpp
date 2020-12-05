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

#include "precomp.h"

#include "sig.h"
#include "parser.h"
#include "patchdiff.h"
#include "diff.h"
#include "backup.h"
#include "display.h"
#include "options.h"
#include "system.h"
#include "actions.h"
#include "plugin.h"

extern plugin_t PLUGIN;
extern char *exename;

cpu_t patchdiff_cpu;

void pd_plugmod_t::term(void) {
   unhook_from_notification_point(HT_UI, ui_callback);

   if (d_engine) {
      if (d_opt->options_save_db()) {
         backup_save_results(d_engine);
      }
      delete d_engine;
   }

   ipc_close();
   delete d_opt;
   d_opt = NULL;
}

int pd_plugmod_t::init() {
   char procname[256];
   bool is64;
#if IDA_SDK_VERSION < 730
   qstrncpy(procname, inf.procname, sizeof(procname));
   is64 = inf.is_64bit();
#else
   inf_get_procname(procname, sizeof(procname));
   is64 = inf_is_64bit();
#endif
   if (!strcmp(procname, "metapc")) {
      if (is64) {
         patchdiff_cpu = CPU_X8664;
      }
      else {
         patchdiff_cpu = CPU_X8632;
      }
   }
   else if (!strcmp(procname, "PPC")) {
      patchdiff_cpu = CPU_PPC;
   }
   else {
      patchdiff_cpu = CPU_DEFAULT;
   }

   d_engine = NULL;

   // handle IPC
   ipc_init(NULL, 0, 0);

   d_opt = new options_t(this);
   if (!d_opt) {
      return 0;
   }

   return 1;
}

void pd_plugmod_t::run_first_instance() {
   char *file;
   slist_t *sl1 = NULL;
   slist_t *sl2 = NULL;
   int ret;

   msg ("\n---------------------------------------------------\n"
      "PatchDiff Plugin v2.0.12\n"
      "Copyright (c) 2010-2011, Nicolas Pouvesle\n"
      "Copyright (C) 2007-2009, Tenable Network Security, Inc\n"
      "Copyright (c) 2018, Chris Eagle (Updates for IDA versions >= 6.7)\n"
      "---------------------------------------------------\n\n");

   ret = backup_load_results(&d_engine, d_opt);
   if (ret == 1) {
      display_results(this);
      return;
   }
   else if (ret == -1) {
      return;
   }

   show_wait_box("PatchDiff is in progress ...");

   msg("Scanning for functions ...\n");

   msg("parsing second idb...\n");
   sl2 = parse_second_idb(&file, d_opt);
   if (!sl2) {
      msg("Error: IDB2 parsing cancelled or failed.\n");
      hide_wait_box();
      return;
   }

   msg("parsing first idb...\n");
   sl1 = parse_idb();
   if (!sl1) {
      msg("Error: IDB1 parsing failed.\n");
      sl2->free_sigs();
      delete sl2;
      hide_wait_box();
      return;
   }

   msg("diffing...\n");
   generate_diff(&d_engine, sl1, sl2, file, d_opt);
   if (d_engine) {
      d_engine->display(this, sl1, sl2, file);
   }

   msg("done!\n");
   hide_wait_box();

   delete sl1;
   delete sl2;
}

void pd_plugmod_t::run_second_instance(const char * options) {
   slist_t * sl;
   char file[QMAXPATH];
   ea_t ea = BADADDR;
   unsigned char opt = 0;
   long id;
   unsigned int v;
   bool cont;
   char tmp[QMAXPATH*4];

   qsscanf(options, "%lu:%a:%u:%s", &id, &ea, &v, file);
   opt = (unsigned char)v;

   if (id) {
      if (ipc_init(file, 2, id)) {
         do {
            cont = ipc_recv_cmd(tmp, sizeof(tmp));
            if (cont) {
               run_second_instance(tmp);
               ipc_recv_cmd_end();
            }
         } while(cont);
      }
   }
   else {
      if (ea == BADADDR) {
         sl = parse_idb();
      }
      else {
         sl = parse_fct(ea, opt);
      }

      if (!sl) {
         return;
      }

      sl->save(file);

      sl->free_sigs();
      delete sl;
   }
}

bool pd_plugmod_t::run(size_t arg) {
   const char * options = NULL;

   autoWait();

   options = get_plugin_options("patchdiff2");

   if (options == NULL) {
      run_first_instance();
   }
   else {
      run_second_instance(options);
   }

   return true;
}

#if IDA_SDK_VERSION < 750

pd_plugmod_t ctx;

//make life easier in a post 7.5 world
#define PLUGIN_MULTI 0

static int idaapi pd_init(void) {
   if (ctx.init()) {
      return PLUGIN_KEEP;
   }
   else {
      return PLUGIN_SKIP;
   }
}

static void idaapi pd_term(void) {
   ctx.term();
}

#if IDA_SDK_VERSION < 700
static void idaapi pd_run(int arg) {
#else
static bool idaapi pd_run(size_t arg) {
#endif
   ctx.run(arg);
#if IDA_SDK_VERSION >= 700
   return true;
#endif
}

#else // >= 750

#define pd_run NULL
#define pd_term NULL

plugmod_t *idaapi pd_init(void) {
   pd_plugmod_t *pd_plugmod = new pd_plugmod_t();
   if (pd_plugmod->init()) {
      return pd_plugmod;
   }
   else {
      delete pd_plugmod;
      return NULL;
   }
}

pd_plugmod_t::~pd_plugmod_t(void) {
#if IDA_SDK_VERSION >= 750
   // this is called via an alternate path prior to 7.5
   term();
#endif
}

#endif

char comment[] = "w00t";
char help[] = "A Binary Difference Analysis plugin module\n";
char wanted_name[] = "PatchDiff2";
char wanted_hotkey[] = "Ctrl-8";

plugin_t PLUGIN = {
   IDP_INTERFACE_VERSION,
   PLUGIN_MOD | PLUGIN_MULTI,
   pd_init,
   pd_term,
   pd_run,
   comment,
   help,
   wanted_name,
   wanted_hotkey
};

