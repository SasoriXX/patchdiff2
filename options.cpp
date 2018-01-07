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

#include "options.h"
#include "system.h"

static options_t *opts;

static bool idaapi pdiff_menu_callback(void *ud) {
   ushort option = 0, prev = 0;
   options_t *opt = (options_t *)ud;

   const char format[] =
         "STARTITEM 0\n"

         "PatchDiff2 options\n"
         "<##Settings #>\n"
         "<#Uses 'pipe' with the second IDA instance to speed up graph display#Keep second IDB open :C>\n"
         "<#Saves PatchDiff2 results into the current IDB#Save results to IDB :C>>\n\n"
         ;

   option |= opt->ipc ? 1 : 0;
   option |= opt->save_db ? 2 : 0;
   prev = opt->ipc;

   if (AskUsingForm_c(format, &option)) {
      opt->ipc = !!(option & 1);
      opt->save_db = !!(option & 2);

      if (prev && !option) {
         ipc_close();
      }
   }

   return true;
}

#if IDA_SDK_VERSION >= 670
#define OPTIONS_NAME "patchdiff:options"
//-------------------------------------------------------------------------
struct options_action_handler_t : public action_handler_t {
   virtual int idaapi activate(action_activation_ctx_t *) {
      pdiff_menu_callback(opts);
      return 0;
   }

   virtual action_state_t idaapi update(action_update_ctx_t *ctx) {
      return AST_ENABLE_ALWAYS;
   }
};
static options_action_handler_t options_action_handler;
//static const action_desc_t options_action = ACTION_DESC_LITERAL(OPTIONS_NAME, "Patchdiff2", &options_action_handler, NULL, NULL, -1);
#endif

options_t *options_init() {
   int ipc, db;

   opts = (options_t *)qalloc(sizeof(*opts));
   if (!opts) {
      return NULL;
   }

   if (system_get_pref("IPC", (void *)&ipc, SPREF_INT)) {
      opts->ipc = !!ipc;
   }
   else {
      opts->ipc = true;
   }

   if (system_get_pref("DB", (void *)&db, SPREF_INT)) {
      opts->save_db = !!db;
   }
   else {
      opts->save_db = true;
   }

#if IDA_SDK_VERSION <= 660
   add_menu_item("Options/", "PatchDiff2", NULL, SETMENU_APP, pdiff_menu_callback, opts);
#else
  register_and_attach_to_menu(
          "Options/Setup", OPTIONS_NAME, "PatchDiff2",
          NULL, SETMENU_APP | SETMENU_CTXIDA,
          &options_action_handler, &PLUGIN);
#endif
  
   return opts;
}


void options_close(options_t *opt) {
#if IDA_SDK_VERSION <= 660
   del_menu_item("Options/PatchDiff2");
#else
   unregister_action(OPTIONS_NAME);
#endif
   if (opts) qfree(opts);
   opts = NULL;
}


bool options_use_ipc(options_t *opt) {
   return opt->ipc;
}


bool options_save_db(options_t *opt) {
   return opt->save_db;
}
