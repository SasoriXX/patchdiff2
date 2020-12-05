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
#include "plugin.h"

static bool idaapi pdiff_menu_callback(void *ud) {
   ushort option = 0, prev = 0;
   pd_plugmod_t *plugin = (pd_plugmod_t *)ud;
   options_t *opt = plugin->d_opt;

   const char format[] =
         "STARTITEM 0\n"

         "PatchDiff2 options\n\n\n"
         "<#Uses 'pipe' with the second IDA instance to speed up graph display#Settings##Keep second IDB open :C>\n"
         "<#Saves PatchDiff2 results into the current IDB#Save results to IDB :C>>\n\n"
         ;

   option |= opt->ipc ? 1 : 0;
   option |= opt->save_db ? 2 : 0;
   prev = opt->ipc;

   if (AskUsingForm_c(format, &option)) {
      opt->ipc = (option & 1) == 1;
      opt->save_db = (option & 2) == 2;

      if (prev && !option) {
         ipc_close();
      }
   }

   return true;
}

#if IDA_SDK_VERSION >= 670
//-------------------------------------------------------------------------
int idaapi options_action_handler_t::activate(action_activation_ctx_t *) {
   pdiff_menu_callback(plugin);
   return 0;
}

action_state_t idaapi options_action_handler_t::update(action_update_ctx_t *ctx) {
   return AST_ENABLE_ALWAYS;
}

#endif

options_t::options_t(pd_plugmod_t *plugin) {
   int ipc, db;

   if (system_get_pref("IPC", (void *)&ipc, SPREF_INT)) {
      this->ipc = !!ipc;
   }
   else {
      this->ipc = true;
   }

   if (system_get_pref("DB", (void *)&db, SPREF_INT)) {
      this->save_db = !!db;
   }
   else {
      this->save_db = true;
   }

#if IDA_SDK_VERSION <= 660
   add_menu_item("Options/", "PatchDiff2", NULL, SETMENU_APP, pdiff_menu_callback, this);
#elif IDA_SDK_VERSION < 750
   register_and_attach_to_menu(
          "Options/Setup", OPTIONS_NAME, "PatchDiff2",
          NULL, SETMENU_APP | SETMENU_CTXIDA,
          &options_action_handler, &PLUGIN);
#else
/*
   register_and_attach_to_menu(
          "Options/Setup", OPTIONS_NAME, "PatchDiff2",
          NULL, SETMENU_APP | SETMENU_CTXIDA,
          &options_action_handler, plugin, ADF_OT_PLUGMOD);
*/
#endif
}

options_t::~options_t() {
#if IDA_SDK_VERSION <= 660
   del_menu_item("Options/PatchDiff2");
#else
//   detach_action_from_menu("Options/Setup", OPTIONS_NAME);
//   unregister_action(OPTIONS_NAME);
#endif
}

bool options_t::options_use_ipc() {
   return ipc;
}

bool options_t::options_save_db() {
   return save_db;
}
