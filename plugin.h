/*
   Patchdiff2
   Portions (c) 2020, Chris Eagle (Updates for IDA versions >= 6.7)

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

#ifndef __PLUGIN_H_
#define __PLUGIN_H_

#include "precomp.h"
#include "patchdiff.h"
#include "diff.h"
#include "options.h"
#include "actions.h"

#if IDA_SDK_VERSION < 750
struct pd_plugmod_t {
#else
struct pd_plugmod_t : public plugmod_t {
#endif

   deng_t *d_engine;
   options_t *d_opt;

   munmatch_action_handler_t munmatch_action_handler = munmatch_action_handler_t(this);
#if IDA_SDK_VERSION < 750
   const action_desc_t munmatch_action = ACTION_DESC_LITERAL(MUNMATCH_NAME, "Unmatch", &munmatch_action_handler, NULL, NULL, -1);
#else
   const action_desc_t munmatch_action = ACTION_DESC_LITERAL_PLUGMOD(MUNMATCH_NAME, "Unmatch", &munmatch_action_handler,
                                                                     this, NULL, NULL, -1);
#endif

   identical_action_handler_t identical_action_handler = identical_action_handler_t(this);
#if IDA_SDK_VERSION < 750
   const action_desc_t identical_action = ACTION_DESC_LITERAL(IDENTICAL_NAME, "Set as identical", &identical_action_handler, NULL, NULL, -1);
#else
   const action_desc_t identical_action = ACTION_DESC_LITERAL_PLUGMOD(IDENTICAL_NAME, "Set as identical", &identical_action_handler,
                                                                      this, NULL, NULL, -1);
#endif

   flagunflag_action_handler_t flagunflag_action_handler = flagunflag_action_handler_t(this);
#if IDA_SDK_VERSION < 750
   const action_desc_t flagunflag_action = ACTION_DESC_LITERAL(FLAGUNFLAG_NAME, "Flag/unflag", &flagunflag_action_handler, NULL, NULL, -1);
#else
   const action_desc_t flagunflag_action = ACTION_DESC_LITERAL_PLUGMOD(FLAGUNFLAG_NAME, "Flag/unflag", &flagunflag_action_handler,
                                                                       this, NULL, NULL, -1);
#endif

   msym_action_handler_t msym_action_handler = msym_action_handler_t(this);
#if IDA_SDK_VERSION < 750
   const action_desc_t msym_action = ACTION_DESC_LITERAL(MSYM_NAME, "Import Symbol", &msym_action_handler, NULL, NULL, -1);
#else
   const action_desc_t msym_action = ACTION_DESC_LITERAL_PLUGMOD(MSYM_NAME, "Import Symbol", &msym_action_handler,
                                                                 this, NULL, NULL, -1);
#endif

   iunmatch_action_handler_t iunmatch_action_handler = iunmatch_action_handler_t(this);
#if IDA_SDK_VERSION < 750
   const action_desc_t iunmatch_action = ACTION_DESC_LITERAL(IUNMATCH_NAME, "Unmatch", &iunmatch_action_handler, NULL, NULL, -1);
#else
   const action_desc_t iunmatch_action = ACTION_DESC_LITERAL_PLUGMOD(IUNMATCH_NAME, "Unmatch", &iunmatch_action_handler,
                                                                     this, NULL, NULL, -1);
#endif

   itom_action_handler_t itom_action_handler = itom_action_handler_t(this);
#if IDA_SDK_VERSION < 750
   const action_desc_t itom_action = ACTION_DESC_LITERAL(ITOM_NAME, "Set as matched", &itom_action_handler, NULL, NULL, -1);
#else
   const action_desc_t itom_action = ACTION_DESC_LITERAL_PLUGMOD(ITOM_NAME, "Set as matched", &itom_action_handler,
                                                                 this, NULL, NULL, -1);
#endif

   isym_action_handler_t isym_action_handler = isym_action_handler_t(this);
#if IDA_SDK_VERSION < 750
   const action_desc_t isym_action = ACTION_DESC_LITERAL(ISYM_NAME, "Import symbol", &isym_action_handler, NULL, NULL, -1);
#else
   const action_desc_t isym_action = ACTION_DESC_LITERAL_PLUGMOD(ISYM_NAME, "Import symbol", &isym_action_handler,
                                                                 this, NULL, NULL, -1);
#endif

   match_action_handler_t match_action_handler = match_action_handler_t(this);
#if IDA_SDK_VERSION < 750
   const action_desc_t match_action = ACTION_DESC_LITERAL(MATCH_NAME, "Set match", &match_action_handler, NULL, NULL, -1);
#else
   const action_desc_t match_action = ACTION_DESC_LITERAL_PLUGMOD(MATCH_NAME, "Set match", &match_action_handler,
                                                                  this, NULL, NULL, -1);
#endif

   options_action_handler_t options_action_handler = options_action_handler_t(this);
#if IDA_SDK_VERSION < 750
   const action_desc_t options_action = ACTION_DESC_LITERAL(OPTIONS_NAME, "Patchdiff2", &options_action_handler, NULL, NULL, -1);
#else
   const action_desc_t options_action = ACTION_DESC_LITERAL_PLUGMOD(OPTIONS_NAME, "Patchdiff2", &options_action_handler,
                                                                    this, NULL, NULL, -1);
#endif

   pgraph_action_handler_t pgraph_action_handler = pgraph_action_handler_t(this);
#if IDA_SDK_VERSION < 750
   const action_desc_t pgraph_action = ACTION_DESC_LITERAL(PGRAPH_NAME, "Jump to code", &pgraph_action_handler, NULL, NULL, -1);
#else
   const action_desc_t pgraph_action = ACTION_DESC_LITERAL_PLUGMOD(PGRAPH_NAME, "Jump to code", &pgraph_action_handler,
                                                                   this, NULL, NULL, -1);
#endif

   /// Invoke the plugin.
   virtual bool idaapi run(size_t arg);

   /// Virtual destructor.
   virtual ~pd_plugmod_t();

   int init();

   void term();

   void run_first_instance();

   void run_second_instance(const char * options);

};

#endif
