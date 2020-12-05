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

#ifndef __ACTIONS_H_
#define __ACTIONS_H_

#include "precomp.h"

#if IDA_SDK_VERSION >= 670

#define MUNMATCH_NAME "patchdiff:munmatch"
#define IDENTICAL_NAME "patchdiff:identical"
#define FLAGUNFLAG_NAME "patchdiff:flagunflag"
#define MSYM_NAME "patchdiff:msym"
#define IUNMATCH_NAME "patchdiff:iunmatch"
#define ITOM_NAME "patchdiff:itom"
#define ISYM_NAME "patchdiff:isym"
#define MATCH_NAME "patchdiff:match"
#define OPTIONS_NAME "patchdiff:options"
#define PGRAPH_NAME "patchdiff:pgraph"

struct pd_plugmod_t;

struct munmatch_action_handler_t : public action_handler_t {

   pd_plugmod_t *plugin;

   munmatch_action_handler_t(pd_plugmod_t *plug) : plugin(plug) {};
   
   virtual int idaapi activate(action_activation_ctx_t *ctx);   
   virtual action_state_t idaapi update(action_update_ctx_t *ctx);
};

struct identical_action_handler_t : public action_handler_t {

   pd_plugmod_t *plugin;

   identical_action_handler_t(pd_plugmod_t *plug) : plugin(plug) {};

   virtual int idaapi activate(action_activation_ctx_t *ctx);
   virtual action_state_t idaapi update(action_update_ctx_t *ctx);
};

struct flagunflag_action_handler_t : public action_handler_t {

   pd_plugmod_t *plugin;

   flagunflag_action_handler_t(pd_plugmod_t *plug) : plugin(plug) {};
   
   virtual int idaapi activate(action_activation_ctx_t *ctx);
   virtual action_state_t idaapi update(action_update_ctx_t *ctx);
};

struct msym_action_handler_t : public action_handler_t {

   pd_plugmod_t *plugin;

   msym_action_handler_t(pd_plugmod_t *plug) : plugin(plug) {};
   
   virtual int idaapi activate(action_activation_ctx_t *ctx);
   virtual action_state_t idaapi update(action_update_ctx_t *ctx);
};

struct iunmatch_action_handler_t : public action_handler_t {

   pd_plugmod_t *plugin;

   iunmatch_action_handler_t(pd_plugmod_t *plug) : plugin(plug) {};
   
   virtual int idaapi activate(action_activation_ctx_t *ctx);
   virtual action_state_t idaapi update(action_update_ctx_t *ctx);
};

struct itom_action_handler_t : public action_handler_t {

   pd_plugmod_t *plugin;

   itom_action_handler_t(pd_plugmod_t *plug) : plugin(plug) {};
   
   virtual int idaapi activate(action_activation_ctx_t *ctx);
   virtual action_state_t idaapi update(action_update_ctx_t *ctx);
};

struct isym_action_handler_t : public action_handler_t {

   pd_plugmod_t *plugin;

   isym_action_handler_t(pd_plugmod_t *plug) : plugin(plug) {};
   
   virtual int idaapi activate(action_activation_ctx_t *ctx);
   virtual action_state_t idaapi update(action_update_ctx_t *ctx);
};

struct match_action_handler_t : public action_handler_t {

   pd_plugmod_t *plugin;

   match_action_handler_t(pd_plugmod_t *plug) : plugin(plug) {};
   
   virtual int idaapi activate(action_activation_ctx_t *ctx);
   virtual action_state_t idaapi update(action_update_ctx_t *ctx);
};

struct options_action_handler_t : public action_handler_t {

   pd_plugmod_t *plugin;

   options_action_handler_t(pd_plugmod_t *plug) : plugin(plug) {};
   
   virtual int idaapi activate(action_activation_ctx_t *);
   virtual action_state_t idaapi update(action_update_ctx_t *ctx);
};

struct pgraph_action_handler_t : public action_handler_t {

   pd_plugmod_t *plugin;

   pgraph_action_handler_t(pd_plugmod_t *plug) : plugin(plug) {};
   
   virtual int idaapi activate(action_activation_ctx_t *ctx);
   virtual action_state_t idaapi update(action_update_ctx_t *ctx);
};

#endif

#endif
