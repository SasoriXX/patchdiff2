/* 
   Patchdiff2
   Portions (C) 2010 - 2011 Nicolas Pouvesle
   Portions (C) 2007 - 2009 Tenable Network Security, Inc.
   Portions (c) 2018, Chris Eagle (Updates for IDA versions >= 6.7)
   
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

#include "diff.h"
#include "display.h"
#include "os.h"
#include "parser.h"
#include "pgraph.h"
#include "options.h"
#include "system.h"
#include "actions.h"
#include "plugin.h"

static uint32 idaapi sizer_dlist(slist_t *sl) {
   if (sl) {
      return sl->num;
   }
   return 0;
}

static uint32 idaapi sizer_match(void *obj) {
   deng_t *d = (deng_t *)obj;

   return sizer_dlist(d ? d->mlist : NULL);
}

static uint32 idaapi sizer_identical(void *obj) {
   deng_t *d = (deng_t *)obj;

   return sizer_dlist(d ? d->ilist : NULL);
}

static uint32 idaapi sizer_unmatch(void *obj) {
   deng_t *d = (deng_t *)obj;

   return sizer_dlist(d ? d->ulist : NULL);
}

static void idaapi close_window(void *obj) {
   deng_t *d = (deng_t *)obj;

   d->wnum--;
   if (!d->wnum) {
      ipc_close();
   }
   return;
}

/*------------------------------------------------*/
/* function : ui_access_sig                       */
/* description: Compensates for the zero index    */
/*         indicating the header row and performs */
/*         bounds checking in debug               */
/*------------------------------------------------*/

static sig_t *ui_access_sig(slist_t *sl, uint32 n) {
#ifdef _DEBUG
   if (!sl || n == 0 || n > sl->num) {
      error("ui attempted to access siglist out-of-bounds: %p %x\n", sl, n - 1);
      return NULL;
   }
#endif
   return sl->sigs[n - 1];
}

#if IDA_SDK_VERSION <= 695
static void idaapi desc_dlist(slist_t *sl, uint32 n, char *const *arrptr) {
   int i;

   /* header */
   if (n == 0) {
      for (i = 0; i < qnumber (header_match); i++) {
         qsnprintf(arrptr[i], MAXSTR, "%s", header_match[i]);
      }
   }
   else {
      sig_t *sig = ui_access_sig(sl, n);
      qsnprintf(arrptr[0], MAXSTR, "%u", sig->mtype);
      qsnprintf(arrptr[1], MAXSTR, "%s", sig->name.c_str());
      qsnprintf(arrptr[2], MAXSTR, "%s", sig->msig->name.c_str());
      qsnprintf(arrptr[3], MAXSTR, "%a", sig->startEA);
      qsnprintf(arrptr[4], MAXSTR, "%a", sig->msig->startEA);
      qsnprintf(arrptr[5], MAXSTR, "%c", sig->id_crc ? '+' : '-');
      qsnprintf(arrptr[6], MAXSTR, "%lx", sig->crc_hash);
      qsnprintf(arrptr[7], MAXSTR, "%lx", sig->msig->crc_hash);
   }
}

/*------------------------------------------------*/
/* function : desc_match                          */
/* description: Fills matched list                */
/*------------------------------------------------*/

static void idaapi desc_match(void *obj, uint32 n, char *const *arrptr) {
   deng_t *d = (deng_t *)obj;

   desc_dlist(d ? d->mlist : NULL, n, arrptr);
}

/*------------------------------------------------*/
/* function : desc_identical                      */
/* description: Fills identical list              */
/*------------------------------------------------*/

static void idaapi desc_identical(void *obj, uint32 n, char *const *arrptr) {
   deng_t *d = (deng_t *)obj;

   desc_dlist(d ? d->ilist : NULL, n, arrptr);
}

/*------------------------------------------------*/
/* function : desc_unmatch                        */
/* description: Fills unmatched list              */
/*------------------------------------------------*/

static void idaapi desc_unmatch(void *obj, uint32 n, char *const *arrptr) {
   int i;

   /* header */
   if (n == 0) {
      for (i = 0; i < qnumber (header_unmatch); i++) {
         qsnprintf(arrptr[i], MAXSTR, "%s", header_unmatch[i]);
      }
   }
   else {
      sig_t *sig = ui_access_sig(((deng_t *)obj)->ulist, n);
      qsnprintf(arrptr[0], MAXSTR, "%u", sig->nfile);
      qsnprintf(arrptr[1], MAXSTR, "%s", sig->name.c_str());
      qsnprintf(arrptr[2], MAXSTR, "%a", sig->startEA);
      qsnprintf(arrptr[3], MAXSTR, "%.8lX", sig->sig);
      qsnprintf(arrptr[4], MAXSTR, "%.8lX", sig->hash);
      qsnprintf(arrptr[5], MAXSTR, "%.8lX", sig->crc_hash);
   }
}
#endif

static void idaapi enter_list(slist_t *sl, uint32 n) {
   jumpto(ui_access_sig(sl, n)->startEA);
   os_copy_to_clipboard(NULL);
}

/*------------------------------------------------*/
/* function : enter_match                         */
/* description: Jumps to code for element n in    */
/*              matched list                      */
/*------------------------------------------------*/

static void idaapi enter_match(void *obj, uint32 n) {
   enter_list(((deng_t *)obj)->mlist, n);
}

/*------------------------------------------------*/
/* function : enter_identical                         */
/* description: Jumps to code for element n in    */
/*              identical list                    */
/*------------------------------------------------*/

static void idaapi enter_identical(void *obj, uint32 n) {
   enter_list(((deng_t *)obj)->ilist, n);
}

/*------------------------------------------------*/
/* function : enter_unmatch                         */
/* description: Jumps to code for element n in    */
/*              unmatched list                    */
/*------------------------------------------------*/

static void idaapi enter_unmatch(void *obj, uint32 n) {
   sig_t *sig = ui_access_sig(((deng_t *)obj)->ulist, n);

   if (sig->nfile == 1) {
      jumpto(sig->startEA);
   }
   else {
      os_copy_to_clipboard(NULL);
   }
}

static uint32 idaapi graph_list(slist_t *sl, uint32 n, options_t *opt) {
   slist_t *sl1 = NULL;
   slist_t *sl2 = NULL;

   msg ("parsing second function...\n");
   sl2 = parse_second_fct(ui_access_sig(sl, n)->msig->startEA, sl->file, opt);
   if (!sl2) {
      msg("Error: FCT2 parsing failed.\n");
      return 0;
   }

   msg ("parsing first function...\n");
#if IDA_SDK_VERSION < 700
   sl1 = parse_fct(ui_access_sig(sl, n)->startEA, dto.graph.s_showpref);
#else
   // dto went away in 7.0, not clear how to replicate above
   sl1 = parse_fct(ui_access_sig(sl, n)->startEA, 0);
#endif
   if (!sl1) {
      msg("Error: FCT1 parsing failed.\n");
      sl2->free_sigs();
      delete sl2;
      return 0;
   }

   sl1->sigs[0]->nfile = 1;
   sl2->sigs[0]->nfile = 2;

   msg ("diffing functions...\n");
   generate_diff(NULL, sl1, sl2, NULL, NULL);

   pgraph_display(sl1, sl2);

   msg ("done!\n");
   return 1;
}

/*------------------------------------------------*/
/* function : graph_match                         */
/* description: Draws graph from element n in     */
/*              matched list                      */
/*------------------------------------------------*/

static void idaapi graph_match(void *obj, uint32 n) {
   slist_t *sl = ((deng_t *)obj)->mlist;
   options_t *opt = ((deng_t *)obj)->opt;

   graph_list(sl, n, opt);

   return;
}

/*------------------------------------------------*/
/* function : graph_identical                     */
/* description: Draws graph from element n in     */
/*              identical list                    */
/*------------------------------------------------*/

static void idaapi graph_identical(void *obj, uint32 n) {
   slist_t *sl = ((deng_t *)obj)->ilist;
   options_t *opt = ((deng_t *)obj)->opt;

   graph_list(sl, n, opt);

   return;
}

/*------------------------------------------------*/
/* function : graph_unmatch                       */
/* description: Draws graph from element n in     */
/*              unmatched list                    */
/*------------------------------------------------*/

static void idaapi graph_unmatch(void *obj, uint32 n) {
   slist_t *sl = NULL;
   slist_t *tmp = ((deng_t *)obj)->ulist;

   if (ui_access_sig(tmp, n)->nfile == 2) {
      msg ("parsing second function...\n");
      sl = parse_second_fct(ui_access_sig(tmp, n)->startEA, tmp->file, ((deng_t *)obj)->opt);
      if (!sl) {
         msg("Error: FCT2 parsing failed.\n");
         return;
      }

      sl->sigs[0]->nfile = 2;
   }
   else {
      msg ("parsing first function...\n");
#if IDA_SDK_VERSION < 700
      sl = parse_fct(ui_access_sig(tmp, n)->startEA, dto.graph.s_showpref);
#else
      // dto went away in 7.0, not clear how to replicate above
      sl = parse_fct(ui_access_sig(tmp, n)->startEA, 0);
#endif
      if (!sl) {
         msg("Error: FCT1 parsing failed.\n");
         return;
      }

      sl->sigs[0]->nfile = 1;
   }

   pgraph_display_one(sl);

   msg ("done!\n");
   return;
}

static uint32 idaapi res_unmatch(deng_t *d, uint32 n, int type) {
   slist_t *sl;

   if (type == 0) {
      sl = d->ilist;
   }
   else {
      sl = d->mlist;
   }

   sig_t *sig = ui_access_sig(sl, n);
   
   sig->nfile = 1;
   sig->msig->nfile = 2;

   d->ulist->add(sig);
   d->ulist->add(sig->msig);

   sig->msig->msig = NULL;
   sig->msig = NULL;

   sl->remove(n - 1);

   refresh_chooser(title_unmatch);

   return 1;
}

/*------------------------------------------------*/
/* function : res_iunmatch                        */
/* description: Unmatches element n from identical*/
/*              list                              */
/*------------------------------------------------*/

static uint32 idaapi res_iunmatch(void *obj, uint32 n) {
   return res_unmatch((deng_t *)obj, n, 0);
}

/*------------------------------------------------*/
/* function : res_munmatch                        */
/* description: Unmatches element n from matched  */
/*              list                              */
/*------------------------------------------------*/

static uint32 idaapi res_munmatch(void *obj, uint32 n) {
   return res_unmatch((deng_t *)obj, n, 1);
}

/*------------------------------------------------*/
/* function : propagate_match                     */
/* description: Propagates new matched result if  */
/*              option is set in dialog box       */
/*------------------------------------------------*/

void propagate_match(deng_t *eng, sig_t *s1, sig_t *s2, int options) {
   size_t i;

   if (options) {
      show_wait_box ("PatchDiff is in progress ...");

      slist_t *l1 = new slist_t(eng->ulist->num, eng->ulist->file);
      slist_t *l2 = new slist_t(eng->ulist->num, eng->ulist->file);

      for (i = 0; i < eng->ulist->num; i++) {
         if (!eng->ulist->sigs[i]->msig) {
            if (eng->ulist->sigs[i]->nfile == 1) {
               l1->add(eng->ulist->sigs[i]);
            }
            else {
               l2->add(eng->ulist->sigs[i]);
            }
         }
      }
      generate_diff(NULL, l1, l2, eng->ulist->file, NULL);

      delete l1;
      delete l2;

      hide_wait_box();
   }

   i = 0;
   while (i < eng->ulist->num) {
      s1 = eng->ulist->sigs[i];
      s2 = s1->msig;

      if (!s2) {
         i++;
      }
      else {
         if (s1->nfile == 1) {
            if (sig_equal(s1, s2, DIFF_EQUAL_SIG_HASH)) {
               eng->ilist->add(s1);
            }
            else {
               eng->mlist->add(s1);
            }
         }

         eng->ulist->remove(i);
      }
   }
}

/*------------------------------------------------*/
/* function : res_match                           */
/* description: Matches 2 elements from unmatched */
/*              list                              */
/*------------------------------------------------*/

static uint32 idaapi res_match(void *obj,uint32 n) {
   deng_t *eng = (deng_t *)obj;
   sig_t *s1, *s2;
   int option;
   ea_t ea = BADADDR;
   size_t i;

   const char format[] =
         "STARTITEM 0\n"

         "Set Match\n"
         "<Match address:$:32:32::>\n\n"

         "Options :\n" 
         "<Propagate :C>>\n\n"
         ;

   option = 1;
   if (AskUsingForm_c(format, &ea, &option)) {
      s1 = ui_access_sig(eng->ulist, n);

      for (i = 0; i < eng->ulist->num; i++) {
         s2 = eng->ulist->sigs[i];

         if (s2->startEA != ea || (s2->nfile == s1->nfile)) {
            continue;
         }
         s1->set_matched_sig(s2, DIFF_MANUAL);
         propagate_match(eng, s1, s2, option);

         refresh_chooser(title_match);
         refresh_chooser(title_identical);

         return 1;
      }

      warning("Address '%a' is not valid.", ea);
      return 0;
   }

   return 1;
}

/*------------------------------------------------*/
/* function : res_mtoi                            */
/* description: Switches element n from matched   */
/*              to identical list                 */
/*------------------------------------------------*/

static uint32 idaapi res_mtoi(void *obj, uint32 n) {
   deng_t *d = (deng_t *)obj;
   sig_t *sig = ui_access_sig(d->mlist, n);

   sig->mtype = sig->msig->mtype = DIFF_MANUAL;

   d->ilist->add(sig);
   d->mlist->remove(n - 1);

   refresh_chooser(title_identical);

   return 1;
}

/*------------------------------------------------*/
/* function : res_itom                            */
/* description: Switches element n from identical */
/*              to matched list                   */
/*------------------------------------------------*/

static uint32 idaapi res_itom(void *obj, uint32 n) {
   deng_t *d = (deng_t *)obj;
   sig_t *sig = ui_access_sig(d->ilist, n);

   sig->mtype = sig->msig->mtype = DIFF_MANUAL;

   d->mlist->add(sig);
   d->ilist->remove(n - 1);

   refresh_chooser(title_match);

   return 1;
}

/*------------------------------------------------*/
/* function : res_flagged                         */
/* description: Sets element as flagged/unflagged */
/*------------------------------------------------*/

static uint32 idaapi res_flagged(void *obj, uint32 n) {
   sig_t *sig = ui_access_sig(((deng_t *)obj)->mlist, n);

   sig->flag = !sig->flag;

   refresh_chooser(title_match);

   return 1;
}

static void transfer_sym(sig_t *sig) {
   sig_t *rhs = sig->msig;
   sig->set_name(rhs->name);
   set_name(sig->startEA, rhs->name.c_str(), SN_NOCHECK | SN_NON_AUTO);
}

static uint32 idaapi transfer_sym_match(void *obj, uint32 n) {
   sig_t *sig = ui_access_sig(((deng_t *)obj)->mlist, n);

   transfer_sym(sig);

   return 1;
}

static uint32 idaapi transfer_sym_identical(void *obj, uint32 n) {
   sig_t *sig = ui_access_sig(((deng_t *)obj)->ilist, n);

   transfer_sym(sig);

   return 1;
}

#if IDA_SDK_VERSION >= 670
//-------------------------------------------------------------------------
int idaapi munmatch_action_handler_t::activate(action_activation_ctx_t *ctx) {
   uint32 n = ctx->chooser_selection.size();
   if (n == 1) {
      n = ctx->chooser_selection[0];
#if IDA_SDK_VERSION < 700
      return res_munmatch(plugin->d_engine, n);
#else
      return res_munmatch(plugin->d_engine, n + 1);  //hack because pre-7.0 choosers index from 1
#endif
   }
   return 0;
}
   
action_state_t idaapi munmatch_action_handler_t::update(action_update_ctx_t *ctx) {
   bool ok = ctx->form_type == BWN_CHOOSER;
   if (ok) {
      //it's a chooser, now make sure it's the correct form
#if IDA_SDK_VERSION < 700
      char name[MAXSTR];
      ok = get_tform_title(ctx->form, name, sizeof(name)) && strneq(name, title_match, qstrlen(title_match));
#else
      qstring title;
      ok = get_widget_title(&title, ctx->widget) && title == title_match;
#endif
   }
   return ok ? AST_ENABLE_FOR_FORM : AST_DISABLE_FOR_FORM;
}

//-------------------------------------------------------------------------
int idaapi identical_action_handler_t::activate(action_activation_ctx_t *ctx) {
   uint32 n = ctx->chooser_selection.size();
   if (n == 1) {
      n = ctx->chooser_selection[0];
#if IDA_SDK_VERSION < 700
      return res_mtoi(plugin->d_engine, n);
#else
      return res_mtoi(plugin->d_engine, n + 1);  //hack because pre-7.0 choosers index from 1
#endif
   }
   return 0;
}

action_state_t idaapi identical_action_handler_t::update(action_update_ctx_t *ctx) {
   bool ok = ctx->form_type == BWN_CHOOSER;
   if (ok) {
      //it's a chooser, now make sure it's the correct form
#if IDA_SDK_VERSION < 700
      char name[MAXSTR];
      ok = get_tform_title(ctx->form, name, sizeof(name)) && strneq(name, title_match, qstrlen(title_match));
#else
      qstring title;
      ok = get_widget_title(&title, ctx->widget) && title == title_match;
#endif
   }
   return ok ? AST_ENABLE_FOR_FORM : AST_DISABLE_FOR_FORM;
}

//-------------------------------------------------------------------------
int idaapi flagunflag_action_handler_t::activate(action_activation_ctx_t *ctx) {
   uint32 n = ctx->chooser_selection.size();
   if (n == 1) {
      n = ctx->chooser_selection[0];
#if IDA_SDK_VERSION < 700
      return res_flagged(plugin->d_engine, n);
#else
      return res_flagged(plugin->d_engine, n + 1);  //hack because pre-7.0 choosers index from 1
#endif
   }
   return 0;
}

action_state_t idaapi flagunflag_action_handler_t::update(action_update_ctx_t *ctx) {
   bool ok = ctx->form_type == BWN_CHOOSER;
   if (ok) {
      //it's a chooser, now make sure it's the correct form
#if IDA_SDK_VERSION < 700
      char name[MAXSTR];
      ok = get_tform_title(ctx->form, name, sizeof(name)) && strneq(name, title_match, qstrlen(title_match));
#else
      qstring title;
      ok = get_widget_title(&title, ctx->widget) && title == title_match;
#endif
   }
   return ok ? AST_ENABLE_FOR_FORM : AST_DISABLE_FOR_FORM;
}

//-------------------------------------------------------------------------
int idaapi msym_action_handler_t::activate(action_activation_ctx_t *ctx) {
   uint32 n = ctx->chooser_selection.size();
   if (n == 1) {
      n = ctx->chooser_selection[0];
#if IDA_SDK_VERSION < 700
      return transfer_sym_match(plugin->d_engine, n);
#else
      return transfer_sym_match(plugin->d_engine, n + 1);  //hack because pre-7.0 choosers index from 1
#endif
   }
   return 0;
}

action_state_t idaapi msym_action_handler_t::update(action_update_ctx_t *ctx) {
   bool ok = ctx->form_type == BWN_CHOOSER;
   if (ok) {
      //it's a chooser, now make sure it's the correct form
#if IDA_SDK_VERSION < 700
      char name[MAXSTR];
      ok = get_tform_title(ctx->form, name, sizeof(name)) && strneq(name, title_match, qstrlen(title_match));
#else
      qstring title;
      ok = get_widget_title(&title, ctx->widget) && title == title_match;
#endif
   }
   return ok ? AST_ENABLE_FOR_FORM : AST_DISABLE_FOR_FORM;
}

//-------------------------------------------------------------------------
int idaapi iunmatch_action_handler_t::activate(action_activation_ctx_t *ctx) {
   uint32 n = ctx->chooser_selection.size();
   if (n == 1) {
      n = ctx->chooser_selection[0];
#if IDA_SDK_VERSION < 700
      return res_iunmatch(plugin->d_engine, n);
#else
      return res_iunmatch(plugin->d_engine, n + 1);  //hack because pre-7.0 choosers index from 1
#endif
   }
   return 0;
}

action_state_t idaapi iunmatch_action_handler_t::update(action_update_ctx_t *ctx) {
   bool ok = ctx->form_type == BWN_CHOOSER;
   if (ok) {
#if IDA_SDK_VERSION < 700
      char name[MAXSTR];
      ok = get_tform_title(ctx->form, name, sizeof(name)) && strneq(name, title_identical, qstrlen(title_match));
#else
      qstring title;
      ok = get_widget_title(&title, ctx->widget) && title == title_identical;
#endif
   }
   return ok ? AST_ENABLE_FOR_FORM : AST_DISABLE_FOR_FORM;
}

//-------------------------------------------------------------------------
int idaapi itom_action_handler_t::activate(action_activation_ctx_t *ctx) {
   uint32 n = ctx->chooser_selection.size();
   if (n == 1) {
      n = ctx->chooser_selection[0];
#if IDA_SDK_VERSION < 700
      return res_itom(plugin->d_engine, n);
#else
      return res_itom(plugin->d_engine, n + 1);  //hack because pre-7.0 choosers index from 1
#endif
   }
   return 0;
}

action_state_t idaapi itom_action_handler_t::update(action_update_ctx_t *ctx) {
   bool ok = ctx->form_type == BWN_CHOOSER;
   if (ok) {
      //it's a chooser, now make sure it's the correct form
#if IDA_SDK_VERSION < 700
      char name[MAXSTR];
      ok = get_tform_title(ctx->form, name, sizeof(name)) && strneq(name, title_identical, qstrlen(title_match));
#else
      qstring title;
      ok = get_widget_title(&title, ctx->widget) && title == title_identical;
#endif
   }
   return ok ? AST_ENABLE_FOR_FORM : AST_DISABLE_FOR_FORM;
}

//-------------------------------------------------------------------------
int idaapi isym_action_handler_t::activate(action_activation_ctx_t *ctx) {
   uint32 n = ctx->chooser_selection.size();
   if (n == 1) {
      n = ctx->chooser_selection[0];
#if IDA_SDK_VERSION < 700
      return transfer_sym_identical(plugin->d_engine, n);
#else
      return transfer_sym_identical(plugin->d_engine, n + 1);  //hack because pre-7.0 choosers index from 1
#endif
   }
   return 0;
}

action_state_t idaapi isym_action_handler_t::update(action_update_ctx_t *ctx) {
   bool ok = ctx->form_type == BWN_CHOOSER;
   if (ok) {
      //it's a chooser, now make sure it's the correct form
#if IDA_SDK_VERSION < 700
      char name[MAXSTR];
      ok = get_tform_title(ctx->form, name, sizeof(name)) && strneq(name, title_identical, qstrlen(title_match));
#else
      qstring title;
      ok = get_widget_title(&title, ctx->widget) && title == title_identical;
#endif
   }
   return ok ? AST_ENABLE_FOR_FORM : AST_DISABLE_FOR_FORM;
}

//-------------------------------------------------------------------------
int idaapi match_action_handler_t::activate(action_activation_ctx_t *ctx) {
   uint32 n = ctx->chooser_selection.size();
   if (n == 1) {
      n = ctx->chooser_selection[0];
#if IDA_SDK_VERSION < 700
      return res_match(plugin->d_engine, n);
#else
      return res_match(plugin->d_engine, n + 1);  //hack because pre-7.0 choosers index from 1
#endif
   }
   return 0;
}

action_state_t idaapi match_action_handler_t::update(action_update_ctx_t *ctx) {
   bool ok = ctx->form_type == BWN_CHOOSER;
   if (ok) {
      //it's a chooser, now make sure it's the correct form
#if IDA_SDK_VERSION < 700
      char name[MAXSTR];
      ok = get_tform_title(ctx->form, name, sizeof(name)) && strneq(name, title_unmatch, qstrlen(title_match));
#else
      qstring title;
      ok = get_widget_title(&title, ctx->widget) && title == title_unmatch;
#endif
   }
   return ok ? AST_ENABLE_FOR_FORM : AST_DISABLE_FOR_FORM;
}

#endif

#if IDA_SDK_VERSION >= 700

static void idaapi desc_dlist(slist_t *sl, uint32 n, qstrvec_t *cols_) {
   qstrvec_t &cols = *cols_;
   sig_t *sig = ui_access_sig(sl, n + 1); //hack because pre-7.0 choosers index from 1
   cols[0].sprnt("%u", sig->mtype);
   cols[1].sprnt("%s", sig->name.c_str());
   cols[2].sprnt("%s", sig->msig->name.c_str());
   cols[3].sprnt("%a", sig->startEA);
   cols[4].sprnt("%a", sig->msig->startEA);
   cols[5].sprnt("%c", sig->id_crc ? '+' : '-');
   cols[6].sprnt("%lx", sig->crc_hash);
   cols[7].sprnt("%lx", sig->msig->crc_hash);
}

//-------------------------------------------------------------------------
struct matched_chooser_t : public chooser_t {
private:
   deng_t *eng;
public:
   // this object must be allocated using `new`
   matched_chooser_t(deng_t *eng_);

  // function that is used to decide whether a new chooser should be opened
  // or we can use the existing one.
  // The contents of the window are completely determined by its title
   virtual const void *get_obj_id(size_t *len) const {
      *len = strlen(title);
      return title;
   }

   // function that returns number of lines in the list
   virtual size_t idaapi get_count() const {
      return sizer_dlist(eng ? eng->mlist : NULL);
   }

   // function that generates the list line
   virtual void idaapi get_row(qstrvec_t *cols, int *icon_, chooser_item_attrs_t *attrs, size_t n) const;

   // function that is called when the user hits Enter
   virtual cbret_t idaapi enter(size_t n) {
      enter_list(eng->mlist, n + 1);  //hack because pre-7.0 choosers index from 1
      return cbret_t(); // nothing changed
   }
   
   virtual cbret_t idaapi edit(size_t n) {
      graph_match(eng, n + 1); //hack because pre-7.0 choosers index from 1
      return cbret_t(); // nothing changed
   }

   virtual void idaapi closed();
   
};

inline matched_chooser_t::matched_chooser_t(deng_t *eng_) :
      chooser_t(CH_ATTRS | CH_CAN_EDIT, qnumber(widths_match), widths_match, header_match, title_match) {
   eng = eng_;  
   popup_names[POPUP_EDIT] = "Display Graphs";
}

void idaapi matched_chooser_t::get_row(qstrvec_t *cols_, int *, chooser_item_attrs_t *, size_t n) const {
   desc_dlist(eng ? eng->mlist : NULL, n, cols_);
}

void idaapi matched_chooser_t::closed() {
   close_window(eng);
}

static matched_chooser_t *matched_chooser;

//-------------------------------------------------------------------------
struct identical_chooser_t : public chooser_t {
private:
   deng_t *eng;
public:
   // this object must be allocated using `new`
   identical_chooser_t(deng_t *eng_);

  // function that is used to decide whether a new chooser should be opened
  // or we can use the existing one.
  // The contents of the window are completely determined by its title
   virtual const void *get_obj_id(size_t *len) const {
      *len = strlen(title);
      return title;
   }

   // function that returns number of lines in the list
   virtual size_t idaapi get_count() const {
      return sizer_dlist(eng ? eng->ilist : NULL);
   }

   // function that generates the list line
   virtual void idaapi get_row(qstrvec_t *cols, int *icon_, chooser_item_attrs_t *attrs, size_t n) const;

   // function that is called when the user hits Enter
   virtual cbret_t idaapi enter(size_t n) {
      enter_list(eng->ilist, n + 1); //hack because pre-7.0 choosers index from 1
      return cbret_t(); // nothing changed
   }

   virtual cbret_t idaapi edit(size_t n) {
      graph_identical(eng, n + 1);  //hack because pre-7.0 choosers index from 1
      return cbret_t(); // nothing changed
   }

   virtual void idaapi closed() {
      close_window(eng);
   }
};

inline identical_chooser_t::identical_chooser_t(deng_t *eng_) :
      chooser_t(CH_ATTRS | CH_CAN_EDIT, qnumber(widths_match), widths_match, header_match, title_identical) {
   eng = eng_;  
   popup_names[POPUP_EDIT] = "Display Graphs";
}

void idaapi identical_chooser_t::get_row(qstrvec_t *cols_, int *, chooser_item_attrs_t *, size_t n) const {
   desc_dlist(eng ? eng->ilist : NULL, n, cols_);
}

static identical_chooser_t *identical_chooser;

//-------------------------------------------------------------------------
struct unmatched_chooser_t : public chooser_t {
private:
   deng_t *eng;
public:
   // this object must be allocated using `new`
   unmatched_chooser_t(deng_t *eng_);

  // function that is used to decide whether a new chooser should be opened
  // or we can use the existing one.
  // The contents of the window are completely determined by its title
   virtual const void *get_obj_id(size_t *len) const {
      *len = strlen(title);
      return title;
   }

   // function that returns number of lines in the list
   virtual size_t idaapi get_count() const {
      return sizer_dlist(eng ? eng->ulist : NULL);
   }

   // function that generates the list line
   virtual void idaapi get_row(qstrvec_t *cols, int *icon_, chooser_item_attrs_t *attrs, size_t n) const;

   // function that is called when the user hits Enter
   virtual cbret_t idaapi enter(size_t n) {
      sig_t *sig = ui_access_sig(eng->ulist, n + 1);  //hack because pre-7.0 choosers index from 1
      
      if (sig->nfile == 1) {
         jumpto(sig->startEA);
      }
      else {
         os_copy_to_clipboard(NULL);
      }

      return cbret_t(); // nothing changed
   }

   virtual cbret_t idaapi edit(size_t n) {
      graph_unmatch(eng, n + 1);  //hack because pre-7.0 choosers index from 1
      return cbret_t(); // nothing changed
   }

   virtual void idaapi closed() {
      close_window(eng);
   }
};

inline unmatched_chooser_t::unmatched_chooser_t(deng_t *eng_) :
      chooser_t(CH_ATTRS | CH_CAN_EDIT, qnumber(widths_unmatch), widths_unmatch, header_unmatch, title_unmatch) {
   eng = eng_;  
   popup_names[POPUP_EDIT] = "Display Graph";
}

void idaapi unmatched_chooser_t::get_row(qstrvec_t *cols_, int *, chooser_item_attrs_t *, size_t n) const {
   qstrvec_t &cols = *cols_;
   sig_t *sig = ui_access_sig(eng->ulist, n + 1);  //hack because pre-7.0 choosers index from 1
   cols[0].sprnt("%u", sig->nfile);
   cols[1].sprnt("%s", sig->name.c_str());
   cols[2].sprnt("%a", sig->startEA);
   cols[3].sprnt("%.8lX", sig->sig);
   cols[4].sprnt("%.8lX", sig->hash);
   cols[5].sprnt("%.8lX", sig->crc_hash);
}

static unmatched_chooser_t *unmatched_chooser;

#endif

/*------------------------------------------------*/
/* function : display_matched                     */
/* description: Displays matched list             */
/*------------------------------------------------*/

static void display_matched(deng_t *eng) {
#if IDA_SDK_VERSION <= 695
   choose2(CH_ATTRS,
      -1, -1, -1, -1,       // position is determined by Windows
      eng,                  // pass the created function list to the window
      qnumber(header_match),// number of columns
      widths_match,       // widths of columns
      sizer_match,          // function that returns number of lines
      desc_match,           // function that generates a line
      title_match,         // window title
      -1,                   // use the default icon for the window
      1,                    // position the cursor on the first line
      NULL,                 // "kill" callback
      NULL,                 // "new" callback
      NULL,                 // "update" callback
      graph_match,          // "edit" callback
      enter_match,          // function to call when the user pressed Enter
      close_window,         // function to call when the window is closed
      popup_match,          // use default popup menu items
      NULL);
#else
   if (matched_chooser == NULL) {
      matched_chooser = new matched_chooser_t(eng);
      matched_chooser->choose(chooser_t::NO_SELECTION);
   }
#endif

   eng->wnum++;
   
#if IDA_SDK_VERSION <= 660 
   add_chooser_command(title_match, "Unmatch", res_munmatch, 0, -1, CHOOSER_POPUP_MENU | CHOOSER_MENU_EDIT);
   add_chooser_command(title_match, "Set as identical", res_mtoi, 0, -1, CHOOSER_POPUP_MENU | CHOOSER_MENU_EDIT);
   add_chooser_command(title_match, "Flag/unflag", res_flagged, 0, -1, CHOOSER_POPUP_MENU | CHOOSER_MENU_EDIT);
   add_chooser_command(title_match, "Import Symbol", transfer_sym_match, 0, -1, CHOOSER_POPUP_MENU | CHOOSER_MENU_EDIT);
#else
   auto_wait();
#if IDA_SDK_VERSION <= 695
   TForm *form = find_tform(title_match);
#else
   TWidget *form = find_widget(title_match);
#endif

   if (form) {
      attach_action_to_popup(form, NULL, MUNMATCH_NAME);
      attach_action_to_popup(form, NULL, IDENTICAL_NAME);
      attach_action_to_popup(form, NULL, FLAGUNFLAG_NAME);
      attach_action_to_popup(form, NULL, MSYM_NAME);
   }
   else {
      msg("Failed to lookup form %s\n", title_match);
   }
#endif
}

/*------------------------------------------------*/
/* function : display_identical                   */
/* description: Displays identical list           */
/*------------------------------------------------*/

static void display_identical(deng_t *eng) {
#if IDA_SDK_VERSION <= 695
   choose2(0,
      -1, -1, -1, -1,       // position is determined by Windows
      eng,                  // pass the created function list to the window
      qnumber(header_match),// number of columns
      widths_match,       // widths of columns
      sizer_identical,      // function that returns number of lines
      desc_identical,       // function that generates a line
      title_identical,    // window title
      -1,                   // use the default icon for the window
      1,                    // position the cursor on the first line
      NULL,                 // "kill" callback
      NULL,                 // "new" callback
      NULL,                 // "update" callback
      graph_identical,      // "edit" callback
      enter_identical,      // function to call when the user pressed Enter
      close_window,         // function to call when the window is closed
      popup_match,          // use default popup menu items
      NULL);  
#else
   if (identical_chooser == NULL) {
      identical_chooser = new identical_chooser_t(eng);
      identical_chooser->choose(chooser_t::NO_SELECTION);
   }
#endif

   eng->wnum++;
   
#if IDA_SDK_VERSION <= 660 
   add_chooser_command(title_identical, "Unmatch", res_iunmatch, 0, -1, CHOOSER_POPUP_MENU | CHOOSER_MENU_EDIT);
   add_chooser_command(title_identical, "Set as matched", res_itom, 0, -1, CHOOSER_POPUP_MENU | CHOOSER_MENU_EDIT);
   add_chooser_command(title_identical, "Import Symbol", transfer_sym_identical, 0, -1, CHOOSER_POPUP_MENU | CHOOSER_MENU_EDIT);
#else
#if IDA_SDK_VERSION <= 695
   TForm *form = find_tform(title_identical);
#else
   auto_wait();
   TWidget *form = find_widget(title_identical);
#endif
   if (form) {
      attach_action_to_popup(form, NULL, IUNMATCH_NAME);
      attach_action_to_popup(form, NULL, ITOM_NAME);
      attach_action_to_popup(form, NULL, ISYM_NAME);
   }
   else {
      msg("Failed to lookup form %s\n", title_identical);
   }
#endif
}

/*------------------------------------------------*/
/* function : display_unmatched                   */
/* description: Displays unmatched list           */
/*------------------------------------------------*/

static void display_unmatched(deng_t *eng) {
#if IDA_SDK_VERSION <= 695
   choose2(0,
      -1, -1, -1, -1,       // position is determined by Windows
      eng,                  // pass the created function list to the window
      qnumber(header_unmatch),// number of columns
      widths_unmatch,        // widths of columns
      sizer_unmatch,        // function that returns number of lines
      desc_unmatch,         // function that generates a line
      title_unmatch,       // window title
      -1,                   // use the default icon for the window
      1,                    // position the cursor on the first line
      NULL,                 // "kill" callback
      NULL,                 // "new" callback
      NULL,                 // "update" callback
      graph_unmatch,        // "edit" callback
      enter_unmatch,        // function to call when the user pressed Enter
      close_window,         // function to call when the window is closed
      popup_unmatch,        // use default popup menu items
      NULL);                // use the same icon for all lines
#else
   if (unmatched_chooser == NULL) {
      unmatched_chooser = new unmatched_chooser_t(eng);
      unmatched_chooser->choose(chooser_t::NO_SELECTION);
   }
#endif

   eng->wnum++;
   
#if IDA_SDK_VERSION <= 660 
   add_chooser_command(title_unmatch, "Set match", res_match, 0, -1, CHOOSER_POPUP_MENU | CHOOSER_MENU_EDIT);
#else
   auto_wait();
#if IDA_SDK_VERSION <= 695
   TForm *form = find_tform(title_unmatch);
#else
   TWidget *form = find_widget(title_unmatch);
#endif
   if (form) {
      attach_action_to_popup(form, NULL, MATCH_NAME);
   }
   else {
      msg("Failed to lookup form %s\n", title_unmatch);
   }
#endif
}

/*------------------------------------------------*/
/* function : ui_callback                         */
/* description: Catchs lists to change bg color   */
/*------------------------------------------------*/

#if IDA_SDK_VERSION < 700
int idaapi ui_callback(void *data, int event_id, va_list va) {
#else
ssize_t idaapi ui_callback(void *data, int event_id, va_list va) {
#endif
   if (event_id == ui_get_chooser_item_attrs) {
      void *co = va_arg(va, void *);
      uint32 n = va_arg(va, uint32);
#if IDA_SDK_VERSION >= 700
      n += 1;  //hack because pre-7.0 choosers index from 1
#endif
      chooser_item_attrs_t *attrs = va_arg(va, chooser_item_attrs_t *);
      if (attrs != NULL) {
         deng_t *d = (deng_t *)co;
         if (d && d->magic == 0x0BADF00D && n > 0) {
            if (ui_access_sig(d->mlist, n)->flag == 1) {
               attrs->color = 0x908070;
            }
         }
      }
   }

   return 0;
}

/*------------------------------------------------*/
/* function : display_results                     */
/* description: Displays diff results             */
/*------------------------------------------------*/

void display_results(pd_plugmod_t *plugin) {

#if IDA_SDK_VERSION >= 670
   register_action(plugin->munmatch_action);
   register_action(plugin->identical_action);
   register_action(plugin->flagunflag_action);
   register_action(plugin->msym_action);
   register_action(plugin->iunmatch_action);
   register_action(plugin->itom_action);
   register_action(plugin->isym_action);
   register_action(plugin->match_action);
#endif

   hook_to_notification_point(HT_UI, ui_callback, NULL);

   display_matched(plugin->d_engine);
   display_unmatched(plugin->d_engine);
   display_identical(plugin->d_engine);
}
