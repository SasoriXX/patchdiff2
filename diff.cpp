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

#include "hash.h"
#include "sig.h"
#include "diff.h"
#include "clist.h"
#include "display.h"
#include "backup.h"
#include "options.h"
#include "plugin.h"

/*------------------------------------------------*/
/* function : diff_init_hash                      */
/* description: Initializes a hash structure and  */
/*              creates successor xrefs           */
/*------------------------------------------------*/

static hpsig_t *diff_init_hash(slist_t *sl) {
   fref_t *fref;
   sig_t *sig;
   hpsig_t *h;
   size_t i;

   h = hash_init(sl->num);
   if (!h) {
      return NULL;
   }
   for (i = 0; i < sl->num; i++) {
      if (hash_add_ea(h, sl->sigs[i]) < 0) {
         hash_free(h);
         return NULL;
      }
   }
   // adds xrefs
   for (i = 0; i < sl->num; i++) {
      if (sl->sigs[i]->srefs) {
         fref = sl->sigs[i]->srefs->list;
         while (fref) {
            if (!fref->rtype) {
               sig = hash_find_ea(h, fref->ea);
               if (sig) {
                  sig->add_pref(sl->sigs[i]->startEA, fref->type, DO_NOT_CHECK_REF);
               }
            }
            fref = fref->next;
         }
      }

      if (sl->sigs[i]->prefs) {
         fref = sl->sigs[i]->prefs->list;
         while (fref) {
            if (!fref->rtype) {
               sig = hash_find_ea(h, fref->ea);
               if (sig) {
                  sig->add_sref(sl->sigs[i]->startEA, fref->type, DO_NOT_CHECK_REF);
               }
            }
            fref = fref->next;
         }
      }
   }
   return h;
}

/*------------------------------------------------*/
/* function : slist_init_crefs                    */
/* description: Initializes slist crefs           */
/*------------------------------------------------*/

static int slist_init_crefs(slist_t *l) {
   hpsig_t *h = NULL;
   clist_t *cl1;
   clist_t *cl2;
   size_t i;

   h = diff_init_hash(l);
   if (!h) {
      return -1;
   }
   for (i = 0; i < l->num; i++) {
      cl1 = new clist_t(h, l->sigs[i]->get_preds());
      cl2 = new clist_t(h, l->sigs[i]->get_succs());
      l->sigs[i]->set_crefs(SIG_PRED, cl1);
      l->sigs[i]->set_crefs(SIG_SUCC, cl2);
   }

   return 0;
}

/*------------------------------------------------*/
/* function : deng_t constructor                  */
/* description: Initializes engine structures     */
/*------------------------------------------------*/
deng_t::deng_t(options_t *opt) {
   init(opt);
   magic = 0x0BADF00D;
}

/*------------------------------------------------*/
/* function : deng_t constructor                  */
/* description: Initializes engine structures     */
/*------------------------------------------------*/
deng_t::deng_t(slist_t *l1, slist_t *l2, options_t *opt) {
   init(opt);

   unmatched = l1->num + l2->num;

   this->opt = opt;

   if (slist_init_crefs(l1) != 0) {
      return;
   }
   if (slist_init_crefs(l2) != 0) {
      return;
   }

   magic = 0x0BADF00D;
}

/*------------------------------------------------*/
/* function : deng_t constructor                  */
/* description: Initializes engine structures     */
/*------------------------------------------------*/
void deng_t::init(options_t *opt) {
   magic = 0;
   wnum = 0;
   opt = opt;
   mlist = NULL;
   ulist = NULL;
   ilist = NULL;
   identical = 0;
   matched = 0;
   unmatched = 0;
}

/*------------------------------------------------*/
/* function : deng_t destructor                   */
/* description: Release engine resources          */
/*------------------------------------------------*/
deng_t::~deng_t() {
   if (ilist) {
      ilist->free_sigs();
      delete ilist;
   }
   if (mlist) {
      mlist->free_sigs();
      delete mlist;
   }
   if (ulist) {
      ulist->free_sigs();
      delete ulist;
   }
}

/*------------------------------------------------*/
/* function : sig_equal                           */
/* description: Checks if 2 sigs are equal        */
/*------------------------------------------------*/

bool sig_equal(sig_t *s1, sig_t *s2, int type) {
   if (s1->sig != s2->sig || s1->hash != s2->hash) {
      return false;
   }

   if (type == DIFF_EQUAL_SIG_HASH_CRC_STR) {
      if (s1->str_hash != s2->str_hash) {
         return false;
      }
   }

   if (type <= DIFF_EQUAL_SIG_HASH_CRC) {
      if (s1->crc_hash != s2->crc_hash) {
         return false;
      }
   }

   return true;
}

/*------------------------------------------------*/
/* function : sig_name_equal                      */
/* description: Checks if 2 sig names are equal   */
/*------------------------------------------------*/

static bool sig_name_equal(sig_t *s1, sig_t *s2) {
   if (!strncmp(s1->name.c_str(), "sub_", 4) || (s1->name != s2->name)) {
      return false;
   }
   return true;
}

/*------------------------------------------------*/
/* function : clist_get_unique_sig                */
/* description: Returns first unique signature in */
/*              list starting at ds              */
/* note: changes ds if ds already matched         */
/*------------------------------------------------*/

dpsig_t *clist_t::get_unique_sig(dpsig_t **ds, int type) {
   dpsig_t *ptr, *tmp;

   if (!*ds) {
      return NULL;
   }
   ptr = *ds;

   // do not keep the current signature if not unique
   while (ptr) {
      if (ptr->sig->get_matched_type() != DIFF_UNMATCHED) {
         if (ptr == *ds) {
            *ds = ptr->next;
            if (!*ds) {
               return NULL;
            }
         }

         tmp = ptr->next;
         remove(ptr);
         ptr = tmp;
      }
      else {
         if (!ptr->next) {
            break;
         }
         if (type == DIFF_NEQUAL_SUCC) {
            if (sig_equal(ptr->sig, (*ds)->sig, type) && sig_equal(ptr->next->sig, (*ds)->sig, type)) {
               return NULL;
            }
            if (( (!sig_equal(ptr->next->sig, (*ds)->sig, type) && (!ptr->prev || !sig_equal(ptr->prev->sig, (*ds)->sig, type))) || !(*ds)->sig->cs->equal_match(*ptr->next->sig->cs)) && ptr->sig->cs->nmatch > 0 &&  ptr->sig->cs->num == ptr->sig->cs->nmatch) {
               break;
            }
         }
         else if (type == DIFF_NEQUAL_PRED) {
            if (sig_equal(ptr->sig, (*ds)->sig, type) && sig_equal(ptr->next->sig, (*ds)->sig, type)) {
               return NULL;
            }
            if (( (!sig_equal(ptr->next->sig, (*ds)->sig, type) && (!ptr->prev || !sig_equal(ptr->prev->sig, (*ds)->sig, type))) || !(*ds)->sig->cp->equal_match(*ptr->next->sig->cp)) && ptr->sig->cp->nmatch > 0 && ptr->sig->cp->num == ptr->sig->cp->nmatch) {
               break;
            }
         }
         else if (type == DIFF_EQUAL_NAME) {
            if (!sig_equal(ptr->next->sig, (*ds)->sig, type) || !sig_name_equal((*ds)->sig, ptr->next->sig)) {
               break;
            }
         }
         else if (type == DIFF_NEQUAL_STR) {
            bool b = false;
            tmp = *ds;

            if (ptr->sig->str_hash != 0) {
               // slow: need to improve
               while (tmp) {
                  if (tmp->sig->startEA != ptr->sig->startEA && tmp->sig->str_hash == ptr->sig->str_hash) {
                     b = true;
                     break;
                  }

                  tmp = tmp->next;
               }

               if (!b) {
                  break;
               }
            }
         }
         else {
            bool b = sig_equal(ptr->next->sig, (*ds)->sig, type);
            if (!b) break;
         }

         ptr = ptr->next;
      }
   }

   return ptr;
}

/*------------------------------------------------*/
/* function : clist_get_best_sig                  */
/* description: Returns best unique signature in  */
/*              list                       */
/* note: position pointer is incremented to the   */
/*       next signature in the list               */
/*------------------------------------------------*/

dpsig_t *clist_t::get_best_sig(int type) {
   dpsig_t *best, *ptr;

   best = pos;

   ptr = get_unique_sig(&best, type);

   // no more signature
   if (!best) return NULL;

   if (ptr == best) {
      pos = best->next;
      return best;
   }

   pos = ptr;
   return get_best_sig(type);
}

/*------------------------------------------------*/
/* function : clist_t::get_eq_sig                 */
/* description: Returns signature if sig presents */
/*              in list and unique                */
/*------------------------------------------------*/

dpsig_t *clist_t::get_eq_sig(dpsig_t *dsig, int type) {
   dpsig_t * ds, * ptr;
   bool b2, b1 = dsig->sig->is_class();

   ds = sigs;
   while (ds) {
      if (type == DIFF_NEQUAL_SUCC) {
         ptr = get_unique_sig(&ds, type);
         if (!ds || !ptr) {
            return NULL;
         }
         b2 = ptr->sig->is_class();
         if (b1 ^ b2) {
            return NULL;
         }
         if (ptr->sig->cs->equal_match(*dsig->sig->cs)) {
            if (ptr->next && (ptr->next->sig->sig == ptr->sig->sig || ptr->next->sig->cs->equal_match(*dsig->sig->cs))) {
               return NULL;
            }

            return ptr;
         }
      }
      else if (type == DIFF_NEQUAL_PRED) {
         ptr = get_unique_sig(&ds, type);
         if (!ds || !ptr) {
            return NULL;
         }
         b2 = ptr->sig->is_class();
         if (b1 ^ b2) {
            return NULL;
         }
         if (ptr->sig->cp->equal_match(*dsig->sig->cp)) {
            if (ptr->next && (ptr->next->sig->sig == ptr->sig->sig || ptr->next->sig->cp->equal_match(*dsig->sig->cp))) {
               return NULL;
            }

            return ptr;
         }
      }
      else if (type == DIFF_EQUAL_NAME) {
         ptr = get_unique_sig(&ds, type);
         if (!ds || !ptr) {
            return NULL;
         }
         if (sig_name_equal(ptr->sig, dsig->sig)) {
            return ptr;
         }
      }
      else if (type == DIFF_NEQUAL_STR) {
         ptr = get_unique_sig(&ds, type);
         if (!ds || !ptr) {
            return NULL;
         }
         if (ptr->sig->str_hash != 0 && ptr->sig->str_hash == dsig->sig->str_hash) {
            return ptr;
         }
      }
      else {
         if (sig_equal(ds->sig, dsig->sig, type)) {
            ptr = get_unique_sig(&ds, type);

            if (!ds) {
               return NULL;
            }
            if (ptr != ds || !sig_equal(ds->sig, dsig->sig, type)) {
               return NULL;
            }

            return ds;
         }
         else if (ds->sig->sig < dsig->sig->sig) {
            return NULL;
         }
      }

      ds = ds->next;
   }

   return NULL;
}

void clist_t::update_crefs(dpsig_t *ds, int type) {
   dpsig_t *tmp;
   dpsig_t *next;
   dpsig_t *tmp2;
   dpsig_t *next2;
   clist_t *tcl;

   tmp = sigs;
   while (tmp) {
      next = tmp->next;

      if (type == SIG_SUCC) {
         tcl = tmp->sig->cs;
      }
      else {
         tcl = tmp->sig->cp;
      }
      tmp2 = tcl->sigs;
      while (tmp2) {
         next2 = tmp2->next;

         if (tmp2->sig->startEA == ds->sig->startEA) {
            tcl->remove(tmp2);
         }
         tmp2 = next2;
      }

      tmp = next;
   }
}

void clist_t::update_and_remove(dpsig_t *ds) {
   if (ds->removed) {
      return;
   }
   ds->sig->cp->update_crefs(ds, SIG_SUCC);
   ds->sig->cs->update_crefs(ds, SIG_PRED);

   remove(ds);
}

/*------------------------------------------------*/
/* function : diff_run                            */
/* description: Runs binary analysis              */
/*------------------------------------------------*/

static int diff_run(deng_t *eng, clist_t *cl1, clist_t *cl2, int min_type, int max_type, bool pclass) {
   dpsig_t *dsig, *dsig2;
   int changed = 0;
   int type = min_type;
   int mtype = max_type;
   bool b;

   if (pclass && max_type > DIFF_EQUAL_SIG_HASH) {
      mtype = DIFF_EQUAL_SIG_HASH;
   }
   do {
      cl1->reset();
      cl2->reset();

      changed = 0;
      while ((dsig = cl1->get_best_sig(type)) != NULL) {
         cl2->reset();
         dsig2 = cl2->get_eq_sig(dsig, type);
         if (dsig2) {
            dsig->sig->set_matched_sig(dsig2->sig, type);

            eng->unmatched -= 2;
            if (dsig->sig->hash2 == dsig2->sig->hash2 || sig_equal(dsig->sig, dsig2->sig, DIFF_EQUAL_SIG_HASH)) {
               eng->identical++;
            }
            else {
               eng->matched++;
            }
            changed = 1;

            cl1->update_and_remove(dsig);
            cl2->update_and_remove(dsig2);

            b = dsig->sig->is_class();

            // string matching is not 100% reliable so we only match on crc/hash
            if (mtype == DIFF_NEQUAL_STR) {
               b = true;
            }
            diff_run(eng, dsig->sig->get_crefs(SIG_PRED), dsig2->sig->get_crefs(SIG_PRED), min_type, max_type, b);
            diff_run(eng, dsig->sig->get_crefs(SIG_SUCC), dsig2->sig->get_crefs(SIG_SUCC), min_type, max_type, b);

         }
      }

      if (changed == 0) {
         type++;
      }
   } while(type <= mtype);

   return 0;
}

/*------------------------------------------------*/
/* function : generate_diff                       */
/* description: Generates binary diff             */
/*------------------------------------------------*/

int generate_diff(deng_t **d, slist_t *l1, slist_t *l2, const char *file, options_t *opt) {
   int ret;
   clist_t *cl1, *cl2;

   deng_t *eng = new deng_t(l1, l2, opt);
   if (!eng->is_valid()) {
      delete eng;
      return -1;
   }
   cl1 = new clist_t(l1);
   cl2 = new clist_t(l2);

   if (file) {
      ret = diff_run(eng, cl1, cl2, DIFF_EQUAL_NAME, DIFF_NEQUAL_STR, false);
   }
   else {
      ret = diff_run(eng, cl1, cl2, DIFF_EQUAL_SIG_HASH_CRC, DIFF_EQUAL_SIG_HASH, false);
      ret = diff_run(eng, cl1, cl2, DIFF_NEQUAL_PRED, DIFF_NEQUAL_STR, false);
   }

   if (d) {
      *d = eng;
   }
   else {
      delete eng;  // what else could be using eng at this point? nothing?
   }
   return 0;
}

void deng_t::display(pd_plugmod_t *plugin, slist_t *l1, slist_t *l2, const char *file) {
   int un1, un2, idf, mf;

   mlist = new slist_t(matched, file);
   ulist = new slist_t(unmatched, file);
   ilist = new slist_t(identical, file);

   un1 = un2 = idf = mf = 0;

   for (size_t i = 0; i < l1->num; i++) {
      if (l1->sigs[i]->is_class()) {
         delete l1->sigs[i];
         continue;
      }

      if (l1->sigs[i]->get_matched_type() == DIFF_UNMATCHED) {
         l1->sigs[i]->set_nfile(1);
         ulist->add(l1->sigs[i]);
         un1++;
      }
      else {
         if (l1->sigs[i]->hash2 == l1->sigs[i]->msig->hash2 || sig_equal(l1->sigs[i], l1->sigs[i]->msig, DIFF_EQUAL_SIG_HASH)) {
            ilist->add(l1->sigs[i]);
            idf++;
         }
         else {
            mlist->add(l1->sigs[i]);
            mf++;
         }
      }
   }

   for (size_t i = 0; i < l2->num; i++) {
      if (l2->sigs[i]->is_class()) {
         delete l2->sigs[i];
         continue;
      }

      if (l2->sigs[i]->get_matched_type() == DIFF_UNMATCHED) {
         l2->sigs[i]->set_nfile(2);
         ulist->add(l2->sigs[i]);
         un2++;
      }
   }

   msg("Identical functions:   %d\n", idf);
   msg("Matched functions:     %d\n", mf);
   msg("Unmatched functions 1: %d\n", un1);
   msg("Unmatched functions 2: %d\n", un2);
   display_results(plugin);
}
