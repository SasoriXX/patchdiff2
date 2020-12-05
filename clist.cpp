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
#include "hash.h"

/*------------------------------------------------*/
/* function : clist_t::clist_t                    */
/* description: Initializes a chained list of     */
/*              signatures                        */
/*------------------------------------------------*/

clist_t::clist_t(slist_t *l) {
   dpsig_t *ds;
   dpsig_t *prev;
   size_t i;

   num = l->num;
   sigs = NULL;
   nmatch = 0;
   msigs = NULL;

   prev = NULL;

   for (i = 0; i < l->num; i++) {
      ds = new dpsig_t();
      ds->prev = prev;
      ds->next = NULL;
      ds->removed = false;
      ds->sig = l->sigs[i];

      if (prev) {
         prev->next = ds;
      }
      else {
         sigs = ds;
      }

      prev = ds;
   }

   pos = sigs;
}

/*------------------------------------------------*/
/* function : clist_t::insert                     */
/* description: Inserts sig in sorted list        */
/*------------------------------------------------*/

int clist_t::insert(sig_t *s) {
   dpsig_t *ds;
   dpsig_t *prev;
   dpsig_t *cur;
   int ret;

   ds = new dpsig_t();
   if (!ds) {
      return -1;
   }
   ds->sig = s;
   ds->prev = NULL;
   ds->next = NULL;
   ds->removed = false;

   prev = NULL;
   cur = sigs;
   while (cur) {
      // sig_compare is reversed
      ret = sig_compare(&s, &cur->sig) ;
      if (!ret && cur->sig->startEA == s->startEA) {
         return -1;
      }
      if (ret <= 0) {
         break;
      }
      prev = cur;
      cur = cur->next;
   }

   ds->prev = prev;
   ds->next = cur;

   if (!prev) {
      sigs = ds;
   }
   else {
      prev->next = ds;
   }
   if (cur) {
      cur->prev = ds;
   }
   num++;

   return 0;
}

/*------------------------------------------------*/
/* function : clist_t_::insert_dsig               */
/* description: Inserts dsig in matched list      */
/*------------------------------------------------*/

int clist_t::insert_dsig(dpsig_t *ds) {
   dpsig_t *prev;
   dpsig_t *cur;
   int ret;

   ds->prev = NULL;
   ds->next = NULL;
   ds->removed = true;

   prev = NULL;
   cur = msigs;
   while (cur) {
      // sig_compare is reversed
      ret = sig_compare(&ds->sig, &cur->sig) ;
      if (!ret && cur->sig->startEA == ds->sig->startEA) {
         return -1;
      }

      if (ret <= 0) {
         break;
      }
      prev = cur;
      cur = cur->next;
   }

   ds->prev = prev;
   ds->next = cur;

   if (!prev) {
      msigs= ds;
   }
   else {
      prev->next = ds;
   }
   if (cur) {
      cur->prev = ds;
   }
   nmatch++;

   return 0;
}

/*------------------------------------------------*/
/* function : clist_t::clist_t                    */
/* description: Initializes a chained list of     */
/*              signatures with a list of xrefs   */
/*------------------------------------------------*/

clist_t::clist_t(hpsig_t *hsig, frefs_t *refs) {
   fref_t *fl;
   sig_t *sig;

   num = 0;
   nmatch = 0;
   sigs = NULL;
   pos = NULL;
   msigs = NULL;

   if (!refs) {
      return;
   }
   fl = refs->list;

   while(fl) {
      sig = hash_find_ea(hsig, fl->ea);
      if (sig && sig->get_matched_type() == DIFF_UNMATCHED) {
         insert(sig);
      }
      fl = fl->next;
   }

   pos = sigs;
}

/*------------------------------------------------*/
/* function : clist_t::remove                     */
/* description: Removes element from list         */
/*------------------------------------------------*/

void clist_t::remove(dpsig_t *ds) {
   if (ds->removed == true)
      return;

   if (ds->prev == NULL) {
      sigs = ds->next;
   }
   else {
      ds->prev->next = ds->next;
   }
   if (ds->next != NULL) {
      ds->next->prev = ds->prev;
   }
   insert_dsig(ds);
}

/*------------------------------------------------*/
/* function : clist_t::reset                      */
/* description: Resets list position              */
/*------------------------------------------------*/

void clist_t::reset() {
   pos = sigs;
}

/*------------------------------------------------*/
/* function : clist_t::~clist_t                   */
/* description: Frees clist_t structure           */
/*------------------------------------------------*/

clist_t::~clist_t() {
   delete sigs;
   sigs = NULL;
   delete msigs;
   msigs = NULL;
}

/*------------------------------------------------*/
/* function : clist_t::equal_match                   */
/* description: Checks if all the elements of a   */
/*              clist match                       */
/*------------------------------------------------*/
bool clist_t::equal_match(const clist_t &cl2) {
   dpsig_t *s1, *s2;
   size_t i;

   if (nmatch == 0 || cl2.nmatch == 0) {
      return false;
   }
   if (nmatch != cl2.nmatch) {
      return false;
   }
   s1 = msigs;
   s2 = cl2.msigs;

   for (i = 0; i < nmatch; i++) {
      if ((s1->sig->get_matched_type() == DIFF_UNMATCHED) || (s1->sig->msig->startEA != s2->sig->startEA)) {
         return false;
      }
      s1 = s1->next;
      s2 = s2->next;
   }

   return true;
}

/*------------------------------------------------*/
/* function : clist_almost_equal_match            */
/* description: Checks if at lest one element of a*/
/*              clist match                       */
/*------------------------------------------------*/
bool clist_t::almost_equal_match(const clist_t &cl2) {
   dpsig_t *s1, *s2;
   size_t i, k;

   if (nmatch == 0 || cl2.nmatch == 0) {
      return false;
   }
   if (nmatch != cl2.nmatch) {
      return false;
   }
   s1 = msigs;

   for (i = 0; i < nmatch; i++) {
      s2 = cl2.msigs;

      for (k = 0; k < cl2.nmatch; k++) {
         if (s1->sig->msig->startEA == s2->sig->startEA) {
            return true;
         }
         s2 = s2->next;
      }

      s1 = s1->next;
   }

   return false;
}
