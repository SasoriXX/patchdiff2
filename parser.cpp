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

#include "parser.h"
#include "sig.h"
#include "os.h"
#include "pchart.h"
#include "system.h"

/*------------------------------------------------*/
/* function : parse_idb                           */
/* description: generates a list of signatures for*/
/*              the current idb                   */
/*------------------------------------------------*/

slist_t *parse_idb() {
   slist_t *sl;
   sig_t *sig;
   size_t fct_num, i;
   qvector<ea_t> class_l;

   fct_num = get_func_qty();

   sl = new slist_t(fct_num, NULL);
   if (!sl) {
      return NULL;
   }

   for (i = 0; i < fct_num; i++) {
      sig = sig_generate(i, class_l);
      if (sig) {
         // removes 1 line jump functions
         if (sig->sig == 0 || sig->lines <= 1) {
            delete sig;
         }
         else {
            sl->add(sig);
         }
      }
   }

   if (!sl->realloc(class_l.size())) {
      sl->free_sigs();
      delete sl;
      return NULL;
   }

   for (i = 0; i < class_l.size(); i++) {
      sig = sig_class_generate(class_l[i]);
      if (sig) {
         sl->add(sig);
      }
   }

   sl->sort();

   return sl;
}

/*------------------------------------------------*/
/* function : parse_fct                           */
/* description: generates a list of signatures for*/
/*              the current function              */
/*------------------------------------------------*/

slist_t *parse_fct(ea_t ea, char options) {
   slist_t * sl;
   sig_t * sig;
   func_t * fct;
   int i, k;
   pflow_chart_t * fchart;
   short opcodes[256];
   char buf[512];

   fct = get_func(ea);
   if (!fct) {
      return NULL;
   }

   if (!pget_func_name(ea, buf, sizeof(buf))) {
      return NULL;
   }

   fchart = new pflow_chart_t(fct);

   sl = new slist_t(fchart->nproper, NULL);
   if (!sl) {
      return NULL;
   }

   for (i = 0; i < fchart->nproper; i++) {
      memset(opcodes, '\0', sizeof(opcodes));
      sig = new sig_t();
      if (!sig) {
         sl->free_sigs();
         delete sl;
         delete fchart;
         return NULL;
      }

      sig->set_start(fchart->blocks[i].startEA);
      sig->set_name(buf);

      for (k = 0; k < fchart->nsucc(i); k++) {
         sig->add_sref(fchart->blocks[i].succ[k].ea, fchart->blocks[i].succ[k].type, CHECK_REF);
      }

      sig->add_block(opcodes, fchart->blocks[i].startEA, fchart->blocks[i].endEA, 1, options);

      sig->calc_sighash(opcodes, 1);

      sl->add(sig);
   }

   sl->sort();
   delete fchart;

   return sl;
}

/*------------------------------------------------*/
/* function : parse_second_idb                    */
/* description: generates a list of signatures for*/
/*              another idb                       */
/*------------------------------------------------*/

slist_t *parse_second_idb(char **file, options_t *opt) {
   char ext[10];

   qsnprintf(ext, sizeof(ext), ".%s", IDB_EXT);

   *file = askfile_c(0, ext, "IDA Database");
   if (!*file) {
      msg("Failed to open second IDB\n");
      return NULL;
   }

   return system_parse_idb(BADADDR, *file, opt);
}

/*------------------------------------------------*/
/* function : parse_second_fct                    */
/* description: generates a list of signatures for*/
/*              another fct                       */
/*------------------------------------------------*/

slist_t *parse_second_fct(ea_t ea, const char *file, options_t *opt){
   return system_parse_idb(ea, file, opt);
}
