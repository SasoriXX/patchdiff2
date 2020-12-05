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

#ifndef __DIFF_H__
#define __DIFF_H__

#include "sig.h"
#include "hash.h"
#include "options.h"

#define DIFF_EQUAL_NAME               0
#define DIFF_EQUAL_SIG_HASH_CRC         1
#define DIFF_EQUAL_SIG_HASH_CRC_STR      2
#define DIFF_EQUAL_SIG_HASH            3
#define DIFF_NEQUAL_PRED            4
#define DIFF_NEQUAL_SUCC            5
#define DIFF_NEQUAL_STR               6
#define DIFF_MANUAL                  7

struct pd_plugmod_t;

struct deng_t {
   int magic;
   int matched;
   int unmatched;
   int identical;
   slist_t *mlist;
   slist_t *ulist;
   slist_t *ilist;
   options_t *opt;
   int wnum;

   deng_t(slist_t *l1, slist_t *l2, options_t *opt);
   deng_t(options_t *opt);
   ~deng_t();

   void init(options_t *opt);

   bool is_valid() {return magic == 0x0BADF00D;};

   void display(pd_plugmod_t *plugin, slist_t *l1, slist_t *l2, const char *file);
};

int generate_diff(deng_t **, slist_t *, slist_t *, const char *, options_t *);

bool sig_equal(sig_t *, sig_t *, int);

#endif
