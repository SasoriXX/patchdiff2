/*
   Patchdiff2
   Portions (C) 2010 - 2011 Nicolas Pouvesle
   Portions (C) 2007 - 2009 Tenable Network Security, Inc.
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

#ifndef __SIG_H__
#define __SIG_H__

#include "precomp.h"

#define DIFF_UNMATCHED -1

#define CLASS_SIG 0xACDCACDC

#define SIG_PRED 1
#define SIG_SUCC 2

#define CHECK_REF 0
#define DO_NOT_CHECK_REF 1

#ifdef _WINDOWS
#define OS_CDECL __cdecl
#else
#define OS_CDECL
#endif

struct sig_t;
struct slist_t;
struct hpsig_t;
struct frefs_t;

struct dpsig_t {
   sig_t *sig;
   bool removed;
   dpsig_t *prev;
   dpsig_t *next;

   ~dpsig_t();
};

struct clist_t {
   uint32_t num;
   dpsig_t *pos;   // position in sigs list
   dpsig_t *sigs;  // chained list

   uint32_t nmatch; // number of matched element
   dpsig_t *msigs;  // matched list

   clist_t(slist_t *);
   clist_t(hpsig_t *, frefs_t *);

   ~clist_t();

   int insert_dsig(dpsig_t *ds);
   int insert(sig_t *);
   void remove(dpsig_t *);
   void reset();

   bool equal_match(const clist_t &rhs);
   bool almost_equal_match(const clist_t &rhs);
   dpsig_t *get_unique_sig(dpsig_t **ds, int type);
   dpsig_t *get_best_sig(int type);
   dpsig_t *get_eq_sig(dpsig_t *dsig, int type);
   void update_crefs(dpsig_t *ds, int type);
   void update_and_remove(dpsig_t *ds);
};

struct fref_t {
   ea_t ea;
   int type;
   char rtype;
   struct fref_t *next;
};

struct frefs_t {
   uint32_t num;
   fref_t *list;
};

struct dline_t {
   uint32_t num;
   uint32_t available;
   char *lines;
};

struct sig_t {
   qstring name;
   ea_t startEA;
   ea_t matchedEA;
   int mtype;
   struct sig_t *msig;
   int node;
   int id_crc;
   int nfile;
   int type;
   int flag;
   uint32_t sig;
   uint32_t hash;
   uint32_t hash2;
   uint32_t crc_hash;
   uint32_t str_hash;
   uint32_t lines;
   frefs_t *prefs;
   frefs_t *srefs;
   clist_t *cp;
   clist_t *cs;
   dline_t dl;

   sig_t();
   ~sig_t();

   int save(FILE *fp);
   ea_t get_start();
   void set_nfile(int);
   void set_matched_sig(sig_t *, int);
   sig_t *get_matched_sig();
   void set_matched_ea(ea_t);
   ea_t get_matched_ea();
   int get_matched_type();
   frefs_t *get_preds();
   frefs_t *get_succs();
   int add_pref(ea_t, int, char);
   int add_sref(ea_t, int, char);
   clist_t *get_crefs(int);
   void set_crefs(int, clist_t *);
   int add_address(short opcodes[256], ea_t ea, bool b, bool line, char options);
   int add_block(short *, ea_t, ea_t, bool, char);
   void set_start(ea_t);
   void set_name(const char *);
   void set_name(const qstring &);
   int calc_sighash(short *, int);
   bool is_class();
   void load_prefs(FILE *fp, int type);
   bool is_jump(ea_t ea, bool *call, bool *cj);
};

struct slist_t {
   uint32_t num;
   uint32_t org_num;
   const char *file;
   bool dclk;
   graph_viewer_t *gv;
   bool unique;
   slist_t *msl;
   sig_t **sigs;

   slist_t(const char *file);
   slist_t(uint32_t num, const char *file);
   ~slist_t();

   bool init(uint32_t num, const char *file);

   void free_sigs();
   int save(const char *);
   bool realloc(uint32_t);
   void add(sig_t *);
   void remove(uint32_t);
   void sort();
   uint32_t getnum() {return num;};
};

int OS_CDECL sig_compare(const void *, const void *);

char *pget_func_name(ea_t, char *, size_t);

sig_t *sig_class_generate(ea_t);
sig_t *sig_generate(size_t, qvector<ea_t> &);

#endif
