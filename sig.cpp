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
#include "x86.h"
#include "ppc.h"
#include "patchdiff.h"
#include "pchart.h"
#include "os.h"

extern cpu_t patchdiff_cpu;

/*------------------------------------------------*/
/* function : pget_func_name                      */
/* description: Gets function name                */
/*------------------------------------------------*/

char *pget_func_name(ea_t ea, char * buffer, size_t blen) {
   char * pos;

#if IDA_SDK_VERSION <= 670
   char tmp[512];
   if (!get_func_name(ea, buffer, blen)) {
      return NULL;
   }
   // make sure this is not a c++ class/struct badly defined as a function
   demangle_name(tmp, blen, buffer, inf.long_demnames);
   if ( (strstr(tmp, "public: static") || strstr(tmp, "private: static")) &&
      (!strstr(tmp, "(") || strstr(tmp, "public: static long (__stdcall")) ) {
      return NULL;
   }
   demangle_name(buffer, blen, buffer, inf.short_demnames);
#else
   qstring name;
   qstring demangled;
   int32 dm_res;
   if (get_func_name2(&name, ea) == 0) {
      return NULL;
   }
   qstrncpy(buffer, name.c_str(), blen);
#if IDA_SDK_VERSION < 730
   uint32 long_demnames = inf.long_demnames;
#else
   uint32 long_demnames = inf_get_long_demnames();
#endif
   dm_res = demangle_name2(&demangled, name.c_str(), long_demnames);
   if (dm_res >= 0) {
      if ( (demangled.find("public: static") != -1 || demangled.find("private: static") != -1) &&
         (demangled.find("(") == -1 || demangled.find("public: static long (__stdcall") == -1) ) {
          return NULL;
      }
#if IDA_SDK_VERSION < 730
      uint32 short_demnames = inf.short_demnames;
#else
      uint32 short_demnames = inf_get_short_demnames();
#endif
      dm_res = demangle_name2(&demangled, name.c_str(), short_demnames);
      qstrncpy(buffer, demangled.c_str(), blen);
   }
#endif

   // remove duplicates of the same name
   pos = strstr(buffer, "Z$0");
   if (pos) {
      pos[0] = '\0';
   }
   return buffer;
}

/*------------------------------------------------*/
/* function : sig_t::sig_t()                      */
/* description: Allocates and initializes a new   */
/*              function signature                */
/*------------------------------------------------*/

sig_t::sig_t() {
   memset(this, 0, sizeof(sig_t));

   mtype = DIFF_UNMATCHED;
   msig = NULL;

}

/*------------------------------------------------*/
/* function : frefs_free                          */
/* description: Frees chained list                */
/*------------------------------------------------*/

void frefs_free(frefs_t *frefs) {
   fref_t *fref;
   fref_t *next;

   fref = frefs->list;
   while (fref) {
      next = fref->next;
      delete fref;
      fref = next;
   }

   delete frefs;
}

/*------------------------------------------------*/
/* function : ~dpsig_t                           */
/* description: Frees chained list                */
/*------------------------------------------------*/

dpsig_t::~dpsig_t() {
   if (next) {
      delete next;
   }
}

/*------------------------------------------------*/
/* function : sig_t:~sig_t()                            */
/* description: Frees signature                   */
/*------------------------------------------------*/

sig_t::~sig_t() {
   if (dl.lines) {
      delete [] dl.lines;
   }

   if (prefs) {
      frefs_free(prefs);
   }
   if (srefs) {
      frefs_free(srefs);
   }
   if (cp) {
      delete cp;
   }
   if (cs) {
      delete cs;
   }
}

/*------------------------------------------------*/
/* function : sig_set_name                        */
/* description: Sets function signature name      */
/*------------------------------------------------*/

void sig_t::set_name(const char *_name) {
   name = _name;
}

void sig_t::set_name(const qstring &_name) {
   name = _name;
}

/*------------------------------------------------*/
/* function : sig_set_start                       */
/* description: Sets function start address       */
/*------------------------------------------------*/

void sig_t::set_start(ea_t ea) {
   startEA = ea;
}

/*------------------------------------------------*/
/* function : sig_get_start                       */
/* description: Returns function start address    */
/*------------------------------------------------*/

ea_t sig_t::get_start() {
   return startEA;
}

/*------------------------------------------------*/
/* function : sig_get_preds                       */
/* description: Returns signature pred xrefs      */
/*------------------------------------------------*/

frefs_t *sig_t::get_preds() {
   return prefs;
}

/*------------------------------------------------*/
/* function : sig_get_succs                       */
/* description: Returns signature succ xrefs      */
/*------------------------------------------------*/

frefs_t *sig_t::get_succs() {
   return srefs;
}

/*------------------------------------------------*/
/* function : sig_get_crefs                       */
/* description: Returns signature cxrefs          */
/*------------------------------------------------*/

clist_t *sig_t::get_crefs(int _type) {
   if (_type == SIG_PRED) {
      return cp;
   }
   if (_type == SIG_SUCC) {
      return cs;
   }
   return NULL;
}

/*------------------------------------------------*/
/* function : sig_set_crefs                       */
/* description: Sets signature cxrefs             */
/*------------------------------------------------*/

void sig_t::set_crefs(int _type, clist_t *_cl) {
   if (_type == SIG_PRED) {
      cp = _cl;
   }
   else if (_type == SIG_SUCC) {
      cs = _cl;
   }
}

/*------------------------------------------------*/
/* function : sig_set_nfile                       */
/* description: Sets file number                  */
/*------------------------------------------------*/

void sig_t::set_nfile(int _num) {
   nfile = _num;
}

/*------------------------------------------------*/
/* function : sig_set_matched_sig                 */
/* description: Sets matched address              */
/*------------------------------------------------*/

void sig_t::set_matched_sig(sig_t *_sig2, int _type) {
   msig = _sig2;
   matchedEA = _sig2->startEA;

   _sig2->msig = this;
   _sig2->matchedEA = startEA;

   mtype = _sig2->mtype = _type;

   if (crc_hash != _sig2->crc_hash)
      id_crc = _sig2->id_crc = 1;
}

/*------------------------------------------------*/
/* function : sig_get_matched_sig                 */
/* description: Returns matched address           */
/*------------------------------------------------*/

sig_t *sig_t::get_matched_sig() {
   return msig;
}

/*------------------------------------------------*/
/* function : sig_get_matched_type                */
/* description: Returns matched type              */
/*------------------------------------------------*/

int sig_t::get_matched_type() {
   return mtype;
}

/*------------------------------------------------*/
/* function : sig_add_fref                        */
/* description: Adds a function reference to the  */
/*              signature                         */
/*------------------------------------------------*/

int sig_add_fref(frefs_t **frefs, ea_t ea, int type, char rtype) {
   fref_t *ref;
   fref_t *next;

   if (!*frefs) {
      *frefs = new frefs_t();
      if (!*frefs) {
         return -1;
      }
      memset(*frefs, 0, sizeof(**frefs));
   }
   else {
      //don't add duplicates
      next = (*frefs)->list;
      while (next) {
         if (next->ea == ea) {
            return -1;
         }
         next = next->next;
      }
   }

   ref = new fref_t();
   if (!ref) {
      return -1;
   }
   ref->ea = ea;
   ref->type = type;
   ref->rtype = rtype;
   ref->next = (*frefs)->list;

   (*frefs)->num++;
   (*frefs)->list = ref;

   return 0;
}

/*------------------------------------------------*/
/* function : sig_add_pref                        */
/* description: Adds a function reference to the  */
/*              signature                         */
/*------------------------------------------------*/

int sig_t::add_pref(ea_t _ea, int _type, char _rtype) {
   return sig_add_fref(&prefs, _ea, _type, _rtype);
}

/*------------------------------------------------*/
/* function : sig_add_sref                        */
/* description: Adds a function reference to the  */
/*              signature                         */
/*------------------------------------------------*/

int sig_t::add_sref(ea_t _ea, int _type, char _rtype) {
   return sig_add_fref(&srefs, _ea, _type, _rtype);
}

/*------------------------------------------------*/
/* function : is_fake_jump                        */
/* description: Returns TRUE if the instruction at*/
/*              ea is a jump                      */
/*------------------------------------------------*/

bool is_fake_jump(ea_t ea) {
   switch (patchdiff_cpu) {
   case CPU_X8632:
   case CPU_X8664:
      if (x86_get_fake_jump(ea) != BADADDR) {
         return true;
      }
   default:
      return false;
   }
}

/*------------------------------------------------*/
/* function : ignore_jump                         */
/* description: Returns TRUE if the instruction at*/
/*              ea is a jump that must be ignored */
/*              in the signature                  */
/*------------------------------------------------*/

bool ignore_jump(ea_t ea) {
   switch(patchdiff_cpu) {
   case CPU_X8632:
   case CPU_X8664:
      if (!x86_is_direct_jump(ea)) {
         return false;
      }
   default:
      return true;
   }
}

/*------------------------------------------------*/
/* function : is_jump                             */
/* description: Returns TRUE if the instruction at*/
/*              ea is a jump                      */
/*------------------------------------------------*/

bool sig_t::is_jump(ea_t _ea, bool *_call, bool *_cj) {
   xrefblk_t _xb;
   cref_t _cr;

   *_call = false;
   *_cj = false;

   if (_xb.first_from(_ea, XREF_FAR)) {
      _cr = (cref_t)_xb.type;
      if (_xb.iscode && (_cr == fl_JF || _cr == fl_JN)) {
         if (ignore_jump(_ea)) {
            return true;
         }
         else {
            *_cj = true;
         }
      }

      if (_xb.iscode && (_cr == fl_CF || _cr == fl_CN)) {
         if (type == 1) {
            add_sref(_xb.to, 0, CHECK_REF);
         }
         *_call = true;
      }
   }
   else {
      return is_fake_jump(_ea);
   }
   return false;
}

/*------------------------------------------------*/
/* function : remove_instr                        */
/* description: Returns TRUE if the instruction at*/
/*              ea must not be added to the sig   */
/*------------------------------------------------*/

bool remove_instr(unsigned char byte, ea_t ea) {
   switch (patchdiff_cpu) {
   case CPU_X8632:
   case CPU_X8664:
      return x86_remove_instr(byte, ea);
   case CPU_PPC:
      return ppc_remove_instr(byte, ea);
   default:
      return false;
   }
}

/*------------------------------------------------*/
/* function : get_byte_with_optimization          */
/* description: Returns byte at address ea        */
/* note: Uses the processor optimized function if */
/*       available                                */
/*------------------------------------------------*/

char get_byte_with_optimization(ea_t ea) {
   switch (patchdiff_cpu) {
   case CPU_X8632:
   case CPU_X8664:
      return x86_get_byte(ea);
   case CPU_PPC:
      return ppc_get_byte(ea);
   default: {
#if IDA_SDK_VERSION >= 700
         insn_t cmd;
         decode_insn(&cmd, ea);
#else
         decode_insn(ea);
#endif
         return (char)cmd.itype;
      }
   }
}

unsigned long ror(unsigned long val, int r) {
   return (val >> r) | (val << (32-r));
}

/*------------------------------------------------*/
/* function : dline_add                           */
/* description: Adds a disassembled line to the   */
/*              signature                         */
/*------------------------------------------------*/
#if IDA_SDK_VERSION < 700
int dline_add(dline_t *dl, ea_t ea, char options) {
   char buf[256];
   char tmp[256];
   char dis[256];
   char addr[30];
   int len;
   flags_t f;

   buf[0] = '\0';

   f = getFlags(ea);
   generate_disasm_line(ea, dis, sizeof(dis));

   decode_insn(ea);
   init_output_buffer(buf, sizeof(buf));

   // Adds block label
   if (has_dummy_name(f)) {
      get_nice_colored_name(ea, tmp, sizeof(tmp), GNCN_NOSEG | GNCN_NOFUNC);
      out_snprintf("%s", tmp);
      out_line(":\n", COLOR_DATNAME);
   }

   if (options) {
      qsnprintf(addr, sizeof(addr), "%a", ea);
      out_snprintf("%s ", addr);
   }

   out_insert(get_output_ptr(), dis);
   term_output_buffer();

   len = strlen(buf);

   if (dl->available < (len + 3)) {
      char *dll = new char[dl->num + len + 256];
      if (!dll) {
         return -1;
      }
      if (dl->lines) {
         memcpy(dll, dl->lines, dl->num);
         delete dl->lines;
      }
      dl->available = len + 256;
      dl->lines = dll;
   }

   if (dl->num) {
      dl->lines[dl->num] = '\n';
      dl->num++;
   }

   memcpy(&dl->lines[dl->num], buf, len);

   dl->available -= len + 1;
   dl->num += len;

   dl->lines[dl->num] = '\0';

   return 0;
}
#else
int dline_add(dline_t *dl, ea_t ea, char options) {
   qstring dis;
   insn_t cmd;
   qstring tmp;
   int len;
   flags_t f;

   f = get_flags(ea);
   generate_disasm_line(&dis, ea);

   decode_insn(&cmd, ea);
   outctx_base_t *pctx = create_outctx(ea);

   // Adds block label
   if (has_dummy_name(f)) {
      get_nice_colored_name(&tmp, ea, GNCN_NOSEG | GNCN_NOFUNC);
      pctx->out_printf("%s", tmp.c_str());
      pctx->out_line(":\n", COLOR_DATNAME);
   }

   if (options) {
      pctx->out_printf("%a ", ea);
   }

   pctx->out_printf("%s", dis.c_str());

   len = pctx->outbuf.length();

   if (dl->available < (len + 3)) {
      char *dll = new char[dl->num + len + 256];
      if (!dll) {
         return -1;
      }
      if (dl->lines) {
         memcpy(dll, dl->lines, dl->num);
         delete dl->lines;
      }
      dl->available = len + 256;
      dl->lines = dll;
   }

   if (dl->num) {
      dl->lines[dl->num] = '\n';
      dl->num++;
   }

   memcpy(&dl->lines[dl->num], pctx->outbuf.c_str(), len);

   dl->available -= len + 1;
   dl->num += len;

   dl->lines[dl->num] = '\0';

   delete pctx;
   return 0;
}
#endif

/*------------------------------------------------*/
/* function : sig_add_address                     */
/* description: Adds an address to the signature  */
/*------------------------------------------------*/

int sig_t::add_address(short opcodes[256], ea_t _ea, bool _b, bool _line, char _options) {
   unsigned char _byte;
   unsigned char _buf[200];
   uint32_t _s, _i;
   bool _call;
   bool _cj;
   ea_t _tea;
   flags_t _f;

   if (_line) {
      dline_add(&dl, _ea, _options);
   }
   if (is_jump(_ea, &_call, &_cj)) {
      return -1;
   }
   _byte = get_byte_with_optimization(_ea);

   if (remove_instr(_byte, _ea)) {
      return -1;
   }
   lines++;
   opcodes[_byte]++;

   if (!_b && !_call) {
      if (_cj) {
         _buf[0] = _byte;
         _s = 1;
      }
      else {
         _s = (uint32_t)get_item_size(_ea);
         if (_s > sizeof(_buf)) {
            _s = sizeof(_buf);
         }
         get_many_bytes(_ea, _buf, _s);
      }

      for (_i = 0; _i < _s; _i++) {
         crc_hash += _buf[_i];
         crc_hash += ( crc_hash << 10 );
         crc_hash ^= ( crc_hash >> 6 );
      }
   }
   else if (_b) {
      _tea = get_first_dref_from(_ea);
      if (_tea != BADADDR) {
         _f = getFlags(_tea);
         if (isASCII(_f)) {
            opinfo_t _op_info;
#if IDA_SDK_VERSION < 700
            get_opinfo(_tea, 0, _f, &_op_info);
#else
            get_opinfo(&_op_info, _tea, 0, _f);
#endif
            _s = get_max_ascii_length(_tea, _op_info.strtype);
#if IDA_SDK_VERSION < 700
            if (!get_ascii_contents2(_tea, _s, _op_info.strtype, _buf, sizeof(_buf))) {
               _s = sizeof(_buf);
            }
            for (_i = 0; _i < _s; _i++) {
               str_hash += _buf[_i] * _i;
            }
#else
            qstring _strlit;
            _s = get_strlit_contents(&_strlit, _tea, _s, _op_info.strtype);
            //the following attempts to match behavior of pre-7.0 patchdiff
            if (_s > sizeof(_buf)) {
               _s = sizeof(_buf);
            }
            for (_i = 0; _i < _s; _i++) {
               str_hash += _strlit[_i] * _i;
            }
#endif
         }
      }
   }

   return 0;
}

/*------------------------------------------------*/
/* function : sig_add_block                       */
/* description: Adds a block to the signature     */
/*------------------------------------------------*/

int sig_t::add_block(short _opcodes[256], ea_t _startEA, ea_t _endEA, bool _line, char _options) {
   ea_t _ea = _startEA;

   while (_ea < _endEA) {
      flags_t _flags = getFlags (_ea);
      if (!isCode (_flags)) {
         return -1;
      }
      bool _b = get_first_dref_from(_ea) != BADADDR ? true : false;
      add_address(_opcodes, _ea, isOff(_flags, OPND_ALL) || _b, _line, _options);

      _ea += get_item_size(_ea);
   }

   return 0;
}

int OS_CDECL compare(const void *arg1, const void *arg2) {
   return *((short *)arg1) - *((short *)arg2);
}

/*------------------------------------------------*/
/* function : sig_calc_sighash                    */
/* description: generates a sig/hash for the      */
/*              signature opcodes                 */
/*------------------------------------------------*/

int sig_t::calc_sighash(short _opcodes[256], int _do_sig) {
   short _tmp;
   short opcodes[256];
   int _i, _j;

   memcpy(opcodes, _opcodes, sizeof(opcodes));
   qsort(opcodes, 256, sizeof(short), compare);

   for (_i = 0; _i < 256; _i++) {
      for (_j = 0; _j < 255; _j++) {
         if (opcodes[_j] > opcodes[_j + 1]) {
            _tmp = opcodes[_j + 1];
            opcodes[_j + 1] = opcodes[_j];
            opcodes[_j] = _tmp;
         }
      }
   }

   hash2 = 0;
   if (_do_sig) {
      sig = 0;
   }
   for (_i = 0; _i < 256; _i++) {
      if (_do_sig) {
         sig += opcodes[_i] * _i;
      }
      hash2 = ror(hash2, 13);
      hash2 += _opcodes[_i];
   }

   return 0;
}

/*------------------------------------------------*/
/* function : parse_dref_list                     */
/* description: checks if the data ref is a class */
/*              like structure. Returns class ea  */
/*              on success                        */
/*------------------------------------------------*/

ea_t parse_dref_list(ea_t _ea) {
   ea_t _fref;
   flags_t _f;

   // scan up
   do {
      _fref = get_first_dref_from(_ea);
      if (_fref == BADADDR) {
         return BADADDR;
      }
      _f = getFlags(_fref);
      if (!isCode(_f)) {
         return BADADDR;
      }
      _fref = get_first_dref_to(_ea);
      if (_fref != BADADDR) {
         _f = getFlags(_fref);
         if (!isCode(_f)) {
            return BADADDR;
         }
         return _ea;
      }

      _ea = prev_visea(_ea);
   } while(_ea != BADADDR);

   return _ea;
}

/*------------------------------------------------*/
/* function : sig_is_class                        */
/* description: Returns true is the signature is  */
/*              a class                           */
/*------------------------------------------------*/

bool sig_t::is_class() {
   if (sig == CLASS_SIG && hash == CLASS_SIG && crc_hash == CLASS_SIG) {
      return true;
   }
   return false;
}

/*------------------------------------------------*/
/* function : sig_class_generate                  */
/* description: generates a signature for the     */
/*              class structure                   */
/*------------------------------------------------*/

sig_t *sig_class_generate(ea_t ea) {
   func_t *xfct;
   sig_t *sig;
   ea_t fref;

   sig = new sig_t();
   if (!sig) {
      return NULL;
   }
   // Adds function start address
   sig->set_start(ea);

   // Adds function name
   sig->name.sprnt("sub_%a", ea);

   // Adds class references
   fref = get_first_dref_to(ea);
   while (fref != BADADDR) {
      xfct = get_func(fref);
      if (xfct) {
         sig->add_sref(xfct->startEA, 0, CHECK_REF);
      }
      fref = get_next_dref_to(ea, fref);
   }

   sig->hash = sig->crc_hash = sig->sig = CLASS_SIG;

   return sig;
}

/*------------------------------------------------*/
/* function : sig_generate                        */
/* description: generates a signature for the     */
/*              given function                    */
/*------------------------------------------------*/

sig_t *sig_generate(size_t fct_num, qvector<ea_t> &class_l) {
   func_t *fct, *xfct;
   pflow_chart_t *fchart;
   sig_t *sig;
   ea_t fref, ea;
   int bnum, i;
   char buf[512];
   short opcodes[256];
   qvector<int> call_list;
   flags_t f;

   fct = getn_func(fct_num);

   memset(opcodes, '\0', sizeof(opcodes));
   fchart = new pflow_chart_t(fct);
   sig = new sig_t();
   if (!sig) {
      delete fchart;
      return NULL;
   }

   sig->type = 1;

   // Adds function start address
   sig->set_start(fct->startEA);

   // Adds function name
   if (pget_func_name(fct->startEA, buf, sizeof(buf))) {
      sig->set_name(buf);
   }
   else {
      return NULL;
   }
   // Adds function references

   fref = get_first_dref_to(fct->startEA);

   while (fref != BADADDR) {
      f = getFlags(fref);
      if (isCode(f)) {
         xfct = get_func(fref);
         if (xfct && xfct->startEA != fct->startEA) {
            sig->add_pref(xfct->startEA, 0, CHECK_REF);
         }
      }
      else {
         ea = parse_dref_list(fref);
         if (ea != BADADDR) {
            sig->add_pref(ea, 0, CHECK_REF);
            class_l.add_unique(ea);
         }
      }

      fref = get_next_dref_to(fct->startEA, fref);
   }

   // Adds each block to the signature
   bnum = fchart->nproper;

   sig->hash = 0;
   sig->sig = 0;

   for (i = 0; i < bnum; i++) {
      int j;
      int ttype;
      int smax = fchart->nsucc(i);
      sig->sig += (i + 1) + smax * i;

      sig->add_block(opcodes, fchart->blocks[i].startEA, fchart->blocks[i].endEA, 0, 0);
      for (j = 0; j < smax; j++) {
         sig->hash = ror(sig->hash, 13);
         ttype = fchart->blocks[i].succ[j].type;
         if (ttype == 2) {
            ttype--;
         }
         sig->hash += ttype;
      }
   }

   sig->calc_sighash(opcodes, 0);

   delete fchart;

   return sig;
}

/*------------------------------------------------*/
/* function : sig_save                            */
/* description: Saves signature refs to disk   */
/*------------------------------------------------*/

void sig_save_refs(FILE *fp, frefs_t *refs) {
   uint32_t num, i;
   fref_t *tmp;

   if (refs) {
      num = refs->num;
      qfwrite(fp, &num, sizeof(num));
      tmp = refs->list;
      for (i = 0; i < num; i++) {
         qfwrite(fp, &tmp->ea, sizeof(tmp->ea));
         qfwrite(fp, &tmp->type, sizeof(tmp->type));
         tmp = tmp->next;
      }
   }
   else {
      num = 0;
      qfwrite(fp, &num, sizeof(num));
   }
}

/*------------------------------------------------*/
/* function : sig_t::save                         */
/* description: Saves signature to disk           */
/*------------------------------------------------*/

int sig_t::save(FILE *_fp) {
   uint32_t _len;

   // saves function name
   _len = name.length();
   qfwrite(_fp, &_len, sizeof(_len));
   qfwrite(_fp, name.c_str(), _len);

   // saves function start address
   qfwrite(_fp, &startEA, sizeof(startEA));

   // saves function lines
   qfwrite(_fp, &dl.num, sizeof(dl.num));
   qfwrite(_fp, dl.lines, dl.num);

   // saves sig/hash
   qfwrite(_fp, &sig, sizeof(sig));
   qfwrite(_fp, &hash, sizeof(hash));
   qfwrite(_fp, &hash2, sizeof(hash2));
   qfwrite(_fp, &crc_hash, sizeof(crc_hash));
   qfwrite(_fp, &str_hash, sizeof(str_hash));

   // saves function refs
   sig_save_refs(_fp, prefs);
   sig_save_refs(_fp, srefs);

   return 0;
}

/*------------------------------------------------*/
/* function : sig_load_prefs                      */
/* description: Loads signature  refs from disk   */
/*------------------------------------------------*/

void sig_t::load_prefs(FILE *_fp, int _type) {
   uint32_t _num, _i;
   pedge_t *_eatab;

   // loads function refs in reverse order
   qfread(_fp, &_num, sizeof(_num));
   _eatab = new pedge_t[_num];

   for (_i = 0; _i < _num; _i++) {
      qfread(_fp, &_eatab[_i].ea, sizeof(_eatab[_i].ea));
      qfread(_fp, &_eatab[_i].type, sizeof(_eatab[_i].type));
   }

   for (_i = _num; _i > 0; _i--) {
      if (_type == SIG_PRED) {
         add_pref(_eatab[_i - 1].ea, _eatab[_i - 1].type, CHECK_REF);
      }
      else {
         add_sref(_eatab[_i - 1].ea, _eatab[_i - 1].type, CHECK_REF);
      }
   }

   delete [] _eatab;
}

/*------------------------------------------------*/
/* function : sig_load                            */
/* description: Loads signature from disk         */
/*------------------------------------------------*/

sig_t *sig_load(FILE *fp) {
   uint32_t len;
   sig_t * sig;
   char buf[512];

   sig = new sig_t();
   if (!sig) {
      return NULL;
   }
   // loads function name
   qfread(fp, &len, sizeof(len));
   qfread(fp, buf, len);
   buf[len] = '\0';

   sig->set_name(buf);

   // loads function start address
   qfread(fp, &sig->startEA, sizeof(sig->startEA));

   // loads function line
   qfread(fp, &sig->dl.num, sizeof(sig->dl.num));
   sig->dl.lines = new char[sig->dl.num + 1];
   if (sig->dl.lines) {
      qfread(fp, sig->dl.lines, sig->dl.num);
      sig->dl.lines[sig->dl.num] = '\0';
   }
   else {
      sig->dl.num = 0;
   }

   // loads sig/hash
   qfread(fp, &sig->sig, sizeof(sig->sig));
   qfread(fp, &sig->hash, sizeof(sig->hash));
   qfread(fp, &sig->hash2, sizeof(sig->hash2));
   qfread(fp, &sig->crc_hash, sizeof(sig->crc_hash));
   qfread(fp, &sig->str_hash, sizeof(sig->str_hash));

   // loads sig refs
   sig->load_prefs(fp, SIG_PRED);
   sig->load_prefs(fp, SIG_SUCC);

   return sig;
}

/*------------------------------------------------*/
/* function : slist_t()                           */
/* description: Initializes a new signature list  */
/*------------------------------------------------*/

bool slist_t::init(uint32_t initial_num, const char *file) {
   this->file = file;
   num = 0;
   org_num = initial_num;
   sigs = new sig_t *[initial_num];

   if (!sigs && org_num != 0) {
      return false;
   }
   return true;
}

slist_t::slist_t(uint32_t num, const char *file) {
   init(num, file);
}

/*------------------------------------------------*/
/* function : slist_t::realloc                     */
/* description: Realloc a signature list          */
/*------------------------------------------------*/

bool slist_t::realloc(uint32_t new_num) {
   sig_t **new_sigs = new sig_t *[org_num + new_num];
   if (!new_sigs) {
      return false;
   }
   if (sigs) {
      memcpy(new_sigs, sigs, org_num * sizeof(sig_t*));
      delete sigs;
   }
   org_num += new_num;
   sigs = new_sigs;

   return true;
}

/*------------------------------------------------*/
/* function : sig_compare                         */
/* description: Compares two signature            */
/*------------------------------------------------*/

int OS_CDECL sig_compare(const void *arg1, const void *arg2) {
   unsigned long v1, v2;

   v1 = (*(sig_t **)arg1)->sig;
   v2 = (*(sig_t **)arg2)->sig;

   if (v2 > v1) {
      return 1;
   }
   if (v2 < v1) {
      return -1;
   }
   v1 = (*(sig_t **)arg1)->hash;
   v2 = (*(sig_t **)arg2)->hash;

   if (v2 > v1) {
      return 1;
   }
   if (v2 < v1) {
      return -1;
   }
   v1 = (*(sig_t **)arg1)->crc_hash;
   v2 = (*(sig_t **)arg2)->crc_hash;

   if (v2 > v1) {
      return 1;
   }
   if (v2 < v1) {
      return -1;
   }
   v1 = (*(sig_t **)arg1)->str_hash;
   v2 = (*(sig_t **)arg2)->str_hash;

   if (v2 > v1) {
      return 1;
   }
   if (v2 < v1) {
      return -1;
   }
   return 0;
}

/*------------------------------------------------*/
/* function : slist_t::sort                        */
/* description: Sorts the signature to the list   */
/*------------------------------------------------*/

void slist_t::sort() {
   qsort(sigs, num, sizeof(*sigs), sig_compare);
}

/*------------------------------------------------*/
/* function : slist_t::add                         */
/* description: Adds a new signature to the list  */
/*------------------------------------------------*/

void slist_t::add(sig_t *sig) {
   if (num >= org_num) {
      if (!realloc(32)) {
         return;
      }
   }

   sig->node = num;
   sigs[num++] = sig;
}

/*------------------------------------------------*/
/* function : slist_t::remove                      */
/* description: Removes a new signature to the    */
/*              list                              */
/*------------------------------------------------*/

void slist_t::remove(uint32_t n) {
   if ( (n+1) < num ) {
      memmove(&sigs[n], &sigs[n+1], ((num - 1) - n) * sizeof(*(sigs)));
   }
   num--;
}

/*------------------------------------------------*/
/* function : slist_t::~slist_t                   */
/* description: Frees a new signature list        */
/*------------------------------------------------*/

slist_t::~slist_t() {
   delete [] sigs;
}

/*------------------------------------------------*/
/* function : slist_t::free_sigs                  */
/* description: Frees a new signature list        */
/*------------------------------------------------*/

void slist_t::free_sigs() {
   for (uint32_t i = 0; i < num; i++) {
      delete sigs[i];
   }
}

/*------------------------------------------------*/
/* function : slist_t::save                        */
/* description: Saves signature list to disk      */
/*------------------------------------------------*/

int slist_t::save(const char *filename) {
   FILE * fp;
   uint32_t i;

   fp = qfopen(filename, "wb+");
   if (fp == NULL) {
      return -1;
   }
   qfwrite(fp, &num, sizeof(num));

   for (i = 0; i < num; i++) {
      sigs[i]->save(fp);
   }
   qfclose(fp);

   return 0;
}

/*------------------------------------------------*/
/* function : slist_t()                           */
/* description: Loads signature list from disk    */
/*------------------------------------------------*/

slist_t::slist_t(const char *filename) {
   uint32_t init_num;

   num = 0;
   org_num = 0;
   file = NULL;
   dclk = false;
   gv = NULL;
   unique = false;
   msl = NULL;
   sigs = NULL;

   FILE *fp = qfopen(filename, "rb");
   if (fp == NULL) {
      msg("slist_t::load: qfopen('%s', 'rb') failed\n", filename);
   }
   if (qfread(fp, &init_num, sizeof(init_num)) != sizeof(init_num)) {
      msg("slist_t::load: qfread(...) failed\n");
      qfclose(fp);
      return;
   }

   if (init(init_num, NULL)) {

      for (uint32_t i = 0; i < init_num; i++) {
         add(sig_load(fp));
      }

      sort();
   }

   qfclose(fp);

}

