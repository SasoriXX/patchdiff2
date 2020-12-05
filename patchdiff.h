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

#ifndef __PATCHDIFF_H__
#define __PATCHDIFF_H__

enum cpu_t {
   CPU_DEFAULT,
   CPU_X8632,
   CPU_X8664,
   CPU_PPC,
   CPU_PPC64,
   CPU_MIPS,
   CPU_MIPS64,
   CPU_ARM,
   CPU_AARCH64
};

#endif
