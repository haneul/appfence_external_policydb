/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Contains the policy database interface used only by the
 * policyd server; all of this should be invisible to the "client"
 * apps.
 */

#ifndef POLICYDB_H
#define POLICYDB_H

#include <sys/types.h>

/* From dalvik/vm/Common.h: */
/*
 * The <stdbool.h> definition uses _Bool, a type known to the compiler.
 */
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>   /* C99 */
#else
# ifndef __bool_true_false_are_defined
typedef enum { false=0, true=!false } bool;
# define __bool_true_false_are_defined 1
# endif
#endif
///*          
// * These match the definitions in the VM specification.
// */
//#ifdef HAVE_STDINT_H
//# include <stdint.h>    /* C99 */
//typedef uint8_t             u1;
//typedef uint16_t            u2;
//typedef uint32_t            u4; 
//typedef uint64_t            u8;
//typedef int8_t              s1;
//typedef int16_t             s2;
//typedef int32_t             s4;
//typedef int64_t             s8;
//#else   
//typedef unsigned char       u1;
//typedef unsigned short      u2;
//typedef unsigned int        u4;
//typedef unsigned long long  u8;
//typedef signed char         s1;
//typedef signed short        s2;
//typedef signed int          s4;
//typedef signed long long    s8;
//#endif

bool doesPolicyAllow(const char *processName, const char *destName, int tag);

#endif
