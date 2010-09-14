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

#ifndef POLICYDB_H
#define POLICYDB_H

#include <sqlite3.h>
//#include <cutils/log.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

//#define LOG_TAG "policydb"

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

/**
 * Persistent variables for storing SQLite database connection, etc.
 */
const char *dbFilename = ":memory:";
//const char *dbFilename = "/data/data/com.android.browser/policy.db";
//const char *dbFilename = "/data/data/com.android.browser/databases/policy.db";
  //"Once created, the SQLite database is stored in the
  // /data/data/<package_name>/databases folder of an Android device"
  //"/data/policyDb" doesn't work, just creates an empty file
  //  neither does "/data/data/com.android.settings/shared_prefs/policy.db"
  //Any "scratch" locations where all apps have write access? Not really...
  //  /sqlite_stmt_journals
  //Shouldn't be any locations where all apps have write access, because
  //otherwise apps could use it for unprotected IPC.
  //Solution: need to move this code to a _centralized_ location!
  //  Context: needs to be "system" or "root" user, not "app_5", etc.
const char *dbTableName = "policy";
static sqlite3 *policyDb = NULL;
//sqlite3 *policyDb = NULL;
  //XXX: make this static???
static bool policyHasChanged = false;
  //XXX: make this static? Yes: only the first app that gets to it needs
  //  to update the database
  //  But need to add a LOCK!!! XXX
static bool defaultAllow = true;        //XXX: set this from global prefs!
sqlite3_stmt *queryStmt = NULL;
  //Ok to not be static: holds the current/previous query statement for
  //  each app?

/* These constants define table structure/columns: */
enum dbColumns {    //must start at 0 for indexing into database!
    SRC = 0,        //SQLITE_TEXT
    DEST,           //SQLITE_TEXT
    TAINT,          //SQLITE_INTEGER
    COLUMNS         //must always be last!!!
};

bool doesPolicyAllow(const char *processName, const char *destName, int tag);

#endif
