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

#include "policydb.h"
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <cutils/log.h>
#include <policy_global.h>

/* Enable this to run some debugging code. The debugging code should have no
 * side-effects at all anyway though. */
#define TESTCODE

#ifdef LOG_TAG
#undef LOG_TAG
#define LOG_TAG "policydb"
#endif

/**
 * From dalvik/vm/Common.h:
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

/**
 * Persistent variables for storing SQLite database connection, etc.
 */
const char *db_filename = "/data/data/com.android.settings/policy.db";
//const char *db_filename = ":memory:";
//const char *db_filename = "/data/data/com.android.browser/policy.db";
//const char *db_filename = "/data/data/com.android.browser/databases/policy.db";
  //"Once created, the SQLite database is stored in the
  // /data/data/<package_name>/databases folder of an Android device"
  //"/data/policyDb" doesn't work, just creates an empty file
  //  neither does "/data/data/com.android.settings/shared_prefs/policy.db"
  //Any "scratch" locations where all apps have write access? Not really...
  //  /sqlite_stmt_journals
sqlite3 *db_ptr = NULL;
static bool db_default_allow = true;  //XXX: set this from global prefs!
sqlite3_stmt *db_query_stmt = NULL;
  //Ok to not be static: holds the current/previous query statement for
  //  each app?

/**
 * These constants define table structure/columns; all of the dbXyzs
 * should match each other!! (It's too damn hard to dynamically
 * construct the create table string, etc. in C)
 * Used by create_db_table() to create the database table.
 */
const char *db_tablename = "policy";
enum dbCols {    //must start at 0 for indexing into database!
    SRC = 0,        //SQLITE_TEXT
    DEST,           //SQLITE_TEXT
    TAINT,          //SQLITE_INTEGER
    COLUMNS         //must always be last!!!
};
const char *db_col_names[] = {
    "src",
    "dest",
    "taint",
};
const char *db_col_types[] = {
    "TEXT",
    "TEXT",
    "INTEGER",
};
const char *db_createstring =
    "CREATE TABLE policy (src TEXT, dest TEXT, taint INTEGER)";
      //make sure string after TABLE is db_tablename

/**
 * Constructs a query string that gets the records/rows of the database matching
 * the given source application name. Returns pointer to a newly-allocated string
 * (which should be freed by the caller) on success, or returns NULL on failure.
 */
char *construct_querystring(const char *source) {
    int queryLen;
    char *queryString;
    const char *select = "SELECT";
    const char *columns = "*";
    const char *from = "FROM";
    const char *where = "WHERE";
 
    LOGW("phornyac: construct_querystring(): entered");
    /**
     * Construct the SQL query string:
     *   SELECT *
     *     FROM <table_name>
     *     WHERE src='<source>'
     * Wildcards: ??
     * Impt: taint may not match exactly!
     *   So, use the callback function for each gotten record to AND the taint
     *   from the database record with the current data taint! This means that
     *   we will "match" if any bit in current data taint tag matches any bit in
     *   taint tag stored in database.
     *     Do this for destination too???? Yes!
     *       So, just WHERE on the source!
     * http://www.w3schools.com/sql/sql_select.asp
     * http://www.w3schools.com/sql/sql_where.asp
     *   Use single quotes, i.e. SELECT * FROM Persons WHERE FirstName='Tove'
     * http://www.w3schools.com/sql/sql_and_or.asp
     */

    //XXX: should sanitize input to this function, or risk SQL injection attack!

    /**
     * Examples: http://www.sqlite.org/lang_expr.html
     *   SELECT * FROM policy WHERE src='com.android.browser'
     *     Get rows for source app com.android.browser
     *   SELECT * FROM policy WHERE src LIKE '%'
     *     Get all rows
     *   SELECT * FROM policy WHERE src='com.android.browser' OR src='*'
     *     Get rows for source app com.android.browser and for global policy
     *     that applies to all source apps
     */
    queryLen = strlen(select) + strlen(" ") + strlen(columns) + 
        strlen(" ") + strlen(from) +
        strlen(" ") + strlen(db_tablename) + strlen(" ") + strlen(where) +
        strlen(" src=\'") + strlen(source) + strlen("\' OR src=\'*\'") + 1;
    queryString = (char *)malloc(queryLen * sizeof(char));
    snprintf(queryString, queryLen, "%s %s %s %s %s src=\'%s\' OR src=\'*\'",
            select, columns, from, db_tablename, where, source);
    LOGW("phornyac: construct_querystring(): queryLen=%d, queryString=%s",
            queryLen, queryString);
    return queryString;
}

/* Prints the current database row. */
void print_row(sqlite3_stmt *stmt){
    const unsigned char *dbSrc;
    const unsigned char *dbDest;
    int dbTaint;

    /**
     * Get the values from the destination and taint tag columns:
     * http://sqlite.org/c3ref/column_blob.html
     */
    dbSrc = sqlite3_column_text(stmt, SRC);
    dbDest = sqlite3_column_text(stmt, DEST);
    dbTaint = sqlite3_column_int(stmt, TAINT);
 
    LOGW("phornyac: print_row(): dbSrc=%s, dbDest=%s, dbTaint=0x%X",
            dbSrc, dbDest, dbTaint);
}

/**
 * Returns true if the two destination IP addresses match, or if the
 * destination stored in the database row is the wildcard "*".
 * XXX: enhance this function to consider subnets, partial IP addresses /
 *   hostnames, etc.!
 */
bool destination_match(const char *curDest, const char *dbDest) {
    LOGW("phornyac: destination_match: curDest=%s, dbDest=%s",
            curDest, dbDest);
    
    if ((strcmp("*", dbDest) == 0) || (strcmp(curDest, dbDest) == 0)) {
        LOGW("phornyac: destination_match: returning true");
        return true;
    }
    LOGW("phornyac: destination_match: returning false");
    return false;
}

/**
 * Returns true if the two taint tags "match," i.e. if they have any of the same
 * bits set.
 */
bool taint_match(int curTaint, int dbTaint) {
    LOGW("phornyac: taint_match: curTaint=0x%X, dbTaint=0x%X",
            curTaint, dbTaint);
    if (curTaint & dbTaint) {
        LOGW("phornyac: taint_match: returning true");
        return true;
    }
    LOGW("phornyac: taint_match: returning false");
    return false;
}

/**
 * Function that is called for every database record that our query
 * returns. If we select the records based solely on the application name,
 * then this function should return true if the destination server and taint
 * of the data about to be transmitted BOTH match one of the records.
 */
bool check_row_for_match(sqlite3_stmt *db_query_stmt, const char *dest, int taint) {
    const unsigned char *dbDest;
    int dbTaint;

    LOGW("phornyac: check_row_for_match(): entered");

    /**
     * Get the values from the destination and taint tag columns:
     * http://sqlite.org/c3ref/column_blob.html
     */
    dbDest = sqlite3_column_text(db_query_stmt, DEST);
    if (dbDest == NULL) {
        LOGW("phornyac: check_row_for_match(): dbDest got NULL, returning false!");
        return false;
    }
    dbTaint = sqlite3_column_int(db_query_stmt, TAINT);

    /* Return true if BOTH the destinations and the taints match: */
    if (destination_match(dest, (const char *)dbDest) && taint_match(taint, dbTaint)) {
        LOGW("phornyac: check_row_for_match(): returning true");
        return true;
    }
    LOGW("phornyac: check_row_for_match(): returning false");
    return false;
}

/**
 * Adds the given (source, dest, taint) triple to the database table.
 * Returns 0 on success, negative on error.
 */
int insert_row(sqlite3 *db, const char *tableName, const char *source,
        const char *dest, int taint) {
    sqlite3_stmt *insertStmt;
    int len;
    int err;
    char *insertString;
    char taintString[32];
      //2^64 = 18446744073709551616, which is 20 digits

    LOGW("phornyac: insert_row(): entered");

    /**
     * Construct the INSERT string:
     *   INSERT INTO table_name VALUES (source, dest, taint)
     * See http://www.w3schools.com/sql/sql_insert.asp
     * XXX: not safe from injection attack???
     */
    const char *insertInto = "INSERT INTO";
    const char *values = "VALUES";
    /* Convert taint int to string: */
    snprintf(taintString, 32, "%d", taint);
      //Should be a decimal integer going into database, not hex!
    LOGW("phornyac: insert_row(): calculated taintString=%s, len=%d",
            taintString, strlen(taintString));
    len = strlen(insertInto) + strlen(" ") + strlen(tableName) + 
        strlen(" ") + strlen(values) + strlen(" (\'") + strlen(source) +
        strlen("\', \'") + strlen(dest) + strlen("\', \'") + strlen(taintString) +
        strlen("\')") + 1;
    insertString = malloc(len * sizeof(char));
    /* Must use quotes around column values inside () ! */
    snprintf(insertString, len, "%s %s %s (\'%s\', \'%s\', \'%s\')",
            insertInto, tableName, values, source, dest, taintString);
    LOGW("phornyac: insert_row(): constructed insertString=%s", insertString);

    /**
     * Prepare an SQLite statement with the INSERT string:
     * See http://sqlite.org/c3ref/prepare.html
     */
    LOGW("phornyac: insert_row(): calling sqlite3_prepare_v2()");
    err = sqlite3_prepare_v2(db, insertString, len, &insertStmt, NULL);
    free(insertString);
    if (err != SQLITE_OK) {
        LOGW("phornyac: insert_row(): sqlite3_prepare_v2() returned "
                "error: %s", sqlite3_errmsg(db));
        LOGW("phornyac: insert_row(): returning -1 due to errors");
        return -1;
    }

    /**
     * Execute the prepared statement:
     */
    LOGW("phornyac: insert_row(): calling sqlite3_step() to execute "
            "INSERT statement");
    err = sqlite3_step(insertStmt);
    if (err != SQLITE_DONE) {
        LOGW("phornyac: insert_row(): sqlite3_step() returned "
                "error: %s", sqlite3_errmsg(db));
        LOGW("phornyac: insert_row(): returning -1 due to errors");
        sqlite3_finalize(insertStmt);  //ignore return value
        return -1;
    }
 
    /* Finalize and return: */
    LOGW("phornyac: insert_row(): INSERT succeeded, finalizing and returning");
    err = sqlite3_finalize(insertStmt);
    if (err != SQLITE_OK) {
        LOGW("phornyac: insert_row(): sqlite3_finalize() returned "
                "error: %s", sqlite3_errmsg(db));
        LOGW("phornyac: insert_row(): returning -1 due to errors");
        return -1;
    }
    return 0;
}

/**
 * Checks the (source, dest, taint) triple against the currently selected
 * policy.
 * Returns: true if the current policy allows the data to be sent, false if
 *   the current policy denies the transmission or on error.
 */
bool doesPolicyAllow(const char *processName, const char *destName, int tag) {
    char *queryString;
    int queryLen;
    const char *columns="*";
    char *errmsg = NULL;
    bool match;
    bool retval = false;
    int err;
    //DEBUG:
    struct stat dbStat;

    LOGW("phornyac: doesPolicyAllow(): entered");
    LOGW("phornyac: doesPolicyAllow(): processName=%s, destName=%s, tag=0x%X",
            processName, destName, tag);

    /* Use snprintf() to generate db filename? */
    //...

    /**
     * Initialize the database connection if not already done:
     * http://sqlite.org/c3ref/open.html
     */
    if (db_ptr == NULL) {
        LOGW("phornyac: doesPolicyAllow(): db_ptr is NULL, initializing");

        //DEBUG (XXX: remove this):
        LOGW("phornyac: doesPolicyAllow(): calling stat for db_filename=%s",
                db_filename);
        err = stat(db_filename, &dbStat);
        if (err) {
            if (errno == ENOENT) {
                LOGW("phornyac: doesPolicyAllow(): stat returned errno=ENOENT, "
                        "db file does not exist yet");
            } else {
                LOGW("phornyac: doesPolicyAllow(): stat returned other errno=%d",
                        errno);
            }
        } else {
            LOGW("phornyac: doesPolicyAllow(): stat succeeded, db file exists");
        }

        //XXX: figure out if this code is central, or if it's "instantiated"
        //  once per application...
        //Right now, it's instantiated once per application!
        //  Figure out a more central place to put it...
        LOGW("phornyac: doesPolicyAllow(): calling sqlite3_open(%s)",
                db_filename);
        /**
         * The "standard" version of sqlite3_open() opens a database for reading
         * and writing, and creates it if it does not exist.
         * http://sqlite.org/c3ref/open.html
         */
        err = sqlite3_open(db_filename, &db_ptr);
        if ((err != SQLITE_OK) || (db_ptr == NULL)) {
            if (db_ptr == NULL) {
                LOGW("phornyac: doesPolicyAllow(): sqlite3_open() returned "
                        "NULL db_ptr!");
            }
            LOGW("phornyac: doesPolicyAllow(): sqlite3_open() error message: "
                    "%s", sqlite3_errmsg(db_ptr));
            db_ptr = NULL;  /* set back to NULL so we'll retry after error */
            LOGW("phornyac: doesPolicyAllow(): returning false due to errors");
            retval = false;
            goto out;
        }
        LOGW("phornyac: doesPolicyAllow(): sqlite3_open() succeeded, db_ptr=%p",
                db_ptr);
        /* XXX: We never close the database connection: is this ok? */

        /**
         * Create the table:
         * See http://sqlite.org/lang_createtable.html
         * See http://sqlite.org/c3ref/exec.html
         */
        LOGW("phornyac: doesPolicyAllow(): creating table \"%s\"", db_tablename);
        //XXX: un-hard-code this!
        //XXX: put this in a separate function!
        err = sqlite3_exec(db_ptr, "CREATE TABLE policy (src TEXT, dest TEXT, taint INTEGER)",
                NULL, NULL, &errmsg);
        LOGW("phornyac: doesPolicyAllow(): sqlite3_exec() returned");
        if (err) {
            if (errmsg) {
                /**
                 * "To avoid memory leaks, the application should invoke
                 *  sqlite3_free() on error message strings returned through the
                 *  5th parameter of of sqlite3_exec() after the error message
                 *  string is no longer needed. If the 5th parameter to
                 *  sqlite3_exec() is not NULL and no errors occur, then
                 *  sqlite3_exec() sets the pointer in its 5th parameter to NULL
                 *  before returning."
                 */
                LOGW("phornyac: doesPolicyAllow(): sqlite3_exec(CREATE TABLE) "
                        "returned error \"%s\", so returning false", errmsg);
                /**
                 * For some reason, when I open browser, then open maps app, I get this
                 * error from maps:
                 *   "W/dalvikvm(  475): phornyac: doesPolicyAllow(): sqlite3_exec(CREATE
                 *    TABLE) returned error "table policy already exists", so returning
                 *    false
                 * Don't get the error when using in-memory database though
                 *   (db_filename=":memory:")
                 */
                sqlite3_free(errmsg);
            } else {
                LOGW("phornyac: doesPolicyAllow(): sqlite3_exec(CREATE TABLE) "
                        "returned error, errmsg=NULL");
            }
            db_ptr = NULL;  /* set back to NULL so we'll retry after error */
            retval = false;
            goto out;
        }

        /* Add some simple rows to database / table for now: */
        LOGW("phornyac: doesPolicyAllow(): adding sample rows to database");
//XXX: can't do this!
//Copied from dalvik/vm/Common.h:
#ifdef HAVE_STDINT_H
# include <stdint.h>    /* C99 */
typedef uint32_t            u4;
#else
typedef unsigned int        u4;
#endif
//Copied from dalvik/vm/interp/Taint.h:
#define TAINT_LOCATION_GPS  ((u4)0x00000010) /* GPS Location */
        err = insert_row(db_ptr, db_tablename, "*", "*", TAINT_LOCATION_GPS);
        err |= insert_row(db_ptr, db_tablename, "com.android.browser",
                "*", 255);
        err |= insert_row(db_ptr, db_tablename, "com.android.browser",
                "72.14.*", 255);  //255 = 0xff
        //(DEBUG: Get all rows in a table: SELECT * FROM Persons)
        if (err) {
            LOGW("phornyac: doesPolicyAllow(): insert_row() returned error, "
                    "so returning false");
            db_ptr = NULL;  /* set back to NULL so we'll retry after error */
            retval = false;
            goto out;
        }

    } else {
        LOGW("phornyac: doesPolicyAllow(): db_ptr was not NULL");
    }

#if 0
    /**
     * Check if the policy has changed, and if so, reload the database...
     * The policyHasChanged variable should be changed when the global policy
     * preferences are changed (or we may have to get/check the policy setting
     * here...)
     * XXX: implement this!
     */
    if (policyHasChanged) {
        LOGW("phornyac: doesPolicyAllow(): policyHasChanged is true, "
                "re-initializing");

        //Close database connection, remove table, re-create database?
        //Combine this with database initialization code above??
        LOGW("phornyac: doesPolicyAllow(): XXX: need to implement changed "
                "policy code!");
        policyHasChanged = false;
    } else {
        LOGW("phornyac: doesPolicyAllow(): policyHasChanged is false");
    }
#endif

    /**
     * Construct a query string to get all of the records matching the current
     * application name: 
     */
    queryString = construct_querystring(processName);  /* Don't forget to free! */
    if (queryString == NULL) {
        LOGW("phornyac: doesPolicyAllow(): construct_querystring returned NULL, "
                "so returning false");
        retval = false;
        goto out;
    }
    LOGW("phornyac: doesPolicyAllow(): construct_querystring returned string %s",
                queryString);
    queryLen = strlen(queryString);

    /**
     * Prepare the SQLite statement:
     * http://sqlite.org/c3ref/prepare.html
     */
    LOGW("phornyac: doesPolicyAllow(): calling sqlite3_prepare_v2()");
    err = sqlite3_prepare_v2(db_ptr, queryString, queryLen + 1,
            &db_query_stmt, NULL);
    free(queryString);
    if (err != SQLITE_OK) {
        LOGW("phornyac: doesPolicyAllow(): sqlite3_prepare_v2() returned "
                "error: %s", sqlite3_errmsg(db_ptr));
        LOGW("phornyac: doesPolicyAllow(): returning false due to errors");
        retval = false;
        goto out;
    }

    /**
     * Evaluate the SQL statement: call sqlite3_step() to get the next matching
     * record, then call check_row_for_match() to see if the record matches the
     * current destination server and taint tag. Repeat until a match is found,
     * or until the statement evaluation is complete and sqlite3_step() returns
     * SQLITE_DONE.
     * If there is a match, we return
     * either true or false, depending on whether our default policy (in the
     * case of no matches) is to block or allow the data transmission.
     * http://sqlite.org/c3ref/step.html
     */
    LOGW("phornyac: doesPolicyAllow(): evaluating the statement by calling "
            "sqlite3_step() repeatedly");
    err = SQLITE_OK;
    while (err != SQLITE_DONE) {
        LOGW("phornyac: doesPolicyAllow(): calling sqlite3_step()");
        err = sqlite3_step(db_query_stmt);

        if (err == SQLITE_ROW) {
            print_row(db_query_stmt);
            match = check_row_for_match(db_query_stmt, destName, tag);
            if (match) {
                /**
                 * If the default policy is to allow data transmission, then
                 * when there is a matching record in the policy database we
                 * should block the transmission, and vice-versa:
                 */
                if (db_default_allow) {
                    LOGW("phornyac: doesPolicyAllow(): found a match, setting "
                            "retval=false");
                    retval = false;
                } else {
                    LOGW("phornyac: doesPolicyAllow(): found a match, setting "
                            "retval=true");
                    retval = true;
                }
                goto finalize_and_out;
            } 
        } else if (err != SQLITE_DONE) {
            LOGW("phornyac: doesPolicyAllow(): sqlite3_step() returned "
                    "error: %s", sqlite3_errmsg(db_ptr));
            LOGW("phornyac: doesPolicyAllow(): returning false due to errors");
            retval = false;
            goto finalize_and_out;
        }
    }

    /**
     * If we reach this code, the query returned no matching rows, so we
     * return true if the default policy is to allow transmission and false
     * if the default policy is to deny transmission:
     */
    if (db_default_allow) {
        LOGW("phornyac: doesPolicyAllow(): no match, setting retval=true");
        retval = true;
    } else {
        LOGW("phornyac: doesPolicyAllow(): no match, setting retval=false");
        retval = false;
    }

finalize_and_out:
    LOGW("phornyac: doesPolicyAllow(): finalizing db_query_stmt and returning");
    sqlite3_finalize(db_query_stmt);
    db_query_stmt = NULL;
      //XXX: optimize this function to re-use db_query_stmt??
out:
    return retval;
}

int add_policydb_entry(policy_entry *entry) {
    LOGW("phornyac: add_policydb_entry(): not implemented yet! "
            "...returning -1");
    return -1;
}

int remove_policydb_entries(policy_entry *entry) {
    LOGW("phornyac: remove_policydb_entries(): not implemented yet! "
            "...returning -1");
    return -1;
}

#define SIIIZE 5
const char *testfile = "/data/data/com.android.settings/files/woohoo.txt";

int query_policydb(policy_entry *entry) {
    LOGW("phornyac: query_policydb(): not implemented yet!");
    int taint = entry->taint_tag;
    int ret;

//XXX: debug code, remove this!!!!
#ifdef TESTCODE
    LOGW("phornyac: query_policydb(): checking if we can read file from RAM");
    int fd;
    int flags = O_RDONLY;
    char buf[SIIIZE];
    ret = open(testfile, flags);
    if (ret < 0) {
        LOGW("phornyac: query_policydb(): error opening file %s, errno=%d",
                testfile, errno);
    } else {
        fd = ret;
        ret = 1;
        while (ret > 0) {
            ret = read(fd, (void *)buf, SIIIZE-1);
            if (ret < 0) {
                LOGW("phornyac: query_policydb(): error reading file, errno=%d",
                        errno);
            }
            LOGW("phornyac: query_policydb(): read %d bytes from file",
                    ret);
            buf[ret] = '\0';
            LOGW("phornyac: query_policydb(): buf=\"%s\"", buf);
        }
        ret = close(fd);
        if (ret < 0) {
            LOGW("phornyac: query_policydb(): error closing file, errno=%d",
                    errno);
        }
    }
#endif

    if (taint) {
        LOGW("phornyac: query_policydb(): taint is nonzero, so "
                "returning 1 for now");
        return 1;
    }
    LOGW("phornyac: query_policydb(): taint is zero, so skipping db, "
            "just returning 0 for now");
    return 0;
}

int refresh_policydb() {
    LOGW("phornyac: refresh_db(): entered");

    LOGW("phornyac: refresh_db(): not implemented yet! Returning 0");
    return 0;

#if 0
    /* Add some simple rows to database / table for now: */
//XXX: can't do this!
//Copied from dalvik/vm/Common.h:
#ifdef HAVE_STDINT_H
# include <stdint.h>    /* C99 */
typedef uint32_t            u4;
#else
typedef unsigned int        u4;
#endif
//Copied from dalvik/vm/interp/Taint.h:
#define TAINT_LOCATION_GPS  ((u4)0x00000010) /* GPS Location */
    err = insert_row(db_ptr, db_tablename, "*", "*", TAINT_LOCATION_GPS);
    err |= insert_row(db_ptr, db_tablename, "com.android.browser",
            "*", 255);
    err |= insert_row(db_ptr, db_tablename, "com.android.browser",
            "72.14.*", 255);  //255 = 0xff
    //(DEBUG: Get all rows in a table: SELECT * FROM Persons)
    if (err) {
        LOGW("phornyac: doesPolicyAllow(): insert_row() returned error, "
                "so returning false");
        db_ptr = NULL;  /* set back to NULL so we'll retry after error */
        retval = false;
        goto out;
    }
#endif
}

/**
 * Creates a database table in the given database.
 * I have no idea how to do this extensibly...
 * 
 * Returns: 0 on success, negative on error.
 */
int create_db_table(sqlite3 *db) {
    LOGW("phornyac: create_db_table(): entered");
    int ret;
    char *errmsg = NULL;
#if 0
    int cmd_len, cmd_len_inner;
    char *cmd;
    char *cmd_inner;
#endif

    if (db == NULL) {
        LOGW("phornyac: create_db_table(): error, db is NULL, "
                "returning -1");
        return -1;
    }
    //TODO: more precondition checking here??

    /**
     * Create the table:
     * See http://sqlite.org/lang_createtable.html
     * See http://sqlite.org/c3ref/exec.html
     */
#if 0
    queryLen = strlen(select) + strlen(" ") + strlen(columns) + 
        strlen(" ") + strlen(from) +
        strlen(" ") + strlen(db_tablename) + strlen(" ") + strlen(where) +
        strlen(" src=\'") + strlen(source) + strlen("\' OR src=\'*\'") + 1;
    queryString = (char *)malloc(queryLen * sizeof(char));
    snprintf(queryString, queryLen, "%s %s %s %s %s src=\'%s\' OR src=\'*\'",
            select, columns, from, db_tablename, where, source);
    LOGW("phornyac: construct_querystring(): queryLen=%d, queryString=%s",
            queryLen, queryString);
#endif
#if 0
    const char *create = "CREATE TABLE";
    cmd_len = 0;
    cmd_len_inner = 0;
    /* Add lengths for col names, types, spaces and commas; may be a bit extra */
    for (i = 0; i < COLUMNS; i++) {
        cmd_len_inner += strlen(db_col_names[i]);
        cmd_len_inner += strlen(db_col_types[i]);
        cmd_len_inner += 3;
    }
    cmd_len = strlen(create) + strlen(" ") + strlen(db_tablename) +
            strlen(" (") + cmd_len_inner + strlen(")");
    cmd_inner = (char *)malloc(cmd_len_inner * sizeof(char));
    if (!cmd_inner) {
        LOGW("phornyac: create_db_table(): failed to allocate cmd_inner, "
                "returning -1");
        return -1;
    }
#endif
    LOGW("phornyac: create_db_table(): calling sqlite3_exec to create "
            "table \"%s\"", db_tablename);
    ret = sqlite3_exec(db, db_createstring, NULL, NULL, &errmsg);
    //LOGW("phornyac: initialize_policydb(): sqlite3_exec() returned");
    if (ret) {
        if (errmsg) {
            LOGW("phornyac: create_db_table(): sqlite3_exec(CREATE TABLE) "
                    "returned error \"%s\", so returning false", errmsg);
            sqlite3_free(errmsg);
        } else {
            LOGW("phornyac: create_db_table(): sqlite3_exec(CREATE TABLE) "
                    "returned error, errmsg=NULL");
        }
        LOGW("phornyac: create_db_table(): returning -1 due to errors");
        db_ptr = NULL;  /* Good idea? */
        return -1;
    }
    LOGW("phornyac: create_db_table(): successfully created table, returning");
    return 0;
}

int initialize_policydb() {
    LOGW("phornyac: initialize_policydb(): entered");
    int ret;
    //char *errmsg = NULL;

    if (db_ptr != NULL) {
        LOGW("phornyac: initialize_policydb(): error, db_ptr pointer is "
                "not NULL! Returning -1");
        return -1;
    }
    
    /**
     * Initialize the database connection if not already done:
     * http://sqlite.org/c3ref/open.html
     */
#ifdef TESTCODE
    //DEBUG (XXX: remove this):
    struct stat db_stat;
    LOGW("phornyac: initialize_policydb(): calling stat for db_filename=%s",
            db_filename);
    ret = stat(db_filename, &db_stat);
    if (ret) {
        if (errno == ENOENT) {
            LOGW("phornyac: initialize_policydb(): stat returned errno=ENOENT, "
                    "db file does not exist yet");
        } else {
            LOGW("phornyac: initialize_policydb(): stat returned other errno=%d",
                    errno);
        }
    } else {
            LOGW("phornyac: initialize_policydb(): stat succeeded, db file exists");
    }
#endif

    /**
     * The "standard" version of sqlite3_open() opens a database for reading
     * and writing, and creates it if it does not exist.
     * http://sqlite.org/c3ref/open.html
     */
    LOGW("phornyac: initialize_policydb(): calling sqlite3_open(%s)",
            db_filename);
    ret = sqlite3_open(db_filename, &db_ptr);
    if ((ret != SQLITE_OK) || (db_ptr == NULL)) {
        if (db_ptr == NULL) {
            LOGW("phornyac: initialize_policydb(): sqlite3_open() returned "
                    "NULL db_ptr!");
        }
        LOGW("phornyac: initialize_policydb(): sqlite3_open() error message: "
                "%s", sqlite3_errmsg(db_ptr));
        db_ptr = NULL;  /* Good idea? */
        LOGW("phornyac: initialize_policydb(): returning -1 due to errors");
        return -1;
    }
    LOGW("phornyac: initialize_policydb(): sqlite3_open() succeeded, "
            "db_ptr=%p", db_ptr);
    /* XXX: We never close the database connection: is this ok? */

    /**
     * Create the table:
     * See http://sqlite.org/lang_createtable.html
     * See http://sqlite.org/c3ref/exec.html
     */
    LOGW("phornyac: initialize_policydb(): calling create_db_table()");
    ret = create_db_table(db_ptr);
    if (ret < 0) {
        LOGW("phornyac: initialize_policydb(): create_db_table() returned "
                "error=%d, goto close_err_exit", ret);
        goto close_err_exit;
   }

    /* Fill in the database table from a file: */
    LOGW("phornyac: initialize_policydb(): calling refresh_policydb() "
            "to init table");
    ret = refresh_policydb();
    if (ret < 0) {
        LOGW("phornyac: initialize_policydb(): refresh_policydb() returned "
                "error %d, goto close_err_exit", ret);
        goto close_err_exit;
    }


    return 0;

close_err_exit:
    ret = sqlite3_close(db_ptr);
    if (ret != SQLITE_OK) {
        LOGW("phornyac: initialize_policydb(): sqlite3_close() returned "
                "error=%d, whatever", ret);
    }
    LOGW("phornyac: initialize_policydb(): returning -1");
    return -1;
}


//SCRATCH:
#if 0
    //XXX: un-hard-code this!
    //XXX: put this in a separate function!
    ret = sqlite3_exec(db_ptr, "CREATE TABLE policy (src TEXT, dest TEXT, taint INTEGER)",
            NULL, NULL, &errmsg);
    LOGW("phornyac: initialize_policydb(): sqlite3_exec() returned");
    if (ret) {
        if (errmsg) {
            /**
             * "To avoid memory leaks, the application should invoke
             *  sqlite3_free() on error message strings returned through the
             *  5th parameter of of sqlite3_exec() after the error message
             *  string is no longer needed. If the 5th parameter to
             *  sqlite3_exec() is not NULL and no errors occur, then
             *  sqlite3_exec() sets the pointer in its 5th parameter to NULL
             *  before returning."
             */
            LOGW("phornyac: doesPolicyAllow(): sqlite3_exec(CREATE TABLE) "
                    "returned error \"%s\", so returning false", errmsg);
            /**
             * For some reason, when I open browser, then open maps app, I get this
             * error from maps:
             *   "W/dalvikvm(  475): phornyac: doesPolicyAllow(): sqlite3_exec(CREATE
             *    TABLE) returned error "table policy already exists", so returning
             *    false
             * Don't get the error when using in-memory database though
             *   (db_filename=":memory:")
             */
            sqlite3_free(errmsg);
        } else {
            LOGW("phornyac: doesPolicyAllow(): sqlite3_exec(CREATE TABLE) "
                    "returned error, errmsg=NULL");
        }
        db_ptr = NULL;  /* set back to NULL so we'll retry after error */
        retval = false;
        goto out;
    }
 #endif
