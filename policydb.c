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

/* Need to define LOG_TAG before #including file: */
#define LOG_TAG "policydb"
#include <cutils/log.h>

/**
 * Constructs a query string that gets the records/rows of the database matching
 * the given source application name. Returns pointer to a newly-allocated string
 * (which should be freed by the caller) on success, or returns NULL on failure.
 */
char *constructQueryString(const char *source) {
    int queryLen;
    char *queryString;
    const char *select = "SELECT";
    const char *columns = "*";
    const char *from = "FROM";
    const char *where = "WHERE";
 
    LOGW("phornyac: constructQueryString(): entered");
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
        strlen(" ") + strlen(dbTableName) + strlen(" ") + strlen(where) +
        strlen(" src=\'") + strlen(source) + strlen("\' OR src=\'*\'") + 1;
    queryString = (char *)malloc(queryLen * sizeof(char));
    snprintf(queryString, queryLen, "%s %s %s %s %s src=\'%s\' OR src=\'*\'",
            select, columns, from, dbTableName, where, source);
    LOGW("phornyac: constructQueryString(): queryLen=%d, queryString=%s",
            queryLen, queryString);
    return queryString;
}

/* Prints the current database row. */
void printRow(sqlite3_stmt *stmt){
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
 
    LOGW("phornyac: printRow(): dbSrc=%s, dbDest=%s, dbTaint=0x%X",
            dbSrc, dbDest, dbTaint);
}

/**
 * Returns true if the two destination IP addresses match, or if the
 * destination stored in the database row is the wildcard "*".
 * XXX: enhance this function to consider subnets, partial IP addresses /
 *   hostnames, etc.!
 */
bool destinationMatch(const char *curDest, const char *dbDest) {
    LOGW("phornyac: destinationMatch: curDest=%s, dbDest=%s",
            curDest, dbDest);
    
    if ((strcmp("*", dbDest) == 0) || (strcmp(curDest, dbDest) == 0)) {
        LOGW("phornyac: destinationMatch: returning true");
        return true;
    }
    LOGW("phornyac: destinationMatch: returning false");
    return false;
}

/**
 * Returns true if the two taint tags "match," i.e. if they have any of the same
 * bits set.
 */
bool taintMatch(int curTaint, int dbTaint) {
    LOGW("phornyac: taintMatch: curTaint=0x%X, dbTaint=0x%X",
            curTaint, dbTaint);
    if (curTaint & dbTaint) {
        LOGW("phornyac: taintMatch: returning true");
        return true;
    }
    LOGW("phornyac: taintMatch: returning false");
    return false;
}

/**
 * Function that is called for every database record that our query
 * returns. If we select the records based solely on the application name,
 * then this function should return true if the destination server and taint
 * of the data about to be transmitted BOTH match one of the records.
 */
bool checkRowForMatch(sqlite3_stmt *queryStmt, const char *dest, int taint) {
    const unsigned char *dbDest;
    int dbTaint;

    LOGW("phornyac: checkRowForMatch(): entered");

    /**
     * Get the values from the destination and taint tag columns:
     * http://sqlite.org/c3ref/column_blob.html
     */
    dbDest = sqlite3_column_text(queryStmt, DEST);
    if (dbDest == NULL) {
        LOGW("phornyac: checkRowForMatch(): dbDest got NULL, returning false!");
        return false;
    }
    dbTaint = sqlite3_column_int(queryStmt, TAINT);

    /* Return true if BOTH the destinations and the taints match: */
    if (destinationMatch(dest, (const char *)dbDest) && taintMatch(taint, dbTaint)) {
        LOGW("phornyac: checkRowForMatch(): returning true");
        return true;
    }
    LOGW("phornyac: checkRowForMatch(): returning false");
    return false;
}

/**
 * Adds the given (source, dest, taint) triple to the database table.
 * Returns 0 on success, negative on error.
 */
int insertDbRow(sqlite3 *db, const char *tableName, const char *source,
        const char *dest, int taint) {
    sqlite3_stmt *insertStmt;
    int len;
    int err;
    char *insertString;
    char taintString[32];
      //2^64 = 18446744073709551616, which is 20 digits

    LOGW("phornyac: insertDbRow(): entered");

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
    LOGW("phornyac: insertDbRow(): calculated taintString=%s, len=%d",
            taintString, strlen(taintString));
    len = strlen(insertInto) + strlen(" ") + strlen(tableName) + 
        strlen(" ") + strlen(values) + strlen(" (\'") + strlen(source) +
        strlen("\', \'") + strlen(dest) + strlen("\', \'") + strlen(taintString) +
        strlen("\')") + 1;
    insertString = malloc(len * sizeof(char));
    /* Must use quotes around column values inside () ! */
    snprintf(insertString, len, "%s %s %s (\'%s\', \'%s\', \'%s\')",
            insertInto, tableName, values, source, dest, taintString);
    LOGW("phornyac: insertDbRow(): constructed insertString=%s", insertString);

    /**
     * Prepare an SQLite statement with the INSERT string:
     * See http://sqlite.org/c3ref/prepare.html
     */
    LOGW("phornyac: insertDbRow(): calling sqlite3_prepare_v2()");
    err = sqlite3_prepare_v2(db, insertString, len, &insertStmt, NULL);
    free(insertString);
    if (err != SQLITE_OK) {
        LOGW("phornyac: insertDbRow(): sqlite3_prepare_v2() returned "
                "error: %s", sqlite3_errmsg(db));
        LOGW("phornyac: insertDbRow(): returning -1 due to errors");
        return -1;
    }

    /**
     * Execute the prepared statement:
     */
    LOGW("phornyac: insertDbRow(): calling sqlite3_step() to execute "
            "INSERT statement");
    err = sqlite3_step(insertStmt);
    if (err != SQLITE_DONE) {
        LOGW("phornyac: insertDbRow(): sqlite3_step() returned "
                "error: %s", sqlite3_errmsg(db));
        LOGW("phornyac: insertDbRow(): returning -1 due to errors");
        sqlite3_finalize(insertStmt);  //ignore return value
        return -1;
    }
 
    /* Finalize and return: */
    LOGW("phornyac: insertDbRow(): INSERT succeeded, finalizing and returning");
    err = sqlite3_finalize(insertStmt);
    if (err != SQLITE_OK) {
        LOGW("phornyac: insertDbRow(): sqlite3_finalize() returned "
                "error: %s", sqlite3_errmsg(db));
        LOGW("phornyac: insertDbRow(): returning -1 due to errors");
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
    LOGW("phornyac: doesPolicyAllow(): processName=%s, destName=%s, tag=%d",
            processName, destName, tag);

    /* Use snprintf() to generate db filename? */
    //...

    /**
     * Initialize the database connection if not already done:
     * http://sqlite.org/c3ref/open.html
     */
    if (policyDb == NULL) {
        LOGW("phornyac: doesPolicyAllow(): policyDb is NULL, initializing");

        //DEBUG (XXX: remove this):
        LOGW("phornyac: doesPolicyAllow(): calling stat for dbFilename=%s",
                dbFilename);
        err = stat(dbFilename, &dbStat);
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
                dbFilename);
        /**
         * The "standard" version of sqlite3_open() opens a database for reading
         * and writing, and creates it if it does not exist.
         * http://sqlite.org/c3ref/open.html
         */
        err = sqlite3_open(dbFilename, &policyDb);
        if ((err != SQLITE_OK) || (policyDb == NULL)) {
            if (policyDb == NULL) {
                LOGW("phornyac: doesPolicyAllow(): sqlite3_open() returned "
                        "NULL policyDb!");
            }
            LOGW("phornyac: doesPolicyAllow(): sqlite3_open() error message: "
                    "%s", sqlite3_errmsg(policyDb));
            policyDb = NULL;  /* set back to NULL so we'll retry after error */
            LOGW("phornyac: doesPolicyAllow(): returning false due to errors");
            retval = false;
            goto out;
        }
        LOGW("phornyac: doesPolicyAllow(): sqlite3_open() succeeded, policyDb=%p",
                policyDb);
        /* XXX: We never close the database connection: is this ok? */

        /**
         * Create the table:
         * See http://sqlite.org/lang_createtable.html
         * See http://sqlite.org/c3ref/exec.html
         */
        LOGW("phornyac: doesPolicyAllow(): creating table \"%s\"", dbTableName);
        //XXX: un-hard-code this!
        //XXX: put this in a separate function!
        err = sqlite3_exec(policyDb, "CREATE TABLE policy (src TEXT, dest TEXT, taint INTEGER)",
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
                 *    TABLE) returned error "table policy already exists", so   returning
                 *    false
                 * Don't get the error when using in-memory database though
                 *   (dbFilename=":memory:")
                 */
                sqlite3_free(errmsg);
            } else {
                LOGW("phornyac: doesPolicyAllow(): sqlite3_exec(CREATE TABLE) "
                        "returned error, errmsg=NULL");
            }
            policyDb = NULL;  /* set back to NULL so we'll retry after error */
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
        err = insertDbRow(policyDb, dbTableName, "*", "*", TAINT_LOCATION_GPS);
        err |= insertDbRow(policyDb, dbTableName, "com.android.browser",
                "*", 255);
        err |= insertDbRow(policyDb, dbTableName, "com.android.browser",
                "72.14.*", 255);  //255 = 0xff
        //(DEBUG: Get all rows in a table: SELECT * FROM Persons)
        if (err) {
            LOGW("phornyac: doesPolicyAllow(): insertDbRow() returned error, "
                    "so returning false");
            policyDb = NULL;  /* set back to NULL so we'll retry after error */
            retval = false;
            goto out;
        }

    } else {
        LOGW("phornyac: doesPolicyAllow(): policyDb was not NULL");
    }

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

    /**
     * Construct a query string to get all of the records matching the current
     * application name: 
     */
    queryString = constructQueryString(processName);  /* Don't forget to free! */
    if (queryString == NULL) {
        LOGW("phornyac: doesPolicyAllow(): constructQueryString returned NULL, "
                "so returning false");
        retval = false;
        goto out;
    }
    LOGW("phornyac: doesPolicyAllow(): constructQueryString returned string %s",
                queryString);
    queryLen = strlen(queryString);

    /**
     * Prepare the SQLite statement:
     * http://sqlite.org/c3ref/prepare.html
     */
    LOGW("phornyac: doesPolicyAllow(): calling sqlite3_prepare_v2()");
    err = sqlite3_prepare_v2(policyDb, queryString, queryLen + 1,
            &queryStmt, NULL);
    free(queryString);
    if (err != SQLITE_OK) {
        LOGW("phornyac: doesPolicyAllow(): sqlite3_prepare_v2() returned "
                "error: %s", sqlite3_errmsg(policyDb));
        LOGW("phornyac: doesPolicyAllow(): returning false due to errors");
        retval = false;
        goto out;
    }

    /**
     * Evaluate the SQL statement: call sqlite3_step() to get the next matching
     * record, then call checkRowForMatch() to see if the record matches the
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
        err = sqlite3_step(queryStmt);

        if (err == SQLITE_ROW) {
            printRow(queryStmt);
            match = checkRowForMatch(queryStmt, destName, tag);
            if (match) {
                /**
                 * If the default policy is to allow data transmission, then
                 * when there is a matching record in the policy database we
                 * should block the transmission, and vice-versa:
                 */
                if (defaultAllow) {
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
                    "error: %s", sqlite3_errmsg(policyDb));
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
    if (defaultAllow) {
        LOGW("phornyac: doesPolicyAllow(): no match, setting retval=true");
        retval = true;
    } else {
        LOGW("phornyac: doesPolicyAllow(): no match, setting retval=false");
        retval = false;
    }

finalize_and_out:
    LOGW("phornyac: doesPolicyAllow(): finalizing queryStmt and returning");
    sqlite3_finalize(queryStmt);
    queryStmt = NULL;
      //XXX: optimize this function to re-use queryStmt??
out:
    return retval;
}


